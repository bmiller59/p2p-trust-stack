// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Mapping founding admins from the identities a ceremony names to the identity rows `createVtc` needs.
 *
 * `resolveRealVtaForStub`: the utility server's TSP bridge creates endpoint-less did:peer:4 stub identities when it
 * records a relationship handshake, keyed by the peer's did:peer:4 VID: a DIFFERENT row from the agent's real
 * did:scid:vh VTA. `createVtc` requires an active libp2p endpoint on every founding admin, so a stub is mapped to the
 * real VTA that shares its DID, else its Ed25519 (or X25519) public key. The legacy ceremony participant and the
 * boundary ceremony host both use this one function.
 *
 * `resolveFoundingAdminUuids`: DIDs (the boundary names admins by DID) to identity uuids, stub-resolved. A DID the
 * server does not know is reported, not guessed.
 */
import type { DataSource } from '../../db/data-source.js';
import * as identitiesRepo from '../../db/repositories/identities-repo.js';
import { logger } from '../../util/logger.js';

/** The authoritative identity (a VTA with an active endpoint) behind an endpoint-less stub, or null. By shared DID first, then by shared key. */
export async function resolveRealVtaForStub(db: DataSource, stubUuid: string): Promise<{ uuid: string } | null> {
  const realByDid = await db.get<{ uuid: string }>(
    `SELECT i.uuid FROM identities i
     JOIN did_documents d ON d.identity_uuid = i.uuid
     WHERE i.role = 'vta' AND i.uuid <> ?
       AND d.did IN (SELECT dd.did FROM did_documents dd WHERE dd.identity_uuid = ?)
       AND EXISTS (SELECT 1 FROM peer_endpoints pe WHERE pe.identity_uuid = i.uuid)
     ORDER BY i.created_at, i.uuid
     LIMIT 1`,
    stubUuid, stubUuid,
  );
  if (realByDid) {
    logger.info(`[founding] stub ${stubUuid} resolved to real VTA ${realByDid.uuid} (by DID)`);
    return realByDid;
  }
  const real = await db.get<{ uuid: string }>(
    `SELECT i.uuid FROM identities i
     JOIN keys k ON k.identity_uuid = i.uuid
     JOIN keys k2 ON k2.public_key = k.public_key AND k2.key_type = k.key_type
     JOIN identities i2 ON i2.uuid = k2.identity_uuid
     JOIN peer_endpoints pe ON pe.identity_uuid = i.uuid
     WHERE i2.uuid = ? AND i.role = 'vta' AND i.uuid <> ?
     ORDER BY i.created_at, i.uuid
     LIMIT 1`,
    stubUuid, stubUuid,
  );
  logger.info(real ? `[founding] stub ${stubUuid} resolved to real VTA ${real.uuid} (by key)` : `[founding] stub ${stubUuid}: no real VTA (no DID or key match)`);
  return real ?? null;
}

/** An identity uuid usable as a founding admin: the identity itself when it has an endpoint, else its real VTA when one exists, else itself (`createVtc` then refuses it). */
export async function resolveFoundingAdminUuid(db: DataSource, identityUuid: string): Promise<string> {
  if (await identitiesRepo.hasAnyEndpoint(db, identityUuid)) return identityUuid;
  const real = await resolveRealVtaForStub(db, identityUuid);
  return real?.uuid ?? identityUuid;
}

export interface ResolvedAdmins {
  /** Identity uuid (as named, before stub resolution) by DID. */
  uuidByDid: Map<string, string>;
  /** Founding-admin uuids in the order of `dids`, stub-resolved. */
  adminUuids: string[];
  /** DIDs no identity row exists for. */
  unknown: string[];
}

export async function resolveFoundingAdminUuids(db: DataSource, dids: readonly string[]): Promise<ResolvedAdmins> {
  const uuidByDid = new Map<string, string>();
  const adminUuids: string[] = [];
  const unknown: string[] = [];
  for (const did of dids) {
    const identity = await identitiesRepo.findByRealDid(db, did);
    if (identity === null) {
      unknown.push(did);
      continue;
    }
    uuidByDid.set(did, identity.uuid);
    adminUuids.push(await resolveFoundingAdminUuid(db, identity.uuid));
  }
  return { uuidByDid, adminUuids, unknown };
}
