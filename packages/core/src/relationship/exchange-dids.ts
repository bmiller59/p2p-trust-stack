// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Per-VRC relationship DIDs (conformance phase P5c, decision 35).
 *
 * Mints a fresh signing-only `did:peer:4` for one VRC exchange (keyed by the `propose` document id),
 * stores its secret key encrypted under the agent's key passphrase, and records the exchange in the
 * mapping table BEFORE the DID is returned for sending. Also holds the pure pre-check applied to a
 * counterparty's proposed relationship DID, the signer loader used by the VRC mint, and the
 * lifecycle end (secret key deleted, public document kept, exchange marked `ended`).
 *
 * Conformant VRCs exist only on the boundary path; the internal TSP ceremony does not call this.
 */
import type { DataSource } from '../db/data-source.js';
import { DidManager } from '../services/did-manager.js';
import * as exchangeDids from '../db/repositories/vrc-exchange-dids-repo.js';
import type { ExchangeDidRow, ExchangeRole, ExchangeState } from '../db/repositories/vrc-exchange-dids-repo.js';

/** Un-accepted exchanges (state `proposed`) allowed per counterparty connection DID. */
export const MAX_PENDING_PER_COUNTERPARTY = 5;
/** Exchanges minted per counterparty inside one window. */
export const MAX_MINTS_PER_WINDOW = 10;
export const MINT_WINDOW_MS = 60_000;

export class ExchangeDidLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExchangeDidLimitError';
  }
}

export interface MintExchangeDidInput {
  /** The `propose` document id (thread id). */
  exchangeId: string;
  role: ExchangeRole;
  /** Our root identity (the connection identity the relationship DID is recorded under). */
  localIdentityUuid: string;
  localConnectionDid: string;
  remoteConnectionDid: string;
  remoteIdentityUuid?: string;
  /** Known up front on the acceptor side (the proposer's DID from `propose`). */
  remoteRelationshipDid?: string;
  /** The agent's key passphrase. No default exists. */
  passphrase: string;
  /** Initial state. Default: `accepted` for an acceptor, `proposed` for a proposer; the boundary uses `held` for a pending human decision. */
  state?: ExchangeState;
  now?: number;
}

/**
 * Mint (or, for a resend of the same exchange, return) the relationship DID for an exchange.
 * Callers must have passed the pipeline's admission checks first: nothing is minted for an
 * unauthenticated sender. The returned row is durable.
 */
export async function mintExchangeRelationshipDid(db: DataSource, input: MintExchangeDidInput): Promise<ExchangeDidRow> {
  const existing = await exchangeDids.findByExchangeId(db, input.exchangeId);
  if (existing !== null) {
    if (
      existing.localConnectionDid !== input.localConnectionDid ||
      existing.remoteConnectionDid !== input.remoteConnectionDid ||
      existing.role !== input.role
    ) {
      throw new Error(`exchange ${input.exchangeId} already exists for different parties or role`);
    }
    return existing; // a resend within one exchange never mints a second DID
  }

  const now = input.now ?? Date.now();
  const mine = await db.all<{ state: string; created_at: number | string }>(
    'SELECT state, created_at FROM vrc_exchange_relationship_dids WHERE local_connection_did = ? AND remote_connection_did = ?',
    input.localConnectionDid,
    input.remoteConnectionDid,
  );
  if (mine.filter((r) => r.state === 'proposed' || r.state === 'held').length >= MAX_PENDING_PER_COUNTERPARTY) {
    throw new ExchangeDidLimitError('too many pending exchanges with this counterparty');
  }
  if (mine.filter((r) => now - Number(r.created_at) < MINT_WINDOW_MS).length >= MAX_MINTS_PER_WINDOW) {
    throw new ExchangeDidLimitError('relationship DIDs are being minted too quickly for this counterparty');
  }

  const manager = new DidManager(db);
  const minted = await manager.createRelationshipDid(input.localIdentityUuid, input.exchangeId, input.passphrase);
  try {
    return await exchangeDids.create(db, {
      exchangeId: input.exchangeId,
      localConnectionDid: input.localConnectionDid,
      remoteConnectionDid: input.remoteConnectionDid,
      localRelationshipDid: minted.did,
      remoteRelationshipDid: input.remoteRelationshipDid,
      localIdentityUuid: input.localIdentityUuid,
      remoteIdentityUuid: input.remoteIdentityUuid,
      role: input.role,
      state: input.state ?? (input.role === 'acceptor' ? 'accepted' : 'proposed'),
      now,
    });
  } catch (err) {
    // The mapping was refused: the DID was never sent, so it must not keep a usable key.
    await manager.deleteRelationshipSecret(minted.did);
    throw err;
  }
}

export type ProposeDidRefusal =
  | 'malformed'
  | 'equalsConnectionDid'
  | 'knownConnectionDid'
  | 'reusedRelationshipDid'
  | 'exchangeConflict';

export type ProposeDidCheck = { ok: true } | { ok: false; reason: ProposeDidRefusal };

export interface ProposeDidCheckInput {
  relationshipDid: unknown;
  /** The sender's envelope `issuer` (its connection DID). */
  senderConnectionDid: string;
  localConnectionDid: string;
  /** The `propose` document id. */
  exchangeId: string;
}

/**
 * The profile pre-check on a proposed relationship DID (plan 2.2; not specification text, and
 * inequality is checkable while uniqueness to the relationship is not provable): well-formed, not a
 * connection DID of either party, not any DID we know as a connection DID, and not already recorded
 * as a relationship DID for another exchange. A resend of the same proposal with the same DID passes.
 */
export async function checkProposedRelationshipDid(db: DataSource, input: ProposeDidCheckInput): Promise<ProposeDidCheck> {
  const did = input.relationshipDid;
  if (typeof did !== 'string' || !/^did:/.test(did)) return { ok: false, reason: 'malformed' };
  if (did === input.senderConnectionDid || did === input.localConnectionDid) return { ok: false, reason: 'equalsConnectionDid' };

  const known = await db.get<{ uuid: string }>(
    "SELECT uuid FROM did_documents WHERE did = ? AND (context_type IS NULL OR context_type <> 'relationship') LIMIT 1",
    did,
  );
  if (known !== null) return { ok: false, reason: 'knownConnectionDid' };
  const asConnection = await db.get<{ exchange_id: string }>(
    'SELECT exchange_id FROM vrc_exchange_relationship_dids WHERE local_connection_did = ? OR remote_connection_did = ? LIMIT 1',
    did,
    did,
  );
  if (asConnection !== null) return { ok: false, reason: 'knownConnectionDid' };

  const holder = await exchangeDids.findByRelationshipDid(db, did);
  if (holder !== null && holder.exchangeId !== input.exchangeId) return { ok: false, reason: 'reusedRelationshipDid' };
  const own = await exchangeDids.findByExchangeId(db, input.exchangeId);
  if (own !== null && own.remoteRelationshipDid !== null && own.remoteRelationshipDid !== did) {
    return { ok: false, reason: 'exchangeConflict' };
  }
  return { ok: true };
}

export interface ExchangeSigner {
  exchange: ExchangeDidRow;
  did: string;
  verificationMethod: string;
  secretKey: Uint8Array;
}

/** The signing key for the exchange's LOCAL relationship DID; null once the relationship has ended. */
export async function loadExchangeSigner(db: DataSource, exchangeId: string, passphrase: string): Promise<ExchangeSigner | null> {
  const exchange = await exchangeDids.findByExchangeId(db, exchangeId);
  if (exchange === null || exchange.state === 'ended') return null;
  const key = await new DidManager(db).loadRelationshipSigningKey(exchange.localRelationshipDid, passphrase);
  if (key === null) return null;
  return { exchange, did: key.did, verificationMethod: key.verificationMethod, secretKey: key.secretKey };
}

/** End one exchange: delete the secret key, keep the public document and the mapping row. Idempotent. */
export async function endExchange(db: DataSource, exchangeId: string, now: number = Date.now()): Promise<boolean> {
  const exchange = await exchangeDids.findByExchangeId(db, exchangeId);
  if (exchange === null) return false;
  await new DidManager(db).deleteRelationshipSecret(exchange.localRelationshipDid);
  if (exchange.state !== 'ended') await exchangeDids.setState(db, exchangeId, 'ended', now);
  return true;
}

/**
 * The human declined a held proposal: the unused local relationship DID loses its secret key (nothing
 * was ever sent under it), the row stays as `declined` so the counterparty's DID cannot be reused.
 */
export async function declineExchange(db: DataSource, exchangeId: string, now: number = Date.now()): Promise<boolean> {
  const exchange = await exchangeDids.findByExchangeId(db, exchangeId);
  if (exchange === null || exchange.state !== 'held') return false;
  await new DidManager(db).deleteRelationshipSecret(exchange.localRelationshipDid);
  await exchangeDids.setState(db, exchangeId, 'declined', now);
  return true;
}

/** End every exchange between a connection pair (relationship teardown). Returns how many were ended. */
export async function endExchangesForConnections(db: DataSource, localConnectionDid: string, remoteConnectionDid: string): Promise<number> {
  const rows = await exchangeDids.listByConnections(db, localConnectionDid, remoteConnectionDid);
  let ended = 0;
  for (const row of rows) {
    if (await endExchange(db, row.exchangeId)) ended++;
  }
  return ended;
}
