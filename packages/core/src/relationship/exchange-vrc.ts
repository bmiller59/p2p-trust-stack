// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformant (per-VRC relationship DID) credentials: labelling, exchange lookup, receive-side
 * binding checks and the archive payload (conformance phase P5c).
 */
import type { DataSource } from '../db/data-source.js';
import type { ExchangeDidRow } from '../db/repositories/vrc-exchange-dids-repo.js';
import { DidResolver } from '../did/did-resolver.js';
import { verifyDtgProof, type DtgCredentialVc } from '../services/dtg-credential.js';

export type VrcLabel = 'conformant' | 'legacy';

const SCOPES = ['pairwise', 'directed', 'public'];

function parse(json: string | null | undefined): Record<string, unknown> | null {
  if (typeof json !== 'string' || json.length === 0) return null;
  try {
    const v: unknown = JSON.parse(json);
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * `conformant` when the credential declares `issuerScope: "pairwise"` (it was minted on a relationship
 * DID); everything issued before P5c (connection DIDs, no `issuerScope`) is `legacy` and left alone.
 */
export function labelVrc(w3cVcJson: string | null | undefined): VrcLabel {
  return parse(w3cVcJson)?.issuerScope === 'pairwise' ? 'conformant' : 'legacy';
}

export type VrcBindingRefusal = 'malformed' | 'scopeMissing' | 'issuerMismatch' | 'subjectMismatch' | 'proofInvalid';
export type VrcBindingCheck = { ok: true } | { ok: false; reason: VrcBindingRefusal };

/**
 * Bindings of an INCOMING credential to its exchange record: `issuerScope` present and valid, issuer
 * equals the counterparty relationship DID recorded for the exchange, subject equals ours.
 */
export function checkIncomingBindings(vc: unknown, exchange: ExchangeDidRow): VrcBindingCheck {
  if (vc === null || typeof vc !== 'object') return { ok: false, reason: 'malformed' };
  const doc = vc as Record<string, unknown>;
  const subject = doc.credentialSubject as { id?: unknown } | undefined;
  if (typeof doc.issuer !== 'string' || subject === undefined || typeof subject !== 'object' || typeof subject.id !== 'string') {
    return { ok: false, reason: 'malformed' };
  }
  if (typeof doc.issuerScope !== 'string' || !SCOPES.includes(doc.issuerScope)) return { ok: false, reason: 'scopeMissing' };
  if (exchange.remoteRelationshipDid === null || doc.issuer !== exchange.remoteRelationshipDid) return { ok: false, reason: 'issuerMismatch' };
  if (subject.id !== exchange.localRelationshipDid) return { ok: false, reason: 'subjectMismatch' };
  return { ok: true };
}

/**
 * Verify the inner proof offline: the verification method's DID must be the credential issuer, its
 * fragment must be listed under `assertionMethod`, and the signature must verify under that key. A
 * `did:peer:4` issuer resolves from the identifier itself, so no rotation log or network is used.
 */
export async function verifyInnerProof(vc: DtgCredentialVc, resolver: DidResolver = new DidResolver()): Promise<boolean> {
  const vm = (vc.proof as { verificationMethod?: unknown } | undefined)?.verificationMethod;
  if (typeof vm !== 'string') return false;
  try {
    const key = await resolver.dereferenceVerificationMethod(vm);
    if (key === null || !key.proofPurposes.includes('assertionMethod')) return false;
    if (vm.split('#')[0] !== vc.issuer) return false;
    return verifyDtgProof(vc, key.rawKey);
  } catch {
    return false;
  }
}

/** Bindings plus offline inner-proof verification. */
export async function checkIncomingVrc(w3cVcJson: string, exchange: ExchangeDidRow): Promise<VrcBindingCheck> {
  const vc = parse(w3cVcJson);
  const bindings = checkIncomingBindings(vc, exchange);
  if (!bindings.ok) return bindings;
  return (await verifyInnerProof(vc as unknown as DtgCredentialVc)) ? { ok: true } : { ok: false, reason: 'proofInvalid' };
}

export interface ExchangeVrcRow {
  uuid: string;
  w3cVcJson: string;
  digest: string | null;
}

/**
 * The credential this exchange already holds: issued by us (`issued`) or received from the
 * counterparty (`received`). Relationship DIDs are unique per exchange, so the credential issuer
 * identifies the exchange; this replaces the per-pair first-wins rule for conformant VRCs.
 */
export async function findExchangeVrc(
  db: DataSource,
  exchange: ExchangeDidRow,
  which: 'issued' | 'received',
): Promise<ExchangeVrcRow | null> {
  if (exchange.localIdentityUuid === null || exchange.remoteIdentityUuid === null) return null;
  const issuerDid = which === 'issued' ? exchange.localRelationshipDid : exchange.remoteRelationshipDid;
  if (issuerDid === null) return null;
  const [issuerUuid, subjectUuid] =
    which === 'issued' ? [exchange.localIdentityUuid, exchange.remoteIdentityUuid] : [exchange.remoteIdentityUuid, exchange.localIdentityUuid];
  const rows = await db.all<{ uuid: string; w3c_vc_json: string; credential_digest: string | null }>(
    `SELECT uuid, w3c_vc_json, credential_digest FROM credentials
      WHERE vc_type = 'vrc' AND issuer_identity_uuid = ? AND subject_identity_uuid = ? AND w3c_vc_json IS NOT NULL
      ORDER BY created_at, uuid`,
    issuerUuid,
    subjectUuid,
  );
  const hit = rows.find((r) => parse(r.w3c_vc_json)?.issuer === issuerDid);
  return hit === undefined ? null : { uuid: hit.uuid, w3cVcJson: hit.w3c_vc_json, digest: hit.credential_digest };
}

/**
 * Archive payload for a conformant VRC. It carries the credential only: no connection identity
 * record (`realDid`, DID document, public keys, peer id, relationship edge), so the archive cannot
 * be handed the relationship-DID to connection-DID mapping by this push. The server applies it with
 * `vrcArchive` handling (no identity upsert, no per-pair dedup).
 */
export async function buildConformantVrcArchivePayload(db: DataSource, credentialUuid: string): Promise<{ vrcArchive: { credentials: Array<Record<string, unknown>> } }> {
  const c = await db.get<Record<string, unknown>>(
    "SELECT * FROM credentials WHERE uuid = ? AND vc_type = 'vrc' AND w3c_vc_json IS NOT NULL",
    credentialUuid,
  );
  if (c === null || labelVrc(c.w3c_vc_json as string) !== 'conformant') {
    throw new Error('not a conformant VRC: the legacy identity push must be used');
  }
  return {
    vrcArchive: {
      credentials: [
        {
          uuid: c.uuid,
          vcType: c.vc_type,
          issuerIdentityUuid: c.issuer_identity_uuid,
          subjectIdentityUuid: c.subject_identity_uuid,
          w3cVcJson: c.w3c_vc_json,
          claim: c.claim,
          status: c.status,
          thresholdRequired: c.threshold_required,
          validFrom: c.valid_from,
          validUntil: c.valid_until,
          credentialDigest: c.credential_digest,
          createdAt: c.created_at,
        },
      ],
    },
  };
}
