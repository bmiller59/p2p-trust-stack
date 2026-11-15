// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Offline did:scid:vh scan: for each identifier and its rotation log, would the package A genesis
 * check (`scidMatchesGenesis`, enforced by `ScidVhMethod.resolveFromLog` and the chain validation
 * behind it) accept or reject it, and why.
 *
 * The verdict is produced by the real core code, not a reimplementation: `scidMatchesGenesis`,
 * `ScidVhMethod.resolveFromLog` and its (private) `validateChain`, called with and without the
 * identifier to separate "newly broken by the genesis check" from "already broken before it".
 * Only the diagnostic variants (key order, createdAt drift) recompute a hash here, and they are used
 * to explain a rejection, never to change a verdict.
 */

import { base58btc } from 'multiformats/bases/base58';
import { ScidVhMethod, scidMatchesGenesis } from '../../src/did/scid-vh-method.js';
import { computeRotationEntryDigest } from '../../src/did/rotation-codec.js';
import {
  unpackRotationEntry,
  parseNextKeyCommitments,
  rotationEntryFromJson,
  type RotationEntryJson,
} from '../../src/did/rotation-entry-codec.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';
import type { DidDocument } from '../../src/did/types.js';
import type { DidDocumentRow, RotationLogRowIn } from './input.js';

export const CURRENT_PREFIX = 'did:scid:vh:1:';
export const LEGACY_PREFIX = 'did:scidvh:';

export type Verdict = 'accept' | 'reject' | 'unverifiable';

/** What the resolver would do with this identifier once package A is deployed. */
export type Resolution =
  | 'log' // full chain verified, resolves from the log
  | 'log-truncated' // genesis accepted, but the chain stops early (unchanged by package A)
  | 'cache-only:chain-invalid' // log held, refused: cached document_json served, source "cache"
  | 'cache-only:no-log-held' // no log: cached document_json served, source "cache"
  | 'unresolvable'; // refused and no cached document

export type FailureClass =
  | 'legacy-prefix' // did:scidvh:<scid> (flat form)
  | 'other-version-prefix' // did:scid:vh:<not 1>:
  | 'not-scid-vh'
  | 'no-log'
  | 'malformed-entry' // a row could not be unpacked
  | 'version-gap' // versions are not 0..n-1
  | 'genesis-version' // first entry is not version 0
  | 'genesis-id-mismatch' // genesis document id is not the identifier
  | 'scid-hash-mismatch' // SCID is not the hash of the genesis entry
  | 'genesis-digest' // the genesis' own stored digest does not match its fields
  | 'genesis-signature' // genesis digest ok but signature / PQ signature / prevHash fail
  | 'chain-truncated'; // genesis ok, later entry invalid (not a genesis-check issue)

export interface Diagnostics {
  /** The SCID matches when the genesis document/parameters are re-hashed with keys in this order. */
  keyOrderMatch?: 'sorted' | 'jsonb';
  /** The SCID matches when createdAt is shifted by this many seconds (within +-DRIFT_WINDOW). */
  createdAtOffsetSeconds?: number;
  /** The genesis' stored digest differs from a recomputation over the stored fields. */
  storedDigestMatchesFields?: boolean;
}

export interface IdentifierReport {
  did: string;
  source: 'db-export' | 'list';
  method: string | null;
  verdict: Verdict;
  /** Would the package A genesis check accept this identifier with its log? null when no log is available. */
  genesisCheck: 'accept' | 'reject' | 'not-checkable';
  classes: FailureClass[];
  reasons: string[];
  resolution: Resolution;
  /** Rejected by the new check but valid under the previous chain validation. */
  newlyBroken: boolean;
  /** Invalid under the previous chain validation too (already refused before package A). */
  alreadyBroken: boolean;
  entries: number;
  validEntriesNew: number;
  validEntriesOld: number;
  firstFailingVersion: number | null;
  /** Per entry, in log order: whether an ML-DSA-65 signature is present. */
  mlDsaPerEntry: boolean[];
  cachedDocumentPresent: boolean;
  cachedDocumentIdMatches: boolean | null;
  diagnostics: Diagnostics;
}

export const DRIFT_WINDOW = 3600;

const method = new ScidVhMethod({});
type Validate = { validateChain(log: RotationLogEntry[], did?: string): { validEntries: RotationLogEntry[] } };
// validateChain is private; the genesis-hash tests use the same view of it.
const validEntryCount = (log: RotationLogEntry[], did?: string): number =>
  (method as unknown as Validate).validateChain(log, did).validEntries.length;

// ---------------------------------------------------------------------------
// Prefix
// ---------------------------------------------------------------------------

export function classifyPrefix(did: string): 'ok' | 'legacy-prefix' | 'other-version-prefix' | 'not-scid-vh' {
  if (did.startsWith(CURRENT_PREFIX)) return 'ok';
  if (did.startsWith(LEGACY_PREFIX)) return 'legacy-prefix';
  if (/^did:scid:vh:[^:]+:/.test(did)) return 'other-version-prefix';
  return 'not-scid-vh';
}

// ---------------------------------------------------------------------------
// Diagnostics (explain a hash mismatch; never change a verdict)
// ---------------------------------------------------------------------------

function sortKeys(v: unknown, order: 'sorted' | 'jsonb'): unknown {
  if (Array.isArray(v)) return v.map((x) => sortKeys(x, order));
  if (v && typeof v === 'object') {
    const keys = Object.keys(v as object);
    keys.sort(
      order === 'sorted'
        ? (a, b) => (a < b ? -1 : a > b ? 1 : 0)
        : // Postgres jsonb stores object keys by length, then bytewise.
          (a, b) => Buffer.byteLength(a) - Buffer.byteLength(b) || (a < b ? -1 : a > b ? 1 : 0),
    );
    const out: Record<string, unknown> = {};
    for (const k of keys) out[k] = sortKeys((v as Record<string, unknown>)[k], order);
    return out;
  }
  return v;
}

function scidOf(g: RotationLogEntry, override: Partial<RotationLogEntry>): string {
  const digest = computeRotationEntryDigest({
    version: g.version,
    parameters: g.parameters,
    prevHash: g.prevHash,
    nextKeyCommitments: g.nextKeyCommitments,
    createdAt: g.createdAt,
    ...override,
    didDocument: { ...(override.didDocument ?? g.didDocument), id: `${CURRENT_PREFIX}{SCID}` },
  });
  return base58btc.encode(digest);
}

export function diagnoseGenesis(did: string, g: RotationLogEntry): Diagnostics {
  const out: Diagnostics = {};
  const want = did.slice(CURRENT_PREFIX.length);
  out.storedDigestMatchesFields =
    Buffer.compare(
      Buffer.from(
        computeRotationEntryDigest({
          version: g.version, parameters: g.parameters, didDocument: g.didDocument, prevHash: g.prevHash,
          nextKeyCommitments: g.nextKeyCommitments, createdAt: g.createdAt,
        }),
      ),
      Buffer.from(g.digest),
    ) === 0;
  for (const order of ['sorted', 'jsonb'] as const) {
    const params = g.parameters ? (sortKeys(g.parameters, order) as RotationLogEntry['parameters']) : g.parameters;
    const doc = sortKeys(g.didDocument, order) as DidDocument;
    if (scidOf(g, { didDocument: doc, parameters: params }) === want) { out.keyOrderMatch = order; break; }
  }
  for (let d = 1; d <= DRIFT_WINDOW; d++) {
    if (scidOf(g, { createdAt: g.createdAt + d }) === want) { out.createdAtOffsetSeconds = d; break; }
    if (scidOf(g, { createdAt: g.createdAt - d }) === want) { out.createdAtOffsetSeconds = -d; break; }
  }
  return out;
}

// ---------------------------------------------------------------------------
// One identifier
// ---------------------------------------------------------------------------

export interface ScanInput {
  did: string;
  source: 'db-export' | 'list';
  method: string | null;
  /** Parsed log entries in version order, or null when no log was supplied for this identifier. */
  log: RotationLogEntry[] | null;
  /** A problem found while building `log` (malformed rows, version gaps). */
  logProblem?: { class: 'malformed-entry' | 'version-gap'; reason: string };
  documentJson: string | null;
}

function parseCached(json: string | null): DidDocument | null {
  if (!json) return null;
  try {
    const p = JSON.parse(json) as DidDocument;
    return p && typeof p === 'object' ? p : null;
  } catch {
    return null;
  }
}

export function scanIdentifier(input: ScanInput): IdentifierReport {
  const { did } = input;
  const classes: FailureClass[] = [];
  const reasons: string[] = [];
  const cached = parseCached(input.documentJson);
  const log = input.log ?? [];
  const prefix = classifyPrefix(did);
  const base = {
    did,
    source: input.source,
    method: input.method,
    entries: log.length,
    mlDsaPerEntry: log.map((e) => !!e.mlDsa65Signature),
    cachedDocumentPresent: cached !== null,
    cachedDocumentIdMatches: cached ? (cached.id ?? did) === did : null,
  };
  const finish = (r: Omit<IdentifierReport, keyof typeof base>): IdentifierReport => ({ ...base, ...r });
  const cacheResolution = (logHeld: boolean): Resolution =>
    cached ? (logHeld ? 'cache-only:chain-invalid' : 'cache-only:no-log-held') : 'unresolvable';
  const rejected = (diagnostics: Diagnostics = {}, extra: Partial<IdentifierReport> = {}): IdentifierReport =>
    finish({
      verdict: 'reject',
      genesisCheck: 'reject',
      classes, reasons,
      resolution: cacheResolution(log.length > 0),
      newlyBroken: false,
      alreadyBroken: false,
      validEntriesNew: 0,
      validEntriesOld: 0,
      firstFailingVersion: log.length > 0 ? 0 : null,
      diagnostics,
      ...extra,
    });

  if (prefix !== 'ok') {
    classes.push(prefix);
    reasons.push(
      prefix === 'legacy-prefix'
        ? 'legacy flat "did:scidvh:" form: fails the "did:scid:vh:1:" prefix test, so the genesis check refuses it for any log'
        : prefix === 'other-version-prefix'
          ? 'a did:scid:vh version other than 1: fails the "did:scid:vh:1:" prefix test'
          : 'not a did:scid:vh identifier',
    );
    if (log.length === 0) return rejected();
    // With a log, say whether the previous chain validation (no identifier check) accepted it.
    const oldValid = validEntryCount(log);
    if (oldValid > 0) reasons.push('the log is internally valid, so this identifier resolved from its log before package A and is newly broken');
    return rejected({}, { validEntriesOld: oldValid, newlyBroken: oldValid > 0, alreadyBroken: oldValid === 0 });
  }

  const suffix = did.slice(CURRENT_PREFIX.length);
  let shapeOk = false;
  try {
    shapeOk = suffix.startsWith('z') && base58btc.decode(suffix).length === 32;
  } catch { /* not base58btc */ }

  if (input.logProblem) {
    classes.push(input.logProblem.class);
    reasons.push(input.logProblem.reason);
    return rejected();
  }

  if (log.length === 0) {
    classes.push('no-log');
    reasons.push(
      `no rotation log supplied: the genesis check cannot be evaluated; the resolver serves only the cached document (source "cache", cacheReason "no-log-held")${shapeOk ? '' : '; the SCID is also not a 32-byte base58btc multihash digest, so it can never match a genesis'}`,
    );
    return finish({
      verdict: 'unverifiable', genesisCheck: 'not-checkable', classes, reasons,
      resolution: cacheResolution(false), newlyBroken: false, alreadyBroken: false,
      validEntriesNew: 0, validEntriesOld: 0, firstFailingVersion: null, diagnostics: {},
    });
  }

  const genesis = log[0];
  const validNew = validEntryCount(log, did);
  const validOld = validEntryCount(log);
  const genesisAccepted = scidMatchesGenesis(did, genesis);
  const common = { validEntriesNew: validNew, validEntriesOld: validOld };

  if (!genesisAccepted) {
    let diagnostics: Diagnostics = {};
    if (genesis.version !== 0) {
      classes.push('genesis-version');
      reasons.push(`the first log entry is version ${genesis.version}, not 0`);
    } else if (genesis.didDocument.id !== did) {
      classes.push('genesis-id-mismatch');
      reasons.push('the genesis entry\'s document id is not this identifier');
    } else {
      classes.push('scid-hash-mismatch');
      reasons.push('the SCID is not base58btc(sha256(genesis entry digest input with id "did:scid:vh:1:{SCID}"))');
      diagnostics = diagnoseGenesis(did, genesis);
      if (diagnostics.keyOrderMatch) {
        reasons.push(`canonicalisation sensitivity: the SCID matches when the genesis keys are re-ordered (${diagnostics.keyOrderMatch}); the stored document or parameters were re-serialised in a different key order`);
      }
      if (diagnostics.createdAtOffsetSeconds !== undefined) {
        reasons.push(`createdAt sensitivity: the SCID matches when createdAt is shifted by ${diagnostics.createdAtOffsetSeconds}s; the stored created_at is not the value that was hashed`);
      }
      if (diagnostics.storedDigestMatchesFields === false) {
        reasons.push('the genesis entry\'s own stored digest does not match its stored fields either (the log row was altered or re-serialised after signing)');
        classes.push('genesis-digest');
      }
    }
    const alreadyBroken = validOld === 0;
    if (alreadyBroken && !classes.includes('genesis-digest') && validNew === 0 && genesisDigestBad(genesis)) {
      classes.push('genesis-digest');
    }
    if (alreadyBroken) reasons.push('the log was also refused by the previous chain validation (broken before package A)');
    return rejected(diagnostics, { ...common, newlyBroken: !alreadyBroken, alreadyBroken });
  }

  // Genesis accepted by the new check.
  if (validNew === 0) {
    // scidMatchesGenesis passed but the chain refuses entry 0: digest / signature / prevHash.
    if (genesisDigestBad(genesis)) {
      classes.push('genesis-digest');
      reasons.push('the genesis entry\'s stored digest does not match its fields');
    } else {
      classes.push('genesis-signature');
      reasons.push('the genesis signature, ML-DSA signature or prevHash does not verify');
    }
    return rejected({}, { ...common, alreadyBroken: true, genesisCheck: 'accept' });
  }

  let resolution: Resolution = 'log';
  let firstFailing: number | null = null;
  try {
    method.resolveFromLog(did, log);
  } catch (e) {
    // resolveFromLog refusing after validNew > 0 means no valid entries remain after witness policy; report generically.
    classes.push('chain-truncated');
    reasons.push(`resolveFromLog refused the log: ${(e as Error).message.replace(did, '<did>')}`);
    return rejected({}, { ...common, genesisCheck: 'accept', alreadyBroken: true });
  }
  if (validNew < log.length) {
    classes.push('chain-truncated');
    resolution = 'log-truncated';
    firstFailing = log[validNew].version;
    reasons.push(`genesis accepted, but the chain is valid only up to version ${log[validNew - 1].version}; entry version ${firstFailing} fails digest, link, pre-rotation commitment or signature (unchanged by package A)`);
  } else {
    reasons.push('genesis hash matches the identifier and the full chain validates');
  }
  return finish({
    verdict: 'accept', genesisCheck: 'accept', classes, reasons, resolution,
    newlyBroken: false, alreadyBroken: false, ...common, firstFailingVersion: firstFailing, diagnostics: {},
  });
}

function genesisDigestBad(g: RotationLogEntry): boolean {
  const d = computeRotationEntryDigest({
    version: g.version, parameters: g.parameters, didDocument: g.didDocument, prevHash: g.prevHash,
    nextKeyCommitments: g.nextKeyCommitments, createdAt: g.createdAt,
  });
  return Buffer.compare(Buffer.from(d), Buffer.from(g.digest)) !== 0;
}

// ---------------------------------------------------------------------------
// Building inputs
// ---------------------------------------------------------------------------

/** Build log entries from rotation_log rows exactly as `DidResolutionService.rowToRotationEntry` does. */
export function rowsToLog(rows: RotationLogRowIn[]): { log: RotationLogEntry[]; problem?: ScanInput['logProblem'] } {
  const sorted = [...rows].sort((a, b) => a.version - b.version);
  const log: RotationLogEntry[] = [];
  for (const row of sorted) {
    try {
      const u = unpackRotationEntry(row.signedEntry);
      if (u.digest.length !== 32 || u.signature.length !== 64) throw new Error('digest or signature has the wrong length');
      log.push({
        version: row.version,
        parameters: u.parameters,
        didDocument: u.didDocument,
        prevHash: row.previousHash,
        nextKeyCommitments: parseNextKeyCommitments(row.newPublicKey),
        createdAt: row.createdAt ?? 0,
        digest: u.digest,
        signature: u.signature,
        mlDsa65Signature: u.mlDsa65Signature,
        witnessAttestations: [],
      });
    } catch (e) {
      return { log: [], problem: { class: 'malformed-entry', reason: `rotation_log version ${row.version} could not be unpacked (${(e as Error).name})` } };
    }
  }
  const gap = sorted.findIndex((r, i) => r.version !== i);
  if (gap >= 0) {
    return { log, problem: { class: 'version-gap', reason: `rotation_log versions are not contiguous from 0 (first irregularity at position ${gap}, version ${sorted[gap].version}); duplicates or gaps` } };
  }
  return { log };
}

/** Build log entries from wire JSON (the utility-server / jsonl shape). */
export function wireToLog(entries: RotationEntryJson[]): { log: RotationLogEntry[]; problem?: ScanInput['logProblem'] } {
  try {
    const log = entries.map(rotationEntryFromJson);
    if (log.some((e) => e.digest.length !== 32 || e.signature.length !== 64)) throw new Error('digest or signature has the wrong length');
    return { log };
  } catch (e) {
    return { log: [], problem: { class: 'malformed-entry', reason: `log file entries could not be parsed (${(e as Error).name})` } };
  }
}

export interface ExportScan {
  reports: IdentifierReport[];
  skippedNonScidRows: number;
  orphanRotationLogGroups: number;
}

/** Scan a did_documents + rotation_log export. Only did:scid:vh-family identifiers are scanned. */
export function scanExport(docs: DidDocumentRow[], logRows: RotationLogRowIn[]): ExportScan {
  const byDoc = new Map<string, RotationLogRowIn[]>();
  for (const r of logRows) {
    const l = byDoc.get(r.didDocumentUuid);
    if (l) l.push(r); else byDoc.set(r.didDocumentUuid, [r]);
  }
  const known = new Set(docs.map((d) => d.uuid));
  const reports: IdentifierReport[] = [];
  let skipped = 0;
  for (const d of docs) {
    const scidFamily = /^did:scid/.test(d.did) || /scid/i.test(d.method ?? '');
    if (!scidFamily) { skipped++; continue; }
    const rows = byDoc.get(d.uuid);
    const built = rows ? rowsToLog(rows) : { log: [] as RotationLogEntry[] };
    reports.push(scanIdentifier({
      did: d.did, source: 'db-export', method: d.method,
      log: rows ? built.log : null, logProblem: built.problem, documentJson: d.documentJson,
    }));
  }
  const orphan = [...byDoc.keys()].filter((k) => !known.has(k)).length;
  return { reports, skippedNonScidRows: skipped, orphanRotationLogGroups: orphan };
}
