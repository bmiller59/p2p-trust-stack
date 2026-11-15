// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Builds synthetic fixture identities (random throwaway keys, nothing real) covering each outcome of
 * the scan, as in-memory logs and as table / list exports. Used by the tests; run directly it writes
 * the exports into a directory:
 *
 *   node --conditions=development --experimental-strip-types --loader ./test-loader.mjs \
 *     tools/scid-scan/make-fixtures.ts <out-dir>
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { base58btc } from 'multiformats/bases/base58';
import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import { computeRotationEntryDigest } from '../../src/did/rotation-codec.js';
import { packRotationEntry, rotationEntryToJson } from '../../src/did/rotation-entry-codec.js';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import { logFileStem } from './input.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';

export interface FixtureIdentity {
  name: string;
  did: string;
  log: RotationLogEntry[];
  /** createdAt value stored in the rotation_log row when it differs from the signed one. */
  rowCreatedAtOverride?: Record<number, number>;
  documentJson: string | null;
  method: string;
  expect: { verdict: 'accept' | 'reject' | 'unverifiable'; classes: string[] };
}

const method = new ScidVhMethod({});

const sortedCopy = (v: unknown): unknown => {
  if (Array.isArray(v)) return v.map(sortedCopy);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortedCopy((v as Record<string, unknown>)[k])]));
  }
  return v;
};
const reversedCopy = (v: unknown): unknown => {
  if (Array.isArray(v)) return v.map(reversedCopy);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v).reverse().map((k) => [k, reversedCopy((v as Record<string, unknown>)[k])]));
  }
  return v;
};

export async function buildFixtureIdentities(): Promise<FixtureIdentity[]> {
  const out: FixtureIdentity[] = [];
  const doc = (log: RotationLogEntry[]): string => JSON.stringify(log[log.length - 1].didDocument);

  const good = await method.create();
  out.push({ name: 'good-genesis', did: good.did, log: good.log, documentJson: doc(good.log), method: 'did:scid:vh', expect: { verdict: 'accept', classes: [] } });

  const rot = await method.create();
  const e1 = await method.rotate({
    currentLog: rot.log, outgoingSigningKeyPair: rot.signingKeyPair, newSigningKeyPair: rot.nextSigningKeyPairs[0]!,
    nextSigningPublicKey: generateEd25519KeyPair().publicKey, witnessAttestations: [],
  });
  out.push({ name: 'good-rotated', did: rot.did, log: [...rot.log, e1], documentJson: doc([...rot.log, e1]), method: 'did:scid:vh', expect: { verdict: 'accept', classes: [] } });

  // Genesis accepted, a later entry tampered: chain stops early, genesis check unchanged.
  const trunc = await method.create();
  const t1 = await method.rotate({
    currentLog: trunc.log, outgoingSigningKeyPair: trunc.signingKeyPair, newSigningKeyPair: trunc.nextSigningKeyPairs[0]!,
    nextSigningPublicKey: generateEd25519KeyPair().publicKey, witnessAttestations: [],
  });
  const badSig = new Uint8Array(t1.signature); badSig[0] ^= 0xff;
  out.push({ name: 'truncated-chain', did: trunc.did, log: [...trunc.log, { ...t1, signature: badSig }], documentJson: null, method: 'did:scid:vh', expect: { verdict: 'accept', classes: ['chain-truncated'] } });

  // Self-consistent log relabelled with another identifier.
  const victim = await method.create();
  const forger = await method.create();
  const g = forger.log[0]!;
  const fdoc = { ...g.didDocument, id: victim.did };
  const fdigest = computeRotationEntryDigest({ ...g, didDocument: fdoc });
  out.push({
    name: 'forged-genesis', did: victim.did,
    log: [{ ...g, didDocument: fdoc, digest: fdigest, signature: signEd25519(fdigest, forger.signingKeyPair.secretKey), mlDsa65Signature: undefined }],
    documentJson: JSON.stringify(fdoc), method: 'did:scid:vh', expect: { verdict: 'reject', classes: ['scid-hash-mismatch'] },
  });

  // Canonicalisation: identifier minted over a key-sorted genesis, stored with the keys in another order.
  const ko = await method.create();
  const kg = ko.log[0]!;
  const sortedDoc = sortedCopy({ ...kg.didDocument, id: 'did:scid:vh:1:{SCID}' }) as RotationLogEntry['didDocument'];
  const koScid = base58btc.encode(computeRotationEntryDigest({ ...kg, didDocument: sortedDoc }));
  const koDid = `did:scid:vh:1:${koScid}`;
  const koDoc = { ...sortedDoc, id: koDid };
  const koDigest = computeRotationEntryDigest({ ...kg, didDocument: koDoc });
  const signed = { ...kg, didDocument: koDoc, digest: koDigest, signature: signEd25519(koDigest, ko.signingKeyPair.secretKey), mlDsa65Signature: undefined };
  out.push({
    name: 'key-order-drift', did: koDid,
    log: [{ ...signed, didDocument: reversedCopy(koDoc) as RotationLogEntry['didDocument'] }],
    documentJson: JSON.stringify(koDoc), method: 'did:scid:vh', expect: { verdict: 'reject', classes: ['scid-hash-mismatch', 'genesis-digest'] },
  });

  // createdAt: the store keeps the insertion second, not the signed createdAt.
  const ca = await method.create();
  out.push({
    name: 'created-at-drift', did: ca.did, log: ca.log, rowCreatedAtOverride: { 0: ca.log[0]!.createdAt + 2 },
    documentJson: doc(ca.log), method: 'did:scid:vh', expect: { verdict: 'reject', classes: ['scid-hash-mismatch', 'genesis-digest'] },
  });

  // Legacy flat prefix with an otherwise genuine log.
  const leg = await method.create();
  const legDid = leg.did.replace('did:scid:vh:1:', 'did:scidvh:');
  out.push({
    name: 'legacy-prefix', did: legDid, log: leg.log, documentJson: JSON.stringify({ ...leg.log[0]!.didDocument, id: legDid }),
    method: 'did:scidvh', expect: { verdict: 'reject', classes: ['legacy-prefix'] },
  });

  const nl = await method.create();
  out.push({ name: 'no-log-cached', did: nl.did, log: [], documentJson: doc(nl.log), method: 'did:scid:vh', expect: { verdict: 'unverifiable', classes: ['no-log'] } });
  const nl2 = await method.create();
  out.push({ name: 'no-log-no-cache', did: nl2.did, log: [], documentJson: null, method: 'did:scid:vh', expect: { verdict: 'unverifiable', classes: ['no-log'] } });
  return out;
}

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64');
const hex = (b: Uint8Array): string => '\\x' + Buffer.from(b).toString('hex');

export interface TableExport {
  didDocuments: Record<string, unknown>[];
  rotationLog: Record<string, unknown>[];
}

/** Table export rows; binary cells are base64 (`encode(col, 'base64')`) or `\x` hex. */
export function toTableExport(ids: FixtureIdentity[], binary: 'base64' | 'hex'): TableExport {
  const enc = binary === 'base64' ? b64 : hex;
  const didDocuments: Record<string, unknown>[] = [];
  const rotationLog: Record<string, unknown>[] = [];
  ids.forEach((id, n) => {
    const uuid = `doc-${String(n).padStart(3, '0')}-${id.name}`;
    didDocuments.push({ uuid, did: id.did, method: id.method, document_json: id.documentJson, status: 'active' });
    for (const e of id.log) {
      rotationLog.push({
        uuid: `rl-${n}-${e.version}`,
        did_document_uuid: uuid,
        version: e.version,
        previous_hash: e.prevHash ? enc(e.prevHash) : null,
        new_public_key: enc(Buffer.from(JSON.stringify(e.nextKeyCommitments.map((k) => Buffer.from(k).toString('base64'))))),
        signed_entry: enc(packRotationEntry({ didDocument: e.didDocument, parameters: e.parameters, digest: e.digest, signature: e.signature, mlDsa65Signature: e.mlDsa65Signature })),
        created_at: id.rowCreatedAtOverride?.[e.version] ?? e.createdAt,
      });
    }
  });
  return { didDocuments, rotationLog };
}

export function rowsToCsv(rows: Record<string, unknown>[], columns: string[]): string {
  const cell = (v: unknown): string => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [columns.join(','), ...rows.map((r) => columns.map((c) => cell(r[c])).join(','))].join('\n') + '\n';
}

export const DID_DOCUMENT_COLUMNS = ['uuid', 'did', 'method', 'document_json', 'status'];
export const ROTATION_LOG_COLUMNS = ['uuid', 'did_document_uuid', 'version', 'previous_hash', 'new_public_key', 'signed_entry', 'created_at'];

/** List-mode files: identifier list plus <stem>.jsonl logs (identities with a log only). */
export function writeListMode(ids: FixtureIdentity[], dir: string): { listFile: string; logsDir: string } {
  const logsDir = join(dir, 'logs');
  mkdirSync(logsDir, { recursive: true });
  for (const id of ids) {
    if (id.log.length === 0) continue;
    const rows = id.log.map((e) => ({ ...rotationEntryToJson(e), ...(id.rowCreatedAtOverride?.[e.version] !== undefined ? { createdAt: id.rowCreatedAtOverride[e.version] } : {}) }));
    writeFileSync(join(logsDir, `${logFileStem(id.did)}.jsonl`), rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  }
  const listFile = join(dir, 'identifiers.txt');
  writeFileSync(listFile, '# synthetic fixture identifiers\n' + ids.map((i) => i.did).join('\n') + '\n');
  return { listFile, logsDir };
}

export function writeAll(dir: string, ids: FixtureIdentity[]): void {
  mkdirSync(dir, { recursive: true });
  const t = toTableExport(ids, 'base64');
  writeFileSync(join(dir, 'did_documents.json'), JSON.stringify(t.didDocuments, null, 1));
  writeFileSync(join(dir, 'rotation_log.json'), JSON.stringify(t.rotationLog, null, 1));
  const h = toTableExport(ids, 'hex');
  writeFileSync(join(dir, 'did_documents.csv'), rowsToCsv(h.didDocuments, DID_DOCUMENT_COLUMNS));
  writeFileSync(join(dir, 'rotation_log.csv'), rowsToCsv(h.rotationLog, ROTATION_LOG_COLUMNS));
  writeListMode(ids, dir);
}

if (process.argv[1]?.endsWith('make-fixtures.ts')) {
  const dir = process.argv[2];
  if (!dir) { process.stderr.write('usage: make-fixtures.ts <out-dir>\n'); process.exit(2); }
  writeAll(resolve(dir), await buildFixtureIdentities());
  process.stdout.write(`fixtures written to ${resolve(dir)}\n`);
}
