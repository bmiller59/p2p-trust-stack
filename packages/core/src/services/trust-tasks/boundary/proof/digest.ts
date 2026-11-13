// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Task digests and outcome evidence (framework 4.9.3 and 4.9.4; conformance plan 3.4, P4).
 *
 *  - `taskDigestMultibase` of a document is the multibase (base58btc, prefix `z`) encoding of a
 *    sha2-256 multihash over the RFC 8785 canonical form of the document WITHOUT its top-level
 *    `proof`. Signing, re-signing or stripping the proof therefore never changes it; a `proof`
 *    member nested inside `payload` is part of the document and is kept.
 *  - A claimed digest is compared on DECODED bytes, so two multibase spellings of the same digest
 *    (`z` base58btc, `u` base64url, `f` hex) are equal. A multihash whose algorithm is not
 *    understood is UNVERIFIED: it is never read as a match and never falls back to the document `id`.
 *  - `documentDigest` (including the proof) is the registry runtime's, used only to detect duplicate
 *    conflicts; it is not a citation.
 *  - A receipt digest (`vrcDigestMultibase`, `vwcDigestMultibase`) is the same form over a
 *    credential AS STORED, recomputed by the receiver, never copied from a request.
 */
import { createHash } from 'node:crypto';
import { base58btc } from 'multiformats/bases/base58';
import { jcsBytes } from './data-integrity.js';

const SHA2_256 = 0x12;

const sha256 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(b).digest());

/** Multibase base58btc multihash (sha2-256) of the canonical form of any JSON value. */
export function digestMultibaseOf(value: unknown): string {
  const hash = sha256(jcsBytes(value));
  const multihash = new Uint8Array(2 + hash.length);
  multihash.set([SHA2_256, hash.length], 0);
  multihash.set(hash, 2);
  return base58btc.encode(multihash);
}

/** The task digest of a document: over the document without its top-level proof. */
export function taskDigestMultibase(doc: Record<string, unknown>): string {
  const { proof: _proof, ...body } = doc;
  return digestMultibaseOf(body);
}

export interface DecodedDigest {
  /** Multihash function code. */
  readonly code: number;
  readonly digest: Uint8Array;
}

/** Decode a multibase multihash (prefixes `z`, `u`, `f`); null when it is not one. */
export function decodeDigestMultibase(text: string): DecodedDigest | null {
  if (typeof text !== 'string' || text.length < 2) return null;
  let raw: Uint8Array;
  try {
    const body = text.slice(1);
    switch (text[0]) {
      case 'z':
        raw = base58btc.decode(text);
        break;
      case 'u':
        if (!/^[A-Za-z0-9_-]+$/.test(body)) return null;
        raw = new Uint8Array(Buffer.from(body, 'base64url'));
        break;
      case 'f':
        if (!/^(?:[0-9a-f]{2})+$/.test(body)) return null;
        raw = new Uint8Array(Buffer.from(body, 'hex'));
        break;
      default:
        return null;
    }
  } catch {
    return null;
  }
  if (raw.length < 2 || raw[1] !== raw.length - 2) return null;
  return { code: raw[0]!, digest: raw.slice(2) };
}

export type DigestComparison = 'match' | 'mismatch' | 'unverified';

/**
 * Compare a claimed digest with the digest of `doc`. `unverified` when the claim is not a
 * multibase multihash or names a hash function this implementation does not compute: the caller
 * must treat that as not proven, never as proven by some other member such as `id`.
 */
export function compareTaskDigest(doc: Record<string, unknown>, claimed: unknown): DigestComparison {
  if (typeof claimed !== 'string') return 'unverified';
  const decoded = decodeDigestMultibase(claimed);
  if (decoded === null || decoded.code !== SHA2_256 || decoded.digest.length !== 32) return 'unverified';
  const own = decodeDigestMultibase(taskDigestMultibase(doc))!;
  return Buffer.compare(Buffer.from(decoded.digest), Buffer.from(own.digest)) === 0 ? 'match' : 'mismatch';
}

// ---------------------------------------------------------------------------
// Outcome evidence
// ---------------------------------------------------------------------------

/** The citation an outcome-evidence credential carries: the initiating document's id and digest. */
export interface TaskCitation {
  readonly taskContext: string;
  readonly taskDigestMultibase: string;
}

export function citeTask(initiating: Record<string, unknown>): TaskCitation {
  if (typeof initiating.id !== 'string' || initiating.id === '') throw new Error('the initiating document has no id');
  return { taskContext: initiating.id, taskDigestMultibase: taskDigestMultibase(initiating) };
}

export type CitationCheck = { ok: true } | { ok: false; reason: 'contextMismatch' | 'digestMismatch' | 'digestUnverified' | 'malformedCitation' };

/**
 * Check a citation against the initiating document the receiver holds VERBATIM: the context must be
 * that document's id and the digest must reproduce over it (compared on decoded bytes).
 */
export function checkCitation(initiating: Record<string, unknown>, citation: { taskContext?: unknown; taskDigestMultibase?: unknown }): CitationCheck {
  if (typeof citation.taskContext !== 'string' || typeof citation.taskDigestMultibase !== 'string') return { ok: false, reason: 'malformedCitation' };
  if (citation.taskContext !== initiating.id) return { ok: false, reason: 'contextMismatch' };
  const cmp = compareTaskDigest(initiating, citation.taskDigestMultibase);
  if (cmp === 'unverified') return { ok: false, reason: 'digestUnverified' };
  return cmp === 'match' ? { ok: true } : { ok: false, reason: 'digestMismatch' };
}
