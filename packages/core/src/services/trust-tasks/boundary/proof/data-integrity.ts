// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Data Integrity proof primitives for Trust Task documents (conformance plan P4):
 * `eddsa-jcs-2022` over the JSON as received. The registry's proof package handles only did:key
 * and is not installable here, so this is our own implementation of the same suite (SPEC 4.7.1):
 *
 *   hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document without proof))
 *   proofValue = multibase(base58btc, Ed25519(hashData))
 *
 * where proofConfig is the proof without `proofValue` (and carries the document's `@context` when
 * the document has one). Canonicalisation is the registry runtime's `canonicalJson` (RFC 8785).
 * Ed25519 verification is strict (RFC 8032 section 5.1.7): small-order and non-canonical public
 * keys and non-canonical S are refused, matching the task force's proof fixtures.
 */
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { base58btc } from 'multiformats/bases/base58';
import { canonicalJson } from '../runtime.js';

export const EDDSA_JCS_2022 = 'eddsa-jcs-2022';
export const PROOF_TYPE = 'DataIntegrityProof';

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const sha256 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(b).digest());

/** JCS bytes of a JSON value. */
export const jcsBytes = (value: unknown): Uint8Array => utf8(canonicalJson(value));

/** The 64 bytes that are signed: hash of the canonical proof configuration then of the canonical body. */
export function hashData(config: unknown, body: unknown): Uint8Array {
  const out = new Uint8Array(64);
  out.set(sha256(jcsBytes(config)), 0);
  out.set(sha256(jcsBytes(body)), 32);
  return out;
}

/** Whole-second RFC 3339 UTC timestamp from epoch milliseconds. */
export function wholeSecondTimestamp(ms: number): string {
  return `${new Date(Math.floor(ms / 1000) * 1000).toISOString().slice(0, 19)}Z`;
}

export function encodeProofValue(signature: Uint8Array): string {
  return base58btc.encode(signature);
}

/** Decode a `z`-prefixed base58btc proofValue; null when it is not one. */
export function decodeProofValue(value: string): Uint8Array | null {
  if (!value.startsWith('z')) return null;
  try {
    return base58btc.decode(value);
  } catch {
    return null;
  }
}

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
// y-coordinates of the small-order points (orders 1, 2, 4, 8) of edwards25519.
const SMALL_ORDER_Y = new Set<bigint>([
  0n,
  1n,
  P - 1n,
  0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05n,
  0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7n,
]);

function leToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}

/** RFC 8032 strictness for the public key and S, then the cofactorless verification equation (node:crypto). */
export function ed25519VerifyStrict(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const y = leToBigInt(publicKey) & ((1n << 255n) - 1n);
  if (y >= P || SMALL_ORDER_Y.has(y)) return false;
  if (leToBigInt(signature.subarray(32)) >= L) return false;
  try {
    // OpenSSL's equation is cofactorless (a mixed-order R fails), which the task force's fixtures require.
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, publicKey]), format: 'der', type: 'spki' });
    return nodeVerify(null, message, key, signature);
  } catch {
    return false;
  }
}
