// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * rotation-entry-codec: the optional trailing ML-DSA-65 block of the packed
 * `rotation_log.signed_entry` blob.
 *
 *   - round trip (with and without the block),
 *   - rows written before the block existed still unpack,
 *   - unknown or malformed trailing data FAILS CLOSED (a reader that silently
 *     dropped a damaged block would turn a PQ-signed entry into a classical
 *     one with no signal),
 *   - the packer refuses a wrong-length signature.
 *
 * Run with:
 *   node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/did/rotation-entry-codec.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { packRotationEntry, unpackRotationEntry } from '../../src/did/rotation-entry-codec.js';
import { ML_DSA_65_SIG_BYTES } from '../../src/crypto/pqc.js';
import type { DidDocument } from '../../src/did/types.js';

const doc = { id: 'did:scid:vh:1:abc', verificationMethod: [] } as unknown as DidDocument;
const digest = new Uint8Array(32).fill(1);
const signature = new Uint8Array(64).fill(2);
const mlDsa = new Uint8Array(ML_DSA_65_SIG_BYTES).map((_, i) => i % 251);

const legacy = () => packRotationEntry({ didDocument: doc, parameters: undefined, digest, signature });
const withTail = () => packRotationEntry({ didDocument: doc, digest, signature, mlDsa65Signature: mlDsa });

function concat(a: Uint8Array, ...rest: number[][]): Uint8Array {
  const tail = rest.flat();
  const out = new Uint8Array(a.length + tail.length);
  out.set(a);
  out.set(tail, a.length);
  return out;
}

test('round trip: the ML-DSA-65 signature survives pack/unpack', () => {
  const got = unpackRotationEntry(withTail());
  assert.deepEqual(got.mlDsa65Signature, mlDsa);
  assert.deepEqual(got.digest, digest);
  assert.deepEqual(got.signature, signature);
  assert.deepEqual(got.didDocument, doc);
});

test('old rows (no trailing block) still unpack, with no signature', () => {
  const got = unpackRotationEntry(legacy());
  assert.equal(got.mlDsa65Signature, undefined);
  assert.deepEqual(got.signature, signature);
  assert.deepEqual(got.digest, digest);
});

test('the block is purely appended: the legacy prefix is byte-identical', () => {
  const l = legacy();
  const t = withTail();
  assert.deepEqual(t.subarray(0, l.length), l);
  assert.equal(t.length, l.length + 1 + 4 + ML_DSA_65_SIG_BYTES);
});

test('fail closed: a truncated block is rejected, not dropped', () => {
  const t = withTail();
  assert.throws(() => unpackRotationEntry(t.subarray(0, t.length - 1)), /ML-DSA|trailing/i);
  assert.throws(() => unpackRotationEntry(t.subarray(0, t.length - 1000)), /ML-DSA|trailing/i);
});

test('fail closed: a partial block header (1-4 trailing bytes) is rejected', () => {
  for (let n = 1; n <= 4; n++) {
    assert.throws(() => unpackRotationEntry(concat(legacy(), new Array(n).fill(1))), /trailing/i, `${n} bytes`);
  }
});

test('fail closed: unknown flag bits are rejected', () => {
  const t = withTail().slice();
  const flagsAt = legacy().length;
  t[flagsAt] = 0x03;
  assert.throws(() => unpackRotationEntry(t), /flag/i);
  t[flagsAt] = 0x02;
  assert.throws(() => unpackRotationEntry(t), /flag/i);
  t[flagsAt] = 0x00;
  assert.throws(() => unpackRotationEntry(t), /flag/i);
});

test('fail closed: bytes after the block are rejected', () => {
  assert.throws(() => unpackRotationEntry(concat(withTail(), [0])), /trailing/i);
});

test('fail closed: a block whose declared length is not 3309 is rejected', () => {
  const short = concat(legacy(), [1, 0, 0, 0, 100], new Array(100).fill(7));
  assert.throws(() => unpackRotationEntry(short), /length/i);
  const huge = concat(legacy(), [1, 0xff, 0xff, 0xff, 0xff]);
  assert.throws(() => unpackRotationEntry(huge), /length|trailing/i);
});

test('the packer refuses a wrong-length ML-DSA-65 signature', () => {
  assert.throws(
    () => packRotationEntry({ didDocument: doc, digest, signature, mlDsa65Signature: new Uint8Array(10) }),
    /ML-DSA/i,
  );
});
