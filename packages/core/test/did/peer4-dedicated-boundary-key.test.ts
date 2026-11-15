// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * K8 (decision 68, D6.2): a NEW did:peer:4 identifier can carry the dedicated `#key-boundary` key from creation.
 * Opt-in (default off, like the dedicated-key mode): with the option off every document and identifier is exactly
 * what it was; existing identifiers keep `#key-1` and are untouched (the verifier policy already accepts that).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDidPeer4Document, createDidPeer4 } from '../../src/did/create.ts';
import { DidPeer4Method } from '../../src/did/did-peer4-method.ts';
import { resolveDidPeer4 } from '../../src/did/resolve.ts';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.ts';

const key = (n: number) => new Uint8Array(32).fill(n);
const mk = (doc: { verificationMethod: Array<{ id: string; publicKeyMultibase: string }> }, id: string) => doc.verificationMethod.find((v) => v.id === id);

test('builder: no boundary key by default, byte-for-byte the same document', () => {
  const plain = buildDidPeer4Document(key(1), key(2));
  assert.equal(mk(plain, '#key-boundary'), undefined);
  assert.deepEqual(plain.verificationMethod.map((v) => v.id), ['#key-1', '#key-2']);
  assert.deepEqual(buildDidPeer4Document(key(1), key(2), undefined, undefined, undefined, undefined), plain);
});

test('builder: the dedicated key is appended after every method, under authentication only', () => {
  const doc = buildDidPeer4Document(key(1), key(2), { peerId: 'p', multiaddrs: [] }, undefined, { mlDsa65PublicKey: new Uint8Array(1952).fill(3) }, key(9));
  assert.deepEqual(doc.verificationMethod.map((v) => v.id), ['#key-1', '#key-2', '#key-mldsa', '#key-boundary']);
  assert.deepEqual(doc.authentication, ['#key-1', '#key-boundary']);
  assert.ok(!(doc.assertionMethod ?? []).includes('#key-boundary'));
  assert.ok(!(doc.keyAgreement ?? []).includes('#key-boundary'));
  assert.equal(doc.service?.[0]?.id, '#tsp');
});

test('createDidPeer4: off by default; on, the identifier itself carries #key-boundary and returns the key pair', async () => {
  const off = await createDidPeer4();
  assert.equal(off.boundaryKeyPair, undefined);
  assert.equal(mk(resolveDidPeer4(off.did), '#key-boundary'), undefined);

  const on = await createDidPeer4(undefined, { dedicatedBoundaryKey: true });
  assert.ok(on.boundaryKeyPair);
  const resolved = resolveDidPeer4(on.did);
  assert.ok(mk(resolved, '#key-boundary'), 'the key is part of the hashed document: resolves offline');
  assert.equal(mk(on.document, '#key-boundary')?.publicKeyMultibase, mk(resolved, '#key-boundary')?.publicKeyMultibase);
  assert.notDeepEqual(on.boundaryKeyPair!.publicKey, on.signingKeyPair.publicKey, 'a dedicated key, not #key-1');
  assert.deepEqual(resolved.verificationMethod.slice(0, 2).map((v) => v.id), ['#key-1', '#key-2'], 'extractors read [0] and [1] by index');
});

test('DidPeer4Method: the option reaches create() and the result', async () => {
  const plain = await new DidPeer4Method().create();
  assert.equal(plain.boundaryKeyPair, undefined);
  const on = await new DidPeer4Method({ dedicatedBoundaryKey: true }).create();
  assert.ok(on.boundaryKeyPair);
  assert.ok(mk(on.document, '#key-boundary'));
  void generateEd25519KeyPair;
});
