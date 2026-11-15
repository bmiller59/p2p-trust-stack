// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * rotate() and SpeculativeRotationService carry the previous DID document forward.
 *
 * Before, both rebuilt the document from the fixed-slot builder: a Slot-A rotation replaced the
 * permanent #key-1/#key-2 (the TSP VID) with the new identity key, the speculative path dropped
 * #key-mldsa/#key-kem, and any verification method added to the document vanished at the next
 * entry. Both slot layouts are covered: Slot-A (utility server: `#key-1` is the permanent TSP key,
 * the chain follows `#key-scid`) and Slot-B (agents: `#key-1` is the rotating identity key).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import { SpeculativeRotationService } from '../../src/did/speculative-rotation.js';
import { generateEd25519KeyPair, generateEd25519KeyPairFromSeed } from '../../src/crypto/primitives.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';
import type { DidDocument } from '../../src/did/types.js';

const SEED = new Uint8Array(32).fill(0x41);
const TSP_SEED = new Uint8Array(32).fill(0x42);
const method = new ScidVhMethod({});

function vm(doc: DidDocument, id: string) {
  return doc.verificationMethod.find((v) => v.id === id);
}
const validCount = (log: RotationLogEntry[]) =>
  (method as unknown as { validateChain(l: RotationLogEntry[]): { validEntries: RotationLogEntry[] } }).validateChain(log).validEntries.length;

async function slotA() {
  return method.create(undefined, {
    identitySeed: SEED,
    transportSigningKeyPair: generateEd25519KeyPairFromSeed(TSP_SEED),
  });
}
async function slotB() {
  return method.create();
}

test('Slot-A: rotate() keeps #key-1 / #key-2 (the TSP VID), advances only #key-scid, commits live and next key', async () => {
  const created = await slotA();
  const rotated = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: created.nextSigningKeyPairs[0],
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
  });
  const before = created.document;
  const after = rotated.didDocument;
  assert.equal(vm(after, '#key-1')!.publicKeyMultibase, vm(before, '#key-1')!.publicKeyMultibase, 'TSP VID key unchanged');
  assert.equal(vm(after, '#key-2')!.publicKeyMultibase, vm(before, '#key-2')!.publicKeyMultibase, 'agreement key unchanged');
  assert.ok(vm(after, '#key-scid'), '#key-scid kept');
  assert.notEqual(vm(after, '#key-scid')!.publicKeyMultibase, vm(before, '#key-scid')!.publicKeyMultibase, 'identity key advanced');
  assert.deepEqual(after.assertionMethod, before.assertionMethod);
  assert.deepEqual(after.authentication, before.authentication);
  assert.equal(rotated.nextKeyCommitments.length, 2, 'live key and a fresh next key are committed');
  assert.equal(validCount([...created.log, rotated]), 2);
});

test('Slot-B: rotate() still moves #key-1 and #key-2 to the new identity key', async () => {
  const created = await slotB();
  const rotated = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: created.nextSigningKeyPairs[0],
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
  });
  assert.notEqual(vm(rotated.didDocument, '#key-1')!.publicKeyMultibase, vm(created.document, '#key-1')!.publicKeyMultibase);
  assert.notEqual(vm(rotated.didDocument, '#key-2')!.publicKeyMultibase, vm(created.document, '#key-2')!.publicKeyMultibase);
  assert.equal(vm(rotated.didDocument, '#key-scid'), undefined, 'no #key-scid is invented for Slot-B');
  assert.equal(validCount([...created.log, rotated]), 2);
});

for (const [label, make] of [['Slot-A', slotA], ['Slot-B', slotB]] as const) {
  test(`${label}: rotate() and a later speculative claim keep PQ keys and an added method`, async () => {
    const created = await make();
    const added = {
      id: '#key-extra',
      type: 'Multikey' as const,
      controller: '',
      publicKeyMultibase: vm(created.document, '#key-1')!.publicKeyMultibase,
    };
    // Simulate a document that carries a verification method the fixed-slot builder does not know.
    const seeded: RotationLogEntry = {
      ...created.log[0],
      didDocument: { ...created.document, verificationMethod: [...created.document.verificationMethod, added] },
    };
    const rotated = await method.rotate({
      currentLog: [seeded],
      outgoingSigningKeyPair: created.signingKeyPair,
      newSigningKeyPair: created.nextSigningKeyPairs[0],
      nextSigningPublicKey: generateEd25519KeyPair().publicKey,
      witnessAttestations: [],
    });
    assert.ok(vm(rotated.didDocument, '#key-extra'), 'added method survives rotate()');
    assert.ok(vm(rotated.didDocument, '#key-mldsa') && vm(rotated.didDocument, '#key-kem'), 'PQ keys kept by rotate()');

    const spec = await new SpeculativeRotationService().computeSpeculativeRotation({
      name: 'alice',
      namespace: 'test',
      did: created.did,
      currentLog: [seeded],
      outgoingSigningKeyPair: created.signingKeyPair,
      newSigningKeyPair: created.signingKeyPair,
      nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    });
    const doc = spec.didDocument;
    assert.ok(vm(doc, '#key-mldsa') && vm(doc, '#key-kem'), 'PQ keys kept (the speculative path used to drop them)');
    assert.ok(vm(doc, '#key-extra'), 'added method survives the speculative path');
  });
}
