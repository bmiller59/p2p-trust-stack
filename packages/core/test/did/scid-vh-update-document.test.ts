// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Gate G2 (phase P11), K1 and K2: `ScidVhMethod.updateDocument` and carry-forward in the other writers.
 *
 * Pins: an in-place add of a dedicated `#key-boundary` method yields a log entry that validates under
 * validateChain with the same DID and the same `#key-1`; every earlier method (PQ keys included) is
 * kept; and NO later writer (rotate, name claim, speculative claim) undoes the added method. Both slot
 * layouts are covered: Slot-A (utility server: `#key-1` is the permanent TSP key, the chain follows
 * `#key-scid`) and Slot-B (agents: `#key-1` is the rotating identity key).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScidVhMethod } from '../../src/did/scid-vh-method.js';
import { SpeculativeRotationService } from '../../src/did/speculative-rotation.js';
import { generateEd25519KeyPair, generateEd25519KeyPairFromSeed } from '../../src/crypto/primitives.js';
import { extractMlDsa65PublicKey, extractHybridKemPublicKey } from '../../src/relationship/key-extract.js';
import { mlDsa65Verify } from '../../src/crypto/pqc.js';
import { BOUNDARY_VM_ID, carryForwardViolations } from '../../src/did/document-carry-forward.js';
import type { DidDocument } from '../../src/did/types.js';

const SEED = new Uint8Array(32).fill(0x41);
const TSP_SEED = new Uint8Array(32).fill(0x42);
const method = new ScidVhMethod({});

function vm(doc: DidDocument, id: string) {
  return doc.verificationMethod.find((v) => v.id === id);
}
const ids = (doc: DidDocument) => doc.verificationMethod.map((v) => v.id);

async function slotA() {
  const created = await method.create(undefined, {
    identitySeed: SEED,
    transportSigningKeyPair: generateEd25519KeyPairFromSeed(TSP_SEED),
  });
  return created;
}
async function slotB() {
  return method.create();
}

for (const [label, make] of [['Slot-A', slotA], ['Slot-B', slotB]] as const) {
  test(`K1 ${label}: addBoundaryKey appends #key-boundary in place, the chain validates, the DID and #key-1 are unchanged`, async () => {
    const created = await make();
    const boundary = generateEd25519KeyPair();
    const entry = await method.addBoundaryKey({
      currentLog: created.log,
      identityKeyPair: created.signingKeyPair,
      boundaryPublicKey: boundary.publicKey,
      mlDsa65KeyPair: created.mlDsa65KeyPair,
    });
    const log = [...created.log, entry];

    assert.equal(entry.version, 1);
    assert.equal(method.validateEntries(log).length, 2, 'both entries validate under validateChain');
    const resolved = method.resolveFromLog(created.did, log);
    assert.equal(resolved.id, created.did, 'same DID');
    assert.equal(vm(resolved, '#key-1')!.publicKeyMultibase, vm(created.document, '#key-1')!.publicKeyMultibase, '#key-1 unchanged');
    assert.equal(ids(resolved)[0], '#key-1', 'index 0 still #key-1');
    assert.equal(ids(resolved)[1], '#key-2', 'index 1 still #key-2');
    assert.equal(ids(resolved).at(-1), BOUNDARY_VM_ID, 'appended LAST');
    assert.ok(resolved.authentication.includes(BOUNDARY_VM_ID), 'listed under authentication');
    assert.ok(!(resolved.assertionMethod ?? []).includes(BOUNDARY_VM_ID), 'not an assertion key');
    assert.ok(!resolved.keyAgreement.includes(BOUNDARY_VM_ID), 'not a key-agreement key');
    assert.deepEqual(carryForwardViolations(created.document, resolved), [], 'a carry-forward of genesis');
    // PQ keys retained and the PQ signature of the update verifies against the published key.
    assert.ok(extractMlDsa65PublicKey(resolved) && extractHybridKemPublicKey(resolved), 'PQ keys retained');
    assert.ok(entry.mlDsa65Signature);
    assert.equal(mlDsa65Verify(entry.mlDsa65Signature!, entry.digest, extractMlDsa65PublicKey(resolved)!), true);
    // Version N-1 lacks the method.
    assert.equal(vm(method.resolveFromLog(created.did, created.log), BOUNDARY_VM_ID), undefined);
  });

  test(`K2 ${label}: a later name claim (self-commit) and a later rotation never undo the added method`, async () => {
    const created = await make();
    const boundary = generateEd25519KeyPair();
    const e1 = await method.addBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: boundary.publicKey });
    let log = [...created.log, e1];

    // Name claim without rotating the identity key; it commits a fresh next key.
    const claimNext = generateEd25519KeyPair();
    const e2 = await method.claimName({
      currentLog: log,
      nameUri: 'vta:test:alice',
      outgoingSigningKeyPair: created.signingKeyPair,
      newSigningKeyPair: created.signingKeyPair,
      nextSigningPublicKey: claimNext.publicKey,
    });
    log = [...log, e2];
    assert.equal(method.validateEntries(log).length, 3);
    let doc = method.resolveFromLog(created.did, log);
    assert.ok(vm(doc, BOUNDARY_VM_ID), 'boundary method survives the name claim');
    assert.deepEqual(doc.alsoKnownAs, ['vta:test:alice']);
    assert.ok(extractMlDsa65PublicKey(doc) && extractHybridKemPublicKey(doc), 'PQ keys survive the name claim');

    // A genuine rotation to the pre-committed next key, then another update.
    const next = claimNext;
    const e3 = await method.rotate({
      currentLog: log,
      outgoingSigningKeyPair: created.signingKeyPair,
      newSigningKeyPair: next,
      nextSigningPublicKey: generateEd25519KeyPair().publicKey,
      witnessAttestations: [],
    });
    log = [...log, e3];
    assert.equal(method.validateEntries(log).length, 4);
    doc = method.resolveFromLog(created.did, log);
    assert.ok(vm(doc, BOUNDARY_VM_ID), 'boundary method survives a rotation');
    assert.equal(vm(doc, '#key-boundary')!.publicKeyMultibase, vm(e1.didDocument, '#key-boundary')!.publicKeyMultibase);
    assert.ok(extractMlDsa65PublicKey(doc), 'PQ key survives a rotation');
    // Rotation leaves the entry able to self-commit (commits its live key too).
    const e4 = await method.updateDocument({ currentLog: log, identityKeyPair: next, mutate: () => {} });
    assert.equal(method.validateEntries([...log, e4]).length, 5, 'a metadata-only entry after a rotation validates');
  });
}

test('K2 Slot-A regression: rotate() keeps #key-1 / #key-2 (the TSP VID), advances only #key-scid, commits a self-commit set', async () => {
  const created = await slotA();
  const next = created.nextSigningKeyPairs[0];
  const rotated = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: next,
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
  assert.equal(method.validateEntries([...created.log, rotated]).length, 2);
});

test('K2 Slot-B: rotate() still moves #key-1 and #key-2 to the new identity key', async () => {
  const created = await slotB();
  const next = created.nextSigningKeyPairs[0];
  const rotated = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: next,
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
  });
  assert.notEqual(vm(rotated.didDocument, '#key-1')!.publicKeyMultibase, vm(created.document, '#key-1')!.publicKeyMultibase);
  assert.notEqual(vm(rotated.didDocument, '#key-2')!.publicKeyMultibase, vm(created.document, '#key-2')!.publicKeyMultibase);
  assert.equal(vm(rotated.didDocument, '#key-scid'), undefined, 'no #key-scid is invented for Slot-B');
  assert.equal(method.validateEntries([...created.log, rotated]).length, 2);
});

for (const [label, make] of [['Slot-A', slotA], ['Slot-B', slotB]] as const) {
  test(`K2 ${label}: SpeculativeRotationService keeps #key-mldsa/#key-kem and the added #key-boundary`, async () => {
    const created = await make();
    const e1 = await method.addBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: generateEd25519KeyPair().publicKey });
    const log = [...created.log, e1];
    const spec = await new SpeculativeRotationService().computeSpeculativeRotation({
      name: 'alice',
      namespace: 'test',
      did: created.did,
      currentLog: log,
      outgoingSigningKeyPair: created.signingKeyPair,
      newSigningKeyPair: created.signingKeyPair,
      nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    });
    const doc = spec.didDocument;
    assert.ok(vm(doc, '#key-mldsa') && vm(doc, '#key-kem'), 'PQ keys kept (the speculative path used to drop them)');
    assert.ok(vm(doc, BOUNDARY_VM_ID), 'boundary method kept');
    assert.ok(doc.authentication.includes(BOUNDARY_VM_ID));
    assert.deepEqual(carryForwardViolations(e1.didDocument, doc), []);
    assert.equal(method.validateEntries([...log, spec.rotationEntry]).length, 3, 'the speculative entry validates');
  });
}

test('K1: updateDocument refuses a mutation that removes or changes an existing method, or the identity key', async () => {
  const created = await slotA();
  const args = { currentLog: created.log, identityKeyPair: created.signingKeyPair };
  await assert.rejects(method.updateDocument({ ...args, mutate: (d) => { d.verificationMethod = d.verificationMethod.filter((v) => v.id !== '#key-mldsa'); } }), /removed/);
  await assert.rejects(
    method.updateDocument({ ...args, mutate: (d) => { vm(d, '#key-1')!.publicKeyMultibase = vm(d, '#key-scid')!.publicKeyMultibase; } }),
    /changed/,
  );
  await assert.rejects(method.updateDocument({ ...args, mutate: (d) => { d.authentication = d.authentication.filter((a) => a !== '#key-1'); } }), /dropped/);
  await assert.rejects(method.updateDocument({ ...args, mutate: (d) => { d.assertionMethod = []; } }), /dropped/);
  await assert.rejects(method.addBoundaryKey({ ...args, boundaryPublicKey: generateEd25519KeyPair().publicKey }).then(async (e) =>
    method.addBoundaryKey({ currentLog: [...created.log, e], identityKeyPair: created.signingKeyPair, boundaryPublicKey: generateEd25519KeyPair().publicKey })), /already present/);
});

test('K1: updateDocument refuses a key that is not the chain\'s current key, and a key the previous entry did not commit', async () => {
  const created = await slotA();
  await assert.rejects(method.updateDocument({ currentLog: created.log, identityKeyPair: generateEd25519KeyPair(), mutate: () => {} }), /current signing key/);
  // After a rotation the OLD identity key is no longer the signing key.
  const rotated = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: created.nextSigningKeyPairs[0],
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
  });
  await assert.rejects(method.updateDocument({ currentLog: [...created.log, rotated], identityKeyPair: created.signingKeyPair, mutate: () => {} }), /current signing key/);
});

test('K1: createdAt is whole seconds from `now` and never earlier than the previous entry', async () => {
  const created = await slotB();
  const e = await method.updateDocument({ currentLog: created.log, identityKeyPair: created.signingKeyPair, mutate: () => {}, now: 1_900_000_123_456 });
  assert.equal(e.createdAt, 1_900_000_123);
  const e2 = await method.updateDocument({ currentLog: [...created.log, e], identityKeyPair: created.signingKeyPair, mutate: () => {}, now: 1_000_000_000_000 });
  assert.equal(e2.createdAt, e.createdAt, 'monotone');
});
