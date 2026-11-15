// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers


/**
 * Gate G2, custody of the dedicated `#key-boundary` key: provisioning into the encrypted key store,
 * fail-closed loading, the process signer (default off byte-identical, dedicated fails closed), and
 * rotation and retirement through the document-update path.
 */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { ScidVhMethod } from "../../../../src/did/scid-vh-method.ts";
import { generateEd25519KeyPairFromSeed } from "../../../../src/crypto/primitives.ts";
import { SqliteKeyStore } from "../../../../src/keystore/sqlite-keystore.ts";
import type { RotationLogEntry } from "../../../../src/did/rotation-types.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { TimePinnedKeyResolver } from "../../../../src/services/trust-tasks/boundary/proof/time-pinned.ts";
import { installBoundarySigner } from "../../../../src/services/trust-tasks/boundary/proof/install.ts";
import { keyPolicyOf } from "../../../../src/services/trust-tasks/boundary/proof/key-config.ts";
import { getBoundarySigner, setBoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import {
  BoundaryKeyError, boundaryKeyFingerprint, boundaryKeyType, destroyBoundaryKey, installProcessBoundarySigner, loadBoundaryKey,
  provisionBoundaryKey, resolveBoundaryProcessKeyConfig,
} from "../../../../src/services/trust-tasks/boundary/proof/key-custody.ts";

const method = new ScidVhMethod({});
const PASS = "test-passphrase-not-a-default";
const doc = (issuer: string) => ({ id: "urn:uuid:bbbbbbbb-2222-4222-8222-222222222222", type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: {} });
afterEach(() => setBoundarySigner(undefined));

function newStore() {
  const handle = new DatabaseSync(":memory:");
  return { handle, store: new SqliteKeyStore(handle) };
}

describe("provisioning and loading", () => {
  it("round trips a random key, stores it encrypted, and never overwrites a generation", async () => {
    const { handle, store } = newStore();
    const out = await provisionBoundaryKey({ store, vid: "did:example:a", passphrase: PASS, generation: 1 });
    const pair = await loadBoundaryKey({ store, vid: "did:example:a", passphrase: PASS, generation: 1 });
    assert.deepEqual(pair.publicKey, out.publicKey);
    assert.equal(out.fingerprint, boundaryKeyFingerprint(out.publicKey));
    const row = handle.prepare("SELECT encrypted_secret_key, key_type FROM keystore_keys").get() as { encrypted_secret_key: Uint8Array; key_type: string };
    assert.equal(row.key_type, boundaryKeyType(1));
    assert.equal(Buffer.from(row.encrypted_secret_key).includes(Buffer.from(pair.secretKey)), false, "the secret is not stored in the clear");
    await assert.rejects(provisionBoundaryKey({ store, vid: "did:example:a", passphrase: PASS, generation: 1 }), (e: BoundaryKeyError) => e.code === "exists");
    const second = await provisionBoundaryKey({ store, vid: "did:example:a", passphrase: PASS, generation: 2 });
    assert.notDeepEqual(second.publicKey, out.publicKey);
  });

  it("refuses an empty passphrase (no default)", async () => {
    const { store } = newStore();
    await assert.rejects(provisionBoundaryKey({ store, vid: "v", passphrase: "", generation: 1 }), (e: BoundaryKeyError) => e.code === "config");
  });

  it("FAILS CLOSED: a missing, wrong-passphrase, malformed or swapped record is an error, never a substitute", async () => {
    const { handle, store } = newStore();
    await assert.rejects(loadBoundaryKey({ store, vid: "v", passphrase: PASS, generation: 1 }), (e: BoundaryKeyError) => e.code === "missing" && /provision it/.test(e.message));
    await provisionBoundaryKey({ store, vid: "v", passphrase: PASS, generation: 1 });
    await assert.rejects(loadBoundaryKey({ store, vid: "v", passphrase: "other", generation: 1 }), (e: BoundaryKeyError) => e.code === "corrupt");
    await assert.rejects(loadBoundaryKey({ store, vid: "v", passphrase: PASS, generation: 2 }), (e: BoundaryKeyError) => e.code === "missing");
    handle.prepare("UPDATE keystore_keys SET encrypted_secret_key = zeroblob(8)").run();
    await assert.rejects(loadBoundaryKey({ store, vid: "v", passphrase: PASS, generation: 1 }), (e: BoundaryKeyError) => e.code === "corrupt");
    // a valid record whose public key was swapped for another key's
    const other = newStore();
    await provisionBoundaryKey({ store: other.store, vid: "v", passphrase: PASS, generation: 1 });
    const pub = (other.handle.prepare("SELECT public_key FROM keystore_keys").get() as { public_key: Uint8Array }).public_key;
    const fresh = newStore();
    await provisionBoundaryKey({ store: fresh.store, vid: "v", passphrase: PASS, generation: 1 });
    fresh.handle.prepare("UPDATE keystore_keys SET public_key = ?").run(pub);
    await assert.rejects(loadBoundaryKey({ store: fresh.store, vid: "v", passphrase: PASS, generation: 1 }), (e: BoundaryKeyError) => e.code === "corrupt");
  });

  it("errors never contain secret material or the passphrase", async () => {
    const { store } = newStore();
    const out = await provisionBoundaryKey({ store, vid: "v", passphrase: PASS, generation: 1 });
    const pair = await loadBoundaryKey({ store, vid: "v", passphrase: PASS, generation: 1 });
    try { await loadBoundaryKey({ store, vid: "v", passphrase: "wrongpass", generation: 1 }); assert.fail(); } catch (e) {
      const m = (e as Error).message;
      assert.equal(m.includes("wrongpass") || m.includes(Buffer.from(pair.secretKey).toString("hex")) || m.includes(Buffer.from(out.publicKey).toString("hex")), false);
    }
  });

  it("destroy removes the secret", async () => {
    const { store } = newStore();
    await provisionBoundaryKey({ store, vid: "v", passphrase: PASS, generation: 1 });
    assert.equal(destroyBoundaryKey({ store, vid: "v", generation: 1 }), true);
    assert.equal(destroyBoundaryKey({ store, vid: "v", generation: 1 }), false);
    await assert.rejects(loadBoundaryKey({ store, vid: "v", passphrase: PASS, generation: 1 }), (e: BoundaryKeyError) => e.code === "missing");
  });
});

describe("process configuration", () => {
  it("unset or key-1: the default, never throws; a bad dedicated setting THROWS instead of downgrading", () => {
    for (const env of [{}, { TRUST_TASKS_BOUNDARY_KEY: "key-1" }]) assert.deepEqual(resolveBoundaryProcessKeyConfig(env), { config: { mode: "key-1" }, generation: 1 });
    for (const env of [
      { TRUST_TASKS_BOUNDARY_KEY: "dedicated" },
      { TRUST_TASKS_BOUNDARY_KEY: "dedicate", BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00Z" },
      { TRUST_TASKS_BOUNDARY_KEY: "dedicated", BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00Z", BOUNDARY_KEY_GENERATION: "0" },
      { TRUST_TASKS_BOUNDARY_KEY: "dedicated", BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00Z", BOUNDARY_KEY_GENERATION: "abc" },
    ]) assert.throws(() => resolveBoundaryProcessKeyConfig(env), (e: BoundaryKeyError) => e.code === "config", JSON.stringify(env));
    assert.equal(resolveBoundaryProcessKeyConfig({ TRUST_TASKS_BOUNDARY_KEY: "dedicated", BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00Z", BOUNDARY_KEY_GENERATION: "3" }).generation, 3);
  });
});

describe("the process signer", () => {
  async function setup() {
    const tsp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x71));
    const created = await method.create(undefined, { transportSigningKeyPair: tsp });
    const { store } = newStore();
    const provisioned = await provisionBoundaryKey({ store, vid: created.did, passphrase: PASS, generation: 1 });
    const g = created.log[0]!.createdAt;
    const e1 = await method.addBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: provisioned.publicKey, now: (g + 100) * 1000 });
    return { tsp, created, store, provisioned, log: [...created.log, e1] as RotationLogEntry[], published: e1.didDocument, cutoverAtMs: (g + 200) * 1000 };
  }

  it("DEFAULT OFF, byte identical: with no gate set the result and the signed bytes equal the plain #key-1 install, and the key store is not touched", async () => {
    const s = await setup();
    const touched: string[] = [];
    const spy = { storeKeyPairAsync: async () => { touched.push("store"); }, retrieveKeyPairAsync: async () => { touched.push("retrieve"); throw new Error("no key found"); }, close() {} };
    const out = await installProcessBoundarySigner({ env: {}, did: s.created.did, didDocument: s.created.document, keys: () => s.tsp, custody: { store: spy, passphrase: PASS } });
    assert.deepEqual(out, { mode: "key-1", installed: true });
    const viaProcess = signDocument(doc(s.created.did), getBoundarySigner()!, { created: s.cutoverAtMs + 5000 });
    setBoundarySigner(undefined);
    assert.deepEqual(installBoundarySigner({ did: s.created.did, didDocument: s.created.document, keys: () => s.tsp }), { installed: true });
    const plain = signDocument(doc(s.created.did), getBoundarySigner()!, { created: s.cutoverAtMs + 5000 });
    assert.equal(JSON.stringify(viaProcess), JSON.stringify(plain));
    assert.deepEqual(touched, []);
    // even with the cutover variable present, nothing changes unless the mode is selected
    setBoundarySigner(undefined);
    const out2 = await installProcessBoundarySigner({ env: { BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00Z", BOUNDARY_KEY_GENERATION: "9" }, did: s.created.did, didDocument: s.published, keys: () => s.tsp });
    assert.deepEqual(out2, { mode: "key-1", installed: true });
    assert.equal(getBoundarySigner()!.at, undefined);
  });

  const env = (cutoverAtMs: number) => ({ TRUST_TASKS_BOUNDARY_KEY: "dedicated", BOUNDARY_KEY_CUTOVER_AT: new Date(cutoverAtMs).toISOString() });

  it("dedicated: installs the cutover signer; documents before the cutover use #key-1, from it on #key-boundary, and the verifier accepts both", async () => {
    const s = await setup();
    const out = await installProcessBoundarySigner({ env: env(s.cutoverAtMs), did: s.created.did, didDocument: s.published, keys: () => s.tsp, custody: { store: s.store, passphrase: PASS } });
    assert.deepEqual(out, { mode: "dedicated", installed: true, generation: 1, fingerprint: s.provisioned.fingerprint, cutoverAtMs: s.cutoverAtMs });
    const verifier = new DidProofVerifier({ resolver: new TimePinnedKeyResolver({ source: { getLog: async () => s.log } }), keyPolicy: keyPolicyOf({ mode: "dedicated", cutoverAtMs: s.cutoverAtMs, maxProofAgeMs: 600_000 })! });
    const after = signDocument(doc(s.created.did), getBoundarySigner()!, { created: s.cutoverAtMs });
    assert.equal((after.proof as { verificationMethod: string }).verificationMethod, `${s.created.did}#key-boundary`);
    assert.equal((await verifier.verify(after, { nowMs: s.cutoverAtMs + 500 })).valid, true);
  });

  it("FAILS CLOSED when the dedicated mode is on and the key is missing: throws and leaves NO signer, no fallback to #key-1", async () => {
    const s = await setup();
    setBoundarySigner(installPlain(s));
    const empty = newStore();
    await assert.rejects(
      installProcessBoundarySigner({ env: env(s.cutoverAtMs), did: s.created.did, didDocument: s.published, keys: () => s.tsp, custody: { store: empty.store, passphrase: PASS } }),
      (e: BoundaryKeyError) => e.code === "missing",
    );
    assert.equal(getBoundarySigner(), undefined);
  });

  it("FAILS CLOSED on a wrong passphrase, on no custody at all, and on a bad gate", async () => {
    const s = await setup();
    await assert.rejects(installProcessBoundarySigner({ env: env(s.cutoverAtMs), did: s.created.did, didDocument: s.published, keys: () => s.tsp, custody: { store: s.store, passphrase: "nope" } }), (e: BoundaryKeyError) => e.code === "corrupt");
    await assert.rejects(installProcessBoundarySigner({ env: env(s.cutoverAtMs), did: s.created.did, didDocument: s.published, keys: () => s.tsp }), (e: BoundaryKeyError) => e.code === "config");
    await assert.rejects(installProcessBoundarySigner({ env: { TRUST_TASKS_BOUNDARY_KEY: "dedicated" }, did: s.created.did, didDocument: s.published, keys: () => s.tsp, custody: { store: s.store, passphrase: PASS } }), (e: BoundaryKeyError) => e.code === "config");
    assert.equal(getBoundarySigner(), undefined);
  });

  it("FAILS CLOSED when the document does not publish the key (not yet published, or a did:peer:4 identifier)", async () => {
    const s = await setup();
    await assert.rejects(
      installProcessBoundarySigner({ env: env(s.cutoverAtMs), did: s.created.did, didDocument: s.created.document, keys: () => s.tsp, custody: { store: s.store, passphrase: PASS } }),
      (e: BoundaryKeyError) => e.code === "notPublished" && /publish the key first/.test(e.message),
    );
    assert.equal(getBoundarySigner(), undefined);
  });

  it("FAILS CLOSED when the stored generation is not the published key (rotation published, process not yet moved)", async () => {
    const s = await setup();
    const g2 = await provisionBoundaryKey({ store: s.store, vid: s.created.did, passphrase: PASS, generation: 2 });
    const e2 = await method.rotateBoundaryKey({ currentLog: s.log, identityKeyPair: s.created.signingKeyPair, boundaryPublicKey: g2.publicKey, now: s.cutoverAtMs });
    await assert.rejects(
      installProcessBoundarySigner({ env: env(s.cutoverAtMs), did: s.created.did, didDocument: e2.didDocument, keys: () => s.tsp, custody: { store: s.store, passphrase: PASS } }),
      (e: BoundaryKeyError) => e.code === "notPublished",
    );
    const moved = await installProcessBoundarySigner({ env: { ...env(s.cutoverAtMs), BOUNDARY_KEY_GENERATION: "2" }, did: s.created.did, didDocument: e2.didDocument, keys: () => s.tsp, custody: { store: s.store, passphrase: PASS } });
    assert.equal(moved.mode === "dedicated" && moved.generation, 2);
  });
});

function installPlain(s: { created: { did: string }; tsp: { publicKey: Uint8Array; secretKey: Uint8Array } }) {
  return { did: s.created.did, verificationMethod: `${s.created.did}#key-1`, publicKey: s.tsp.publicKey, sign: () => new Uint8Array(64) };
}

describe("rotation and retirement through the document-update path", () => {
  it("rotate replaces only #key-boundary; the old key stays valid for documents created before the entry, the new one after; same DID and #key-1", async () => {
    const tsp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x71));
    const created = await method.create(undefined, { transportSigningKeyPair: tsp });
    const g = created.log[0]!.createdAt;
    const k1 = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x81));
    const k2 = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x82));
    const e1 = await method.addBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: k1.publicKey, now: (g + 100) * 1000 });
    const e2 = await method.rotateBoundaryKey({ currentLog: [...created.log, e1], identityKeyPair: created.signingKeyPair, boundaryPublicKey: k2.publicKey, now: (g + 300) * 1000 });
    const log = [...created.log, e1, e2];
    assert.equal(method.validateEntries(log, created.did).length, 3);
    assert.equal(e2.didDocument.id, created.did);
    const vmOf = (d: typeof e1.didDocument, id: string) => d.verificationMethod.find((v) => v.id === id)?.publicKeyMultibase;
    assert.equal(vmOf(e2.didDocument, "#key-1"), vmOf(e1.didDocument, "#key-1"));
    assert.notEqual(vmOf(e2.didDocument, "#key-boundary"), vmOf(e1.didDocument, "#key-boundary"));
    const cutover = (g + 200) * 1000;
    const verifier = new DidProofVerifier({ resolver: new TimePinnedKeyResolver({ source: { getLog: async () => log } }), keyPolicy: keyPolicyOf({ mode: "dedicated", cutoverAtMs: cutover, maxProofAgeMs: 600_000 })! });
    const sign = (pair: { publicKey: Uint8Array; secretKey: Uint8Array }, createdMs: number) => {
      const signer = { did: created.did, verificationMethod: `${created.did}#key-boundary`, publicKey: pair.publicKey, sign: (m: Uint8Array) => generateSigned(pair, m) };
      return signDocument(doc(created.did), signer, { created: createdMs });
    };
    assert.equal((await verifier.verify(sign(k1, (g + 250) * 1000), { nowMs: (g + 251) * 1000 })).valid, true, "old key before the rotation entry");
    assert.equal((await verifier.verify(sign(k2, (g + 400) * 1000), { nowMs: (g + 401) * 1000 })).valid, true, "new key after it");
    assert.equal((await verifier.verify(sign(k1, (g + 400) * 1000), { nowMs: (g + 401) * 1000 })).valid, false, "retired key refused after it");
  });

  it("rotate is not a general loophole: only #key-boundary may change; a missing or unchanged key is refused", async () => {
    const tsp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x71));
    const created = await method.create(undefined, { transportSigningKeyPair: tsp });
    const k1 = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x81));
    await assert.rejects(method.rotateBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: k1.publicKey }), /not present/);
    const e1 = await method.addBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: k1.publicKey });
    await assert.rejects(method.rotateBoundaryKey({ currentLog: [...created.log, e1], identityKeyPair: created.signingKeyPair, boundaryPublicKey: k1.publicKey }), /already holds/);
    await assert.rejects(
      method.updateDocument({ currentLog: [...created.log, e1], identityKeyPair: created.signingKeyPair, allowChange: ["#key-boundary"], mutate: (d) => { d.verificationMethod = d.verificationMethod.filter((v) => v.id !== "#key-1"); } }),
      /#key-1 was removed/,
    );
  });

  it("retire removes #key-boundary and its authentication entry (cutover rollback); old documents stay verifiable, new ones fall back to #key-1", async () => {
    const tsp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x71));
    const created = await method.create(undefined, { transportSigningKeyPair: tsp });
    const g = created.log[0]!.createdAt;
    const k1 = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x81));
    const e1 = await method.addBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: k1.publicKey, now: (g + 100) * 1000 });
    const e2 = await method.retireBoundaryKey({ currentLog: [...created.log, e1], identityKeyPair: created.signingKeyPair, now: (g + 300) * 1000 });
    const log = [...created.log, e1, e2];
    assert.equal(method.validateEntries(log, created.did).length, 3);
    assert.equal(e2.didDocument.verificationMethod.some((v) => v.id === "#key-boundary"), false);
    assert.equal(e2.didDocument.authentication.includes("#key-boundary"), false);
    const verifier = new DidProofVerifier({ resolver: new TimePinnedKeyResolver({ source: { getLog: async () => log } }), keyPolicy: keyPolicyOf({ mode: "dedicated", cutoverAtMs: (g + 200) * 1000, maxProofAgeMs: 600_000 })! });
    const k1doc = signDocument(doc(created.did), { did: created.did, verificationMethod: `${created.did}#key-boundary`, publicKey: k1.publicKey, sign: (m) => generateSigned(k1, m) }, { created: (g + 250) * 1000 });
    assert.equal((await verifier.verify(k1doc, { nowMs: (g + 251) * 1000 })).valid, true);
    const after = signDocument(doc(created.did), { did: created.did, verificationMethod: `${created.did}#key-1`, publicKey: tsp.publicKey, sign: (m) => generateSigned(tsp, m) }, { created: (g + 400) * 1000 });
    assert.equal((await verifier.verify(after, { nowMs: (g + 401) * 1000 })).valid, true, "back on #key-1 after the rollback");
    const late = signDocument(doc(created.did), { did: created.did, verificationMethod: `${created.did}#key-boundary`, publicKey: k1.publicKey, sign: (m) => generateSigned(k1, m) }, { created: (g + 400) * 1000 });
    assert.equal((await verifier.verify(late, { nowMs: (g + 401) * 1000 })).valid, false);
  });
});

import { ed25519 } from "@noble/curves/ed25519.js";
function generateSigned(pair: { secretKey: Uint8Array }, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, pair.secretKey);
}
