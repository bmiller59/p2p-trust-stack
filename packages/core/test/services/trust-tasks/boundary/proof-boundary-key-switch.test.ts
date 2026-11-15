// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Gate G2 (phase P11), K6/K7: the BoundarySigner switch to the dedicated key behind an explicit
 * configuration gate (default OFF), the cutover instant, and the key set at `created` end to end.
 */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { ScidVhMethod } from "../../../../src/did/scid-vh-method.ts";
import { generateEd25519KeyPairFromSeed, sha256 } from "../../../../src/crypto/primitives.ts";
import type { RotationLogEntry } from "../../../../src/did/rotation-types.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { TimePinnedKeyResolver } from "../../../../src/services/trust-tasks/boundary/proof/time-pinned.ts";
import { installBoundarySigner } from "../../../../src/services/trust-tasks/boundary/proof/install.ts";
import { deriveBoundaryKeyPair, keyPolicyOf, resolveBoundaryKeyConfig } from "../../../../src/services/trust-tasks/boundary/proof/key-config.ts";
import { getBoundarySigner, setBoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";

const method = new ScidVhMethod({});
const doc = (issuer: string) => ({ id: "urn:uuid:bbbbbbbb-2222-4222-8222-222222222222", type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: {} });
afterEach(() => setBoundarySigner(undefined));

describe("the configuration gate (default off)", () => {
  it("nothing configured, or key-1: the legacy key and no verifier policy", () => {
    for (const env of [{}, { TRUST_TASKS_BOUNDARY_KEY: "" }, { TRUST_TASKS_BOUNDARY_KEY: "key-1" }, { BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00Z" }]) {
      const { config, problem } = resolveBoundaryKeyConfig(env);
      assert.deepEqual(config, { mode: "key-1" });
      assert.equal(problem, undefined);
      assert.equal(keyPolicyOf(config), undefined);
    }
  });

  it("dedicated needs a cutover with an explicit zone; anything else is NOT honoured and says why", () => {
    for (const env of [
      { TRUST_TASKS_BOUNDARY_KEY: "dedicated" },
      { TRUST_TASKS_BOUNDARY_KEY: "dedicated", BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00" },
      { TRUST_TASKS_BOUNDARY_KEY: "dedicated", BOUNDARY_KEY_CUTOVER_AT: "tomorrow" },
      { TRUST_TASKS_BOUNDARY_KEY: "dedicated", BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00Z", BOUNDARY_KEY_MAX_PROOF_AGE_SECONDS: "-5" },
      { TRUST_TASKS_BOUNDARY_KEY: "Dedicated", BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T00:00:00Z" },
    ]) {
      const { config, problem } = resolveBoundaryKeyConfig(env);
      assert.equal(config.mode, "key-1", JSON.stringify(env));
      assert.ok(problem, JSON.stringify(env));
    }
  });

  it("dedicated with a cutover: the instant and the verifier policy", () => {
    const { config, problem } = resolveBoundaryKeyConfig({ TRUST_TASKS_BOUNDARY_KEY: "dedicated", BOUNDARY_KEY_CUTOVER_AT: "2030-01-01T02:00:00+02:00", BOUNDARY_KEY_MAX_PROOF_AGE_SECONDS: "120" });
    assert.equal(problem, undefined);
    assert.deepEqual(config, { mode: "dedicated", cutoverAtMs: Date.parse("2030-01-01T00:00:00Z"), maxProofAgeMs: 120_000 });
    assert.deepEqual(keyPolicyOf(config), { cutoverAtMs: Date.parse("2030-01-01T00:00:00Z"), maxProofAgeMs: 120_000 });
  });
});

describe("deriveBoundaryKeyPair", () => {
  it("is deterministic, depends on the seed, and is domain-separated from the keys the seed already yields", () => {
    const seed = new Uint8Array(32).fill(0x61);
    const a = deriveBoundaryKeyPair(seed);
    assert.deepEqual(deriveBoundaryKeyPair(seed).publicKey, a.publicKey);
    assert.notDeepEqual(deriveBoundaryKeyPair(new Uint8Array(32).fill(0x62)).publicKey, a.publicKey);
    const identity = generateEd25519KeyPairFromSeed(seed);
    const nextCommitted = generateEd25519KeyPairFromSeed(sha256(new Uint8Array([...seed, 0x01])));
    assert.notDeepEqual(a.publicKey, identity.publicKey);
    assert.notDeepEqual(a.publicKey, nextCommitted.publicKey);
  });
});

describe("signer switch and key set at created, end to end (Slot-A identity)", () => {
  async function setup() {
    const tsp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x71));
    const created = await method.create(undefined, { transportSigningKeyPair: tsp });
    const g = created.log[0]!.createdAt;
    const boundary = deriveBoundaryKeyPair(new Uint8Array(32).fill(0x72));
    const e1 = await method.addBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: boundary.publicKey, now: (g + 100) * 1000 });
    const log: RotationLogEntry[] = [...created.log, e1];
    const cutoverAtMs = (g + 200) * 1000;
    return { created, tsp, boundary, log, g, cutoverAtMs, published: e1.didDocument };
  }

  it("default (no dedicated option): installs #key-1 exactly as before", async () => {
    const s = await setup();
    const out = installBoundarySigner({ did: s.created.did, keys: () => s.tsp, didDocument: s.created.document });
    assert.deepEqual(out, { installed: true }, "the result shape is unchanged when the gate is off");
    assert.equal(getBoundarySigner()!.verificationMethod, `${s.created.did}#key-1`);
    assert.equal(getBoundarySigner()!.at, undefined);
  });

  it("dedicated requested but the document does not publish #key-boundary: stays on #key-1 and says why", async () => {
    const s = await setup();
    const out = installBoundarySigner({ did: s.created.did, keys: () => s.tsp, didDocument: s.created.document, dedicated: { keys: () => s.boundary, cutoverAtMs: s.cutoverAtMs } });
    assert.equal(out.installed, true);
    assert.equal(out.key, "key-1");
    assert.match(out.reason ?? "", /does not publish #key-boundary/);
    assert.equal(getBoundarySigner()!.at, undefined);
  });

  it("dedicated requested but the key held is not the published one: stays on #key-1", async () => {
    const s = await setup();
    const wrong = deriveBoundaryKeyPair(new Uint8Array(32).fill(0x73));
    const out = installBoundarySigner({ did: s.created.did, keys: () => s.tsp, didDocument: s.published, dedicated: { keys: () => wrong, cutoverAtMs: s.cutoverAtMs } });
    assert.equal(out.key, "key-1");
    assert.match(out.reason ?? "", /not the key published/);
  });

  it("with the key published: #key-1 before the cutover instant, #key-boundary from it on; the verifier accepts each at its own side", async () => {
    const s = await setup();
    const out = installBoundarySigner({ did: s.created.did, keys: () => s.tsp, didDocument: s.published, dedicated: { keys: () => s.boundary, cutoverAtMs: s.cutoverAtMs } });
    assert.deepEqual(out, { installed: true, key: "dedicated" });
    const signer = getBoundarySigner()!;
    const verifier = new DidProofVerifier({
      resolver: new TimePinnedKeyResolver({ source: { getLog: async () => s.log } }),
      keyPolicy: keyPolicyOf({ mode: "dedicated", cutoverAtMs: s.cutoverAtMs, maxProofAgeMs: 600_000 })!,
    });

    const before = signDocument(doc(s.created.did), signer, { created: s.cutoverAtMs - 1000 });
    assert.equal((before.proof as { verificationMethod: string }).verificationMethod, `${s.created.did}#key-1`);
    assert.equal((await verifier.verify(before, { nowMs: s.cutoverAtMs - 500 })).valid, true, "pre-cutover #key-1 document verifies");

    const after = signDocument(doc(s.created.did), signer, { created: s.cutoverAtMs });
    assert.equal((after.proof as { verificationMethod: string }).verificationMethod, `${s.created.did}#key-boundary`);
    const verdict = await verifier.verify(after, { nowMs: s.cutoverAtMs + 500 });
    assert.equal(verdict.valid, true, verdict.detail);
    assert.equal(verdict.purpose, "authentication");

    // The retired key is refused for a document created after the cutover, even when forged with the old key.
    const stale = signDocument(doc(s.created.did), { ...signer, at: undefined }, { created: s.cutoverAtMs + 1000 });
    assert.equal((await verifier.verify(stale, { nowMs: s.cutoverAtMs + 1500 })).failure, "keyNotListed");
  });

  it("the key set at created: the same dedicated-key document is refused when its created predates the entry that added the key", async () => {
    const s = await setup();
    installBoundarySigner({ did: s.created.did, keys: () => s.tsp, didDocument: s.published, dedicated: { keys: () => s.boundary, cutoverAtMs: s.g * 1000 } });
    const verifier = new DidProofVerifier({ resolver: new TimePinnedKeyResolver({ source: { getLog: async () => s.log } }), keyPolicy: {} });
    const early = signDocument(doc(s.created.did), getBoundarySigner()!, { created: (s.g + 50) * 1000 });
    assert.equal((early.proof as { verificationMethod: string }).verificationMethod, `${s.created.did}#key-boundary`, "the signer used the dedicated key");
    assert.equal((await verifier.verify(early, { nowMs: (s.g + 60) * 1000 })).failure, "keyNotListed", "key set at created lacks it");
    const later = signDocument(doc(s.created.did), getBoundarySigner()!, { created: (s.g + 150) * 1000 });
    assert.equal((await verifier.verify(later, { nowMs: (s.g + 160) * 1000 })).valid, true);
  });
});
