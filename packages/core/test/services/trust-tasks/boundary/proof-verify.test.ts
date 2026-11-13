// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * P4a: the DID-resolving proof verifier. PRF-001..033 are the task force's proof fixtures, run
 * through the verifier by vector id (PRF-002..005 are ES256 fixtures: the cryptosuite is not
 * claimed, so they are reported SKIP and asserted to be refused as unsupported, never as valid).
 * Own fixtures: did:peer:4 and did:scid:vh issuers (Slot-A and Slot-B), purposes, listed keys,
 * resolution failure rules, bounds.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createDidPeer4 } from "../../../../src/did/create.ts";
import { ScidVhMethod } from "../../../../src/did/scid-vh-method.ts";
import { DidResolver } from "../../../../src/did/did-resolver.ts";
import { generateEd25519KeyPair } from "../../../../src/crypto/primitives.ts";
import type { RotationLogEntry } from "../../../../src/did/rotation-types.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import type { ProofVerdict } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import {
  BoundedRotationLogSource, CompositeKeyResolver, DidKeyResolver, DidResolverKeyResolver, ResolutionRateLimiter,
  ResolutionUnavailable, SourcedKeyResolver, didKeyFromEd25519,
} from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import { createEd25519BoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import { FIXTURES } from "./helpers.ts";
import { loadVectorFile } from "./conformance/vector-runner.ts";

const NOW = Date.parse("2026-11-12T10:00:00Z");
const verifier = (resolver = new DidKeyResolver()) => new DidProofVerifier({ resolver: new CompositeKeyResolver([new DidKeyResolver(), resolver]) });
const read = (file: string): Record<string, unknown> => JSON.parse(readFileSync(join(FIXTURES, "proof", file), "utf8")) as Record<string, unknown>;

describe("PRF-001..033: the task force's proof fixtures, by vector id", () => {
  const prf = loadVectorFile("prf.json");
  const manifest = JSON.parse(readFileSync(join(FIXTURES, "proof", "manifest.json"), "utf8")) as { entries: { file: string; expect: "valid" | "invalid" }[] };
  const expectByFile = new Map(manifest.entries.map((e) => [e.file, e.expect]));
  const v = verifier();
  let ran = 0;
  for (const vec of prf.vectors) {
    const step = vec.steps[0] as unknown as { verifyProof?: { file: string; expect: "valid" | "invalid" } };
    if (step.verifyProof === undefined) continue;
    const { file, expect } = step.verifyProof;
    const cryptosuite = (vec.requires ?? []).find((r) => r.startsWith("cryptosuite:"));
    if (cryptosuite === "cryptosuite:ecdsa-jcs-2019") {
      it(`${vec.id} SKIP (ES256 not claimed): ${file} is refused as an unsupported cryptosuite, never valid`, async () => {
        const verdict = await v.verify(read(file.replace("proof/", "")), { nowMs: NOW });
        assert.equal(verdict.valid, false);
        assert.equal(verdict.failure, "unsupportedCryptosuite");
      });
      continue;
    }
    ran++;
    it(`${vec.id} ${file}: ${expect}`, async () => {
      assert.equal(expectByFile.get(file.replace("proof/", "")), expect, "the vector agrees with the fixture manifest");
      const verdict = await v.verify(read(file.replace("proof/", "")), { nowMs: NOW });
      assert.equal(verdict.valid, expect === "valid", `${file}: ${verdict.failure ?? ""} ${verdict.detail ?? ""}`);
    });
  }
  it("ran every eddsa fixture the manifest lists", () => {
    const eddsa = [...expectByFile.keys()].filter((f) => f.startsWith("eddsa-"));
    assert.equal(ran, eddsa.length);
  });
});

describe("own did:peer:4 and did:scid:vh issuers", () => {
  const doc = (issuer: string, extra: Record<string, unknown> = {}) => ({
    id: "urn:uuid:11111111-1111-4111-8111-111111111111", type: "https://trusttasks.org/spec/conformance/widget/0.1",
    issuer, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: { n: 1 }, ...extra,
  });
  const created = NOW;

  it("did:peer:4: signs with #key-1 under authentication and verifies offline", async () => {
    const peer = await createDidPeer4();
    const signer = createEd25519BoundarySigner({ did: peer.did, secretKey: peer.signingKeyPair.secretKey });
    const v = new DidProofVerifier({ resolver: new DidResolverKeyResolver(new DidResolver()) });
    const signed = signDocument(doc(peer.did), signer, { created });
    const verdict = await v.verify(signed, { nowMs: NOW });
    assert.equal(verdict.valid, true, verdict.detail);
    assert.equal(verdict.signer, peer.did);
    assert.equal(verdict.purpose, "authentication");
    assert.equal(verdict.keySource, "offline");
    // #key-1 is listed under both signing relationships
    const assertion = signDocument(doc(peer.did), signer, { created, purpose: "assertionMethod" });
    assert.equal((await v.verify(assertion, { nowMs: NOW })).valid, true);
  });

  it("did:peer:4: keyAgreement and an unlisted fragment are refused; a tampered body is refused", async () => {
    const peer = await createDidPeer4();
    const v = new DidProofVerifier({ resolver: new DidResolverKeyResolver(new DidResolver()) });
    const signer = createEd25519BoundarySigner({ did: peer.did, secretKey: peer.signingKeyPair.secretKey });
    const ka = signDocument(doc(peer.did), signer, { created, purpose: "keyAgreement" });
    assert.equal((await v.verify(ka, { nowMs: NOW })).failure, "purposeRefused");
    const other = createEd25519BoundarySigner({ did: peer.did, secretKey: peer.signingKeyPair.secretKey, fragment: "key-2" });
    const unlisted = signDocument(doc(peer.did), other, { created });
    assert.equal((await v.verify(unlisted, { nowMs: NOW })).failure, "keyNotListed", "#key-2 is a keyAgreement key, not an authentication key");
    const tampered = { ...signDocument(doc(peer.did), signer, { created }), payload: { n: 2 } };
    assert.equal((await v.verify(tampered, { nowMs: NOW })).failure, "signatureInvalid");
  });

  it("did:peer:4: a key that is not the document's (signed by another key, same fragment) is refused", async () => {
    const peer = await createDidPeer4();
    const stranger = generateEd25519KeyPair();
    const v = new DidProofVerifier({ resolver: new DidResolverKeyResolver(new DidResolver()) });
    const signed = signDocument(doc(peer.did), createEd25519BoundarySigner({ did: peer.did, secretKey: stranger.secretKey }), { created });
    assert.equal((await v.verify(signed, { nowMs: NOW })).failure, "signatureInvalid");
  });

  async function scid(slotA: boolean) {
    const method = new ScidVhMethod({});
    const transport = generateEd25519KeyPair();
    const r = await method.create(undefined, slotA ? { transportSigningKeyPair: transport } : {});
    const source = { async getLog(): Promise<RotationLogEntry[]> { return r.log; } };
    return { r, transport, resolver: new DidResolverKeyResolver(new DidResolver({ logSource: source })) };
  }

  it("did:scid:vh Slot-B (agent layout): #key-1 is the identity key, in authentication AND assertionMethod", async () => {
    const { r, resolver } = await scid(false);
    const keys = await resolver.resolve(r.did);
    const k1 = keys!.keys.find((k) => k.fragment === "key-1")!;
    assert.deepEqual([...k1.relationships].sort(), ["assertionMethod", "authentication"]);
    assert.equal(keys!.source, "log");
    const signer = createEd25519BoundarySigner({ did: r.did, secretKey: r.signingKeyPair.secretKey });
    const v = new DidProofVerifier({ resolver });
    for (const purpose of ["authentication", "assertionMethod"]) {
      const verdict = await v.verify(signDocument(doc(r.did), signer, { created, purpose }), { nowMs: NOW });
      assert.equal(verdict.valid, true, `${purpose}: ${verdict.detail}`);
    }
    assert.equal((await v.verify(signDocument(doc(r.did), signer, { created, purpose: "keyAgreement" }), { nowMs: NOW })).failure, "purposeRefused");
  });

  it("did:scid:vh Slot-A (server layout): #key-1 is the TSP key under authentication; assertionMethod is #key-scid only", async () => {
    const { r, transport, resolver } = await scid(true);
    const keys = await resolver.resolve(r.did);
    const k1 = keys!.keys.find((k) => k.fragment === "key-1")!;
    assert.deepEqual(k1.relationships, ["authentication"]);
    assert.deepEqual(Buffer.from(k1.publicKey), Buffer.from(transport.publicKey), "#key-1 holds the permanent TSP key");
    const signer = createEd25519BoundarySigner({ did: r.did, secretKey: transport.secretKey });
    const v = new DidProofVerifier({ resolver });
    assert.equal((await v.verify(signDocument(doc(r.did), signer, { created }), { nowMs: NOW })).valid, true);
    const asAssertion = signDocument(doc(r.did), signer, { created, purpose: "assertionMethod" });
    assert.equal((await v.verify(asAssertion, { nowMs: NOW })).failure, "keyNotListed", "#key-1 is not an assertion method on Slot-A");
    // the identity key signs assertionMethod as #key-scid
    const scidSigner = createEd25519BoundarySigner({ did: r.did, secretKey: r.signingKeyPair.secretKey, fragment: "key-scid" });
    assert.equal((await v.verify(signDocument(doc(r.did), scidSigner, { created, purpose: "assertionMethod" }), { nowMs: NOW })).valid, true);
  });

  it("issuer, signer and verification-method controller must agree (PRF-105 shape)", async () => {
    const a = await createDidPeer4();
    const b = await createDidPeer4();
    const v = new DidProofVerifier({ resolver: new DidResolverKeyResolver(new DidResolver()) });
    const signerB = createEd25519BoundarySigner({ did: b.did, secretKey: b.signingKeyPair.secretKey });
    const claimed = signDocument(doc(a.did), signerB, { created, allowIssuerMismatch: true });
    assert.equal((await v.verify(claimed, { nowMs: NOW })).failure, "issuerMismatch");
    // a relative reference is resolved against the issuer
    const signerA = createEd25519BoundarySigner({ did: a.did, secretKey: a.signingKeyPair.secretKey });
    const signed = signDocument(doc(a.did), signerA, { created }) as unknown as { proof: { verificationMethod: string } };
    const relative = { ...signed, proof: { ...signed.proof, verificationMethod: "#key-1" } };
    // the written reference is covered by the signature, so changing it breaks the signature, not the controller rule
    assert.equal((await v.verify(relative, { nowMs: NOW })).failure, "signatureInvalid");
    const relativeSigner = createEd25519BoundarySigner({ did: a.did, secretKey: a.signingKeyPair.secretKey, verificationMethod: "#key-1" });
    assert.equal((await v.verify(signDocument(doc(a.did), relativeSigner, { created }), { nowMs: NOW })).valid, true);
  });

  it("an issuer of a method not served is refused (definite), a malformed did:peer:4 likewise", async () => {
    const v = verifier(new DidResolverKeyResolver(new DidResolver()) as never);
    const key = generateEd25519KeyPair();
    const web = createEd25519BoundarySigner({ did: "did:web:example.com", secretKey: key.secretKey });
    assert.equal((await v.verify(signDocument(doc("did:web:example.com"), web, { created }), { nowMs: NOW })).failure, "unresolvableIssuer");
    const bad = createEd25519BoundarySigner({ did: "did:peer:4garbage", secretKey: key.secretKey });
    assert.equal((await v.verify(signDocument(doc("did:peer:4garbage"), bad, { created }), { nowMs: NOW })).failure, "unresolvableIssuer");
  });
});

describe("resolution failure is unavailable, never proofInvalid; bounds", () => {
  const key = generateEd25519KeyPair();
  const did = "did:scid:vh:1:zQmExampleExampleExampleExampleExample";
  const signed = (d = did) => signDocument({ id: "urn:uuid:22222222-2222-4222-8222-222222222222", type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer: d, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: {} },
    createEd25519BoundarySigner({ did: d, secretKey: key.secretKey }), { created: NOW });
  const unavailable = async (v: DidProofVerifier, d: Record<string, unknown>) => {
    try {
      await v.verify(d, { nowMs: NOW });
    } catch (err) {
      return err as { code?: string; retryable?: boolean };
    }
    return undefined;
  };

  it("a log not held, a throwing source, a timeout and a cached result are all unavailable (retryable)", async () => {
    const empty = new DidProofVerifier({ resolver: new DidResolverKeyResolver(new DidResolver({ logSource: { async getLog() { return []; } } })) });
    const e1 = await unavailable(empty, signed());
    assert.equal(e1?.code, "unavailable"); assert.equal(e1?.retryable, true);
    const throwing = new DidProofVerifier({ resolver: new DidResolverKeyResolver(new DidResolver({ logSource: { async getLog() { throw new Error("connection refused"); } } })) });
    assert.equal((await unavailable(throwing, signed()))?.code, "unavailable");
    const slow = new BoundedRotationLogSource({ getLog: () => new Promise(() => undefined) }, { timeoutMs: 20 });
    const timeout = new DidProofVerifier({ resolver: new DidResolverKeyResolver(new DidResolver({ logSource: slow })) });
    assert.equal((await unavailable(timeout, signed()))?.code, "unavailable");
    const cached = new DidProofVerifier({ resolver: new SourcedKeyResolver(async () => ({ source: "cache", didDocument: { id: did, verificationMethod: [] } as never })) });
    assert.equal((await unavailable(cached, signed()))?.code, "unavailable", "a cache-sourced resolution is refused");
  });

  it("the entry cap refuses an oversized log; a fetched log is cached for the ttl and an error is not", async () => {
    let calls = 0;
    const big = Array.from({ length: 5 }, (_, i) => ({ version: i }) as unknown as RotationLogEntry);
    const capped = new BoundedRotationLogSource({ async getLog() { calls++; return big; } }, { maxEntries: 4 });
    await assert.rejects(capped.getLog(did), /larger than allowed/);
    let t = 0;
    const cache = new BoundedRotationLogSource({ async getLog() { calls++; return big; } }, { now: () => t, ttlMs: 1000 });
    calls = 0;
    await cache.getLog(did); await cache.getLog(did);
    assert.equal(calls, 1, "second read served from the cache");
    t = 2000; await cache.getLog(did);
    assert.equal(calls, 2, "refetched after the ttl");
    let fail = true; calls = 0;
    const flaky = new BoundedRotationLogSource({ async getLog() { calls++; if (fail) throw new Error("down"); return big; } }, { now: () => t });
    await assert.rejects(flaky.getLog(did)); fail = false; await flaky.getLog(did);
    assert.equal(calls, 2, "a failure is not cached");
  });

  it("the rate limit applies before any fetch: per DID and globally; offline methods are never counted", async () => {
    let t = 0; let fetched = 0;
    const limiter = new ResolutionRateLimiter({ perKey: 2, global: 3, windowMs: 1000, now: () => t });
    const src = new BoundedRotationLogSource({ async getLog() { fetched++; return []; } }, { limiter, ttlMs: 0 });
    const v = new DidProofVerifier({ resolver: new CompositeKeyResolver([new DidKeyResolver(), new DidResolverKeyResolver(new DidResolver({ logSource: src }))]) });
    assert.equal((await unavailable(v, signed()))?.code, "unavailable"); // not held: attempt 1
    assert.equal((await unavailable(v, signed()))?.code, "unavailable"); // attempt 2
    assert.equal(fetched, 2);
    assert.equal((await unavailable(v, signed()))?.code, "unavailable"); // per-DID limit: no fetch
    assert.equal(fetched, 2, "the third attempt never reached the source");
    await unavailable(v, signed("did:scid:vh:1:zQmOtherOtherOtherOtherOtherOtherOth")); // global 3
    await unavailable(v, signed("did:scid:vh:1:zQmThirdThirdThirdThirdThirdThirdThi"));
    assert.equal(fetched, 3, "the global limit stops distinct DIDs");
    t = 5000; await unavailable(v, signed());
    assert.equal(fetched, 4, "a new window opens");
    // did:key is offline: never limited
    const dk = createEd25519BoundarySigner({ did: didKeyFromEd25519(key.publicKey), secretKey: key.secretKey, fragment: didKeyFromEd25519(key.publicKey).slice(8) });
    for (let i = 0; i < 10; i++) {
      const d = signDocument({ id: `urn:uuid:3333333${i}-3333-4333-8333-333333333333`, type: "x", issuer: dk.did, recipient: "r", payload: {} }, dk, { created: NOW });
      assert.equal((await v.verify(d, { nowMs: NOW })).valid, true);
    }
  });

  it("the verdict carries what the pipeline persists", async () => {
    const dk = createEd25519BoundarySigner({ did: didKeyFromEd25519(key.publicKey), secretKey: key.secretKey, fragment: didKeyFromEd25519(key.publicKey).slice(8) });
    const d = signDocument({ id: "urn:uuid:44444444-4444-4444-8444-444444444444", type: "x", issuer: dk.did, recipient: "r", payload: {} }, dk, { created: NOW });
    const v = verifier();
    const bound = v.forContext({ nowMs: NOW });
    assert.equal(await bound.verify(d as never), true);
    const verdict = bound.verdict as ProofVerdict;
    assert.equal(verdict.signer, dk.did); assert.equal(verdict.purpose, "authentication"); assert.equal(verdict.createdMs, NOW);
    // a resolution that cannot complete is kept apart from a verdict (the runtime reports any failure as proofInvalid)
    const down = new DidProofVerifier({ resolver: { async resolve() { throw new ResolutionUnavailable("down"); } } }).forContext({ nowMs: NOW });
    assert.equal(await down.verify(signed(did) as never), false);
    assert.equal(down.verdict, undefined);
    assert.equal((down.unavailable as { code?: string } | undefined)?.code, "unavailable");
  });
});
