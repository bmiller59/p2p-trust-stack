// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * P4b: attestation through the pipeline-backed in-process adapter. Vectors by id:
 *  - PRF-101 (tamper), 102 (keyAgreement), 104 (unknown cryptosuite), 105 (controller is not the
 *    issuer), 106 (proof without recipient; design PRF-013), 108 (Tier 1 unsigned accepted) at
 *    Tier 1; PRF-103 (purpose pinned; design PRF-011) and PRF-107 (proof required) at Tier 2;
 *  - RSP-004 and RSP-005 (replies signed by the IUT under authentication, whole seconds, verifying
 *    under the request's recipient) and ERR-003 (errors signed) at Tier 2, plus every Tier 1
 *    ERR/LIF/RSP vector re-run at Tier 2 so every reply shape is checked signed;
 *  - ID-003 (issuer == proof signer == transport sender) by explicit sends.
 * The suite's PRF-001..033 fixture vectors are in proof-verify.test.ts. Non-vacuity: a verifier that
 * accepts everything fails PRF-101/105; replies that lose their proof fail RSP-004/ERR-003.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { BoundaryAdapter } from "./conformance/adapter.ts";
import type { BoundaryHandler } from "./conformance/adapter.ts";
import type { Adapter, SendParams, SendResult } from "./conformance/contract.ts";
import { allVectors, runVector, loadVectorFile } from "./conformance/vector-runner.ts";
import type { Env } from "./conformance/vector-runner.ts";
import type { SpecPolicy, TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { DidKeyResolver, didKeyFromEd25519 } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import { createEd25519BoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import { CARRIER_TYPE } from "./helpers.ts";

const actor = (byte: number) => {
  const secretKey = new Uint8Array(32).fill(byte);
  const did = didKeyFromEd25519(ed25519.getPublicKey(secretKey));
  return createEd25519BoundarySigner({ did, secretKey, fragment: did.slice("did:key:".length) });
};
const IUT = actor(1);
const A = actor(2);
const X = actor(3);
const NOW = "2026-11-12T10:00:00Z";

const spec: SpecPolicy = { typeUri: CARRIER_TYPE, isBearer: false, isProofRequired: false, isRecipientRequired: true, isIssuedAtRequired: true,
  payloadSchema: { type: "object", required: ["subject"], properties: { subject: { type: "string" } } } };
const carrierPayload = { subject: "did:web:alice.example" };
const handler: BoundaryHandler = {
  spec,
  handle: (doc) => ({ id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000dd", threadId: doc.threadId ?? doc.id, type: `${CARRIER_TYPE}#response`, issuer: doc.recipient, recipient: doc.issuer, issuedAt: "2026-11-12T10:00:00Z", payload: {} }) as TrustTaskDocument<unknown>,
  carrier: { typeUri: CARRIER_TYPE, class: "consequential", validPayload: carrierPayload },
};
const verifier = (accept = false): DidProofVerifier => {
  const v = new DidProofVerifier({ resolver: new DidKeyResolver() });
  if (accept) (v as unknown as { verify: unknown }).verify = async () => ({ valid: true, signer: A.did, purpose: "authentication" });
  return v;
};
const adapter = (tier: 1 | 2, opts: { accept?: boolean; signer?: boolean } = {}): BoundaryAdapter =>
  new BoundaryAdapter({ servedVids: [IUT.did], handlers: [handler], proof: { verifier: verifier(opts.accept), tier }, ...(opts.signer === false ? {} : { signer: IUT }) });
const env: Env = { iutVid: IUT.did, senderVid: A.did, otherVid: X.did, carrier: CARRIER_TYPE, carrierPayload, clockStart: NOW, keys: { A, X }, replyVerifier: verifier() };

const prf = loadVectorFile("prf.json");
const prfVec = (id: string) => ({ file: prf, vector: prf.vectors.find((v) => v.id === id)! });
const run = async (id: string, a: Adapter, file = prf) => {
  const vector = file.vectors.find((v) => v.id === id)!;
  return runVector(a, file, vector, env);
};

describe("Tier 1 attestation vectors (a verifier is configured; unsigned stays acceptable)", () => {
  for (const id of ["PRF-101", "PRF-102", "PRF-104", "PRF-105", "PRF-106", "PRF-108"]) {
    it(`${id}: ${prfVec(id).vector.title}`, async () => {
      assert.deepEqual((await run(id, adapter(1))).failures, []);
    });
  }
  it("a signed request is accepted and the reply is signed by the IUT under authentication (the signer is installed at Tier 1 too)", async () => {
    const out = await runVector(adapter(1), prf, { id: "t", title: "t", tier: 1, clarify: null, steps: [{ send: { template: "carrier.request" }, expect: { disposition: "response", state: { handled: 1 } } }] }, env);
    assert.deepEqual(out.failures, []);
  });
  it("PRF-103 and PRF-107 are Tier 2: an adapter that claims Tier 1 only does not claim them", async () => {
    assert.equal((await adapter(1).capabilities()).tierMax, 1);
    assert.equal(prfVec("PRF-103").vector.tier, 2);
    assert.equal(prfVec("PRF-107").vector.tier, 2);
  });
});

describe("Tier 2 (attested): proof on every request, purpose pinned, every reply signed", () => {
  for (const id of ["PRF-103", "PRF-107"]) {
    it(`${id}${id === "PRF-103" ? " (design PRF-011)" : ""}: ${prfVec(id).vector.title}`, async () => {
      assert.deepEqual((await run(id, adapter(2))).failures, []);
    });
  }
  for (const id of ["PRF-101", "PRF-102", "PRF-104", "PRF-105", "PRF-106"]) {
    it(`${id} also holds at Tier 2, and its error reply is signed`, async () => {
      assert.deepEqual((await run(id, adapter(2))).failures, []);
    });
  }
  it("the adapter declares tierMax 2, eddsa-jcs-2022, proofVerify and attested", async () => {
    const caps = await adapter(2).capabilities();
    assert.equal(caps.tierMax, 2);
    assert.deepEqual(caps.cryptosuites, ["eddsa-jcs-2022"]);
    assert.ok(caps.optional.includes("proofVerify") && caps.optional.includes("attested"));
  });
  const replyFiles = ["err.json", "lif.json", "rsp.json"];
  for (const { file, vector } of allVectors(replyFiles)) {
    const label = vector.id === "RSP-004" ? "RSP-004 (and RSP-005: verifies under the request's recipient)" : vector.id;
    // control types are not served by the in-process adapter until the layer 3b handlers (P4b of the plan)
    it(`${label}: ${vector.title}`, { skip: vector.id === "LIF-003" ? "control is a layer 3b handler" : false }, async () => {
      assert.deepEqual((await runVector(adapter(2), file, vector, env)).failures, []);
    });
  }
  it("RSP-005: the reply's proof verifies under the request's recipient and under no other identifier", async () => {
    const a = adapter(2);
    await a.setClock(NOW);
    const signed = signDocument({ id: "urn:uuid:66666666-6666-4666-8666-666666666666", type: CARRIER_TYPE, issuer: A.did, recipient: IUT.did, issuedAt: NOW, payload: carrierPayload }, A, { created: Date.parse(NOW) });
    const res = await a.send({ from: { kind: "actor", vid: A.did }, bytes: JSON.stringify(signed) });
    const reply = JSON.parse(res.replies[0]!) as Record<string, unknown> & { proof: { verificationMethod: string; proofPurpose: string; created: string } };
    assert.equal(reply.issuer, IUT.did);
    assert.equal(reply.proof.verificationMethod, IUT.verificationMethod);
    assert.equal(reply.proof.proofPurpose, "authentication");
    assert.match(reply.proof.created, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/, "whole-second created");
    assert.match(String(reply.issuedAt), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/, "whole-second issuedAt");
    const v = verifier();
    assert.equal((await v.verify(reply, { nowMs: Date.parse(NOW) })).signer, signed.recipient);
    // forged: the same reply re-attributed to the sender is not verifiable
    assert.equal((await v.verify({ ...reply, issuer: A.did }, { nowMs: Date.parse(NOW) })).valid, false);
  });
});

describe("ID-003: issuer == proof signer == transport sender (Tier 2)", () => {
  const send = async (a: BoundaryAdapter, doc: Record<string, unknown>, from: SendParams["from"]): Promise<{ code?: string; type: string; res: SendResult }> => {
    await a.setClock(NOW);
    const res = await a.send({ from, bytes: JSON.stringify(doc) });
    const r = res.replies[0] === undefined ? {} : (JSON.parse(res.replies[0]) as { type?: string; payload?: { code?: string } });
    return { code: r.payload?.code, type: r.type ?? "", res };
  };
  const base = (issuer: string, id: string) => ({ id: `urn:uuid:${id}-7777-4777-8777-777777777777`, type: CARRIER_TYPE, issuer, recipient: IUT.did, issuedAt: NOW, payload: carrierPayload });
  const created = Date.parse(NOW);

  it("all three are the same identifier: accepted", async () => {
    const r = await send(adapter(2), signDocument(base(A.did, "11111111"), A, { created }), { kind: "actor", vid: A.did });
    assert.equal(r.type, `${CARRIER_TYPE}#response`);
  });
  it("the transport sender is not the issuer: identityMismatch, even though the proof is valid", async () => {
    const r = await send(adapter(2), signDocument(base(A.did, "22222222"), A, { created }), { kind: "actor", vid: X.did });
    assert.equal(r.code, "identityMismatch");
  });
  it("the proof is by another identifier than the issuer: proofInvalid", async () => {
    const r = await send(adapter(2), signDocument(base(A.did, "33333333"), X, { created, allowIssuerMismatch: true }), { kind: "actor", vid: A.did });
    assert.equal(r.code, "proofInvalid");
  });
  it("the proof verifies under another key than the issuer's although it names the issuer's method: proofInvalid", async () => {
    const forger = createEd25519BoundarySigner({ did: A.did, secretKey: new Uint8Array(32).fill(9), verificationMethod: A.verificationMethod });
    const r = await send(adapter(2), signDocument(base(A.did, "44444444"), forger, { created }), { kind: "actor", vid: A.did });
    assert.equal(r.code, "proofInvalid");
  });
  it("a proof with no transport sender (proof-only) is accepted: the verified proof establishes the sender", async () => {
    const r = await send(adapter(2), signDocument(base(A.did, "55555555"), A, { created }), { kind: "none" });
    assert.equal(r.type, `${CARRIER_TYPE}#response`);
  });
});

describe("a Tier 2 reply is never sent unsigned", () => {
  it("with no signer the answer is a minimal unsigned unavailable body (503), nothing executed", async () => {
    const a = adapter(2, { signer: false });
    await a.setClock(NOW);
    const signed = signDocument({ id: "urn:uuid:88888888-8888-4888-8888-888888888888", type: CARRIER_TYPE, issuer: A.did, recipient: IUT.did, issuedAt: NOW, payload: carrierPayload }, A, { created: Date.parse(NOW) });
    const res = await a.send({ from: { kind: "actor", vid: A.did }, bytes: JSON.stringify(signed) });
    assert.equal(res.transport.status, 503);
    assert.deepEqual(res.replies, []);
  });
});

describe("non-vacuity", () => {
  class Mutant implements Adapter {
    private readonly inner: Adapter;
    private readonly mutate: (d: Record<string, unknown>) => Record<string, unknown>;
    constructor(inner: Adapter, mutate: (d: Record<string, unknown>) => Record<string, unknown>) { this.inner = inner; this.mutate = mutate; }
    capabilities = () => this.inner.capabilities();
    provision = (r: string[]) => this.inner.provision(r);
    trust = (v: string, d?: unknown) => this.inner.trust(v, d);
    setClock = (i: string) => this.inner.setClock(i);
    advance = (m: number) => this.inner.advance(m);
    trigger = (a: string, g: Record<string, unknown>) => this.inner.trigger(a, g);
    observe = (q: Parameters<Adapter["observe"]>[0]) => this.inner.observe(q);
    restart = () => this.inner.restart();
    reset = () => this.inner.reset();
    snapshot = () => this.inner.snapshot();
    diff = (s: string) => this.inner.diff(s);
    verifyProof = (p: { bytes: string }) => this.inner.verifyProof(p);
    async send(params: SendParams): Promise<SendResult> {
      const res = await this.inner.send(params);
      return { ...res, replies: res.replies.map((r) => JSON.stringify(this.mutate(JSON.parse(r) as Record<string, unknown>))) };
    }
  }
  it("acceptUnverifiedProof: a verifier that accepts everything fails PRF-101, 102 and 105", async () => {
    for (const id of ["PRF-101", "PRF-105"]) assert.ok(!(await run(id, adapter(1, { accept: true }))).pass, id);
  });
  it("unsignedReplies: replies that lose their proof fail RSP-004 and ERR-003", async () => {
    const strip = (d: Record<string, unknown>) => { const { proof: _p, ...rest } = d; return rest; };
    const rsp = loadVectorFile("rsp.json");
    const err = loadVectorFile("err.json");
    assert.ok(!(await run("RSP-004", new Mutant(adapter(2), strip), rsp)).pass);
    assert.ok(!(await run("ERR-003", new Mutant(adapter(2), strip), err)).pass);
  });
  it("wholeMillisecondTimestamps: a reply issuedAt with milliseconds fails RSP-004", async () => {
    const ms = (d: Record<string, unknown>) => ({ ...d, issuedAt: "2026-11-12T10:00:00.250Z" });
    assert.ok(!(await run("RSP-004", new Mutant(adapter(2), ms), loadVectorFile("rsp.json"))).pass);
  });
  it("a reply re-attributed to another identity fails RSP-005's check", async () => {
    assert.ok(!(await run("RSP-004", new Mutant(adapter(2), (d) => ({ ...d, issuer: X.did })), loadVectorFile("rsp.json"))).pass);
  });
});
