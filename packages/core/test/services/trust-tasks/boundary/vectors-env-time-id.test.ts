// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance vectors ENV, TIME and ID (Tier 1) run against the in-process adapter, which now routes
 * every document through the boundary pipeline (conformance plan P2). The files are byte copies of the
 * suite's; test names embed the vector ids. ENV-013 is Tier 2 (closed payloads) and not claimed.
 *
 * Ids as built: ENV-001..014 (the task named 001..010; 011, 012 and 014 are also Tier 1 and also run),
 * TIME-001..024 and 101/102, ID-001/002. PRF-012 is a proof-verification vector (optional capability
 * `proofVerify`): the adapter does not claim it, see prf-012-negative below.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BoundaryAdapter } from "./conformance/adapter.ts";
import type { BoundaryHandler } from "./conformance/adapter.ts";
import type { Adapter, SendParams, SendResult } from "./conformance/contract.ts";
import { allVectors, runVector } from "./conformance/vector-runner.ts";
import type { Env } from "./conformance/vector-runner.ts";
import type { SpecPolicy, TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { CARRIER_TYPE, fixture } from "./helpers.ts";

const IUT = "did:web:iut.example";
const SENDER = "did:web:a.example";
const FILES = ["env.json", "time.json", "id.json"];

const spec: SpecPolicy = {
  typeUri: CARRIER_TYPE,
  isBearer: false,
  isProofRequired: false,
  isRecipientRequired: true,
  isIssuedAtRequired: true,
  payloadSchema: { type: "object", required: ["subject"], properties: { subject: { type: "string" } } },
};
const carrierPayload = { subject: "did:web:alice.example" };
const handlerFor = (cls: "consequential" | "read"): BoundaryHandler => ({
  spec: cls === "read" ? { ...spec, isIssuedAtRequired: false } : spec,
  handle: (doc) => ({ id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000dd", threadId: doc.threadId ?? doc.id, type: `${CARRIER_TYPE}#response`, issuer: doc.recipient, recipient: doc.issuer, payload: {} }) as TrustTaskDocument<unknown>,
  carrier: { typeUri: CARRIER_TYPE, class: cls, validPayload: carrierPayload },
});
const env: Env = { iutVid: IUT, senderVid: SENDER, otherVid: "did:web:x.example", carrier: CARRIER_TYPE, carrierPayload, clockStart: "2026-11-12T10:00:00Z" };
const fresh = (cls: "consequential" | "read" = "consequential"): BoundaryAdapter => new BoundaryAdapter({ servedVids: [IUT], handlers: [handlerFor(cls)] });

const tier1 = allVectors(FILES).filter((v) => v.vector.tier === 1);
const expectedIds = [
  ...Array.from({ length: 12 }, (_, i) => `ENV-${String(i + 1).padStart(3, "0")}`),
  "ENV-014",
  ...Array.from({ length: 24 }, (_, i) => `TIME-${String(i + 1).padStart(3, "0")}`),
  "TIME-101",
  "TIME-102",
  "ID-001",
  "ID-002",
];

describe("the vectors under test are exactly the Tier 1 vectors in the copied files", () => {
  it("ids", () => {
    assert.deepEqual(tier1.map((v) => v.vector.id).sort(), [...expectedIds].sort());
  });
  it("ENV-013 is Tier 2 (closed payloads): not claimed at Tier 1", async () => {
    const t2 = allVectors(FILES).filter((v) => v.vector.tier === 2).map((v) => v.vector.id);
    assert.deepEqual(t2, ["ENV-013"]);
    assert.equal((await fresh().capabilities()).tierMax, 1);
  });
});

describe("Tier 1 vectors pass against the pipeline-backed adapter", () => {
  for (const { file, vector } of tier1) {
    it(`${vector.id}: ${vector.title}`, async () => {
      const out = await runVector(fresh(), file, vector, env);
      assert.deepEqual(out.failures, []);
    });
  }
});

/** Applies a change to every reply, to show the runner does not pass vacuously. */
class Mutant implements Adapter {
  private readonly inner: BoundaryAdapter;
  private readonly mutate: (doc: Record<string, unknown>) => Record<string, unknown>;
  constructor(inner: BoundaryAdapter, mutate: (doc: Record<string, unknown>) => Record<string, unknown>) {
    this.inner = inner;
    this.mutate = mutate;
  }
  capabilities = () => this.inner.capabilities();
  provision = (r: string[]) => this.inner.provision(r);
  trust = () => this.inner.trust();
  setClock = (i: string) => this.inner.setClock(i);
  advance = (m: number) => this.inner.advance(m);
  trigger = () => this.inner.trigger();
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

describe("non-vacuity: a broken adapter fails the vectors that name the rule", () => {
  const byId = (id: string) => allVectors(FILES).find((v) => v.vector.id === id)!;
  const fails = async (id: string, adapter: Adapter, text?: RegExp): Promise<void> => {
    const { file, vector } = byId(id);
    const out = await runVector(adapter, file, vector, env);
    assert.ok(!out.pass, `${id} should fail`);
    if (text !== undefined) assert.ok(out.failures.some((f) => text.test(f)), `${id}: ${out.failures.join(" | ")}`);
  };
  it("ID-001: a wrong-recipient error issued by the contested recipient (replyIssuerFromRequest)", async () => {
    await fails("ID-001", new Mutant(fresh(), (d) => ({ ...d, issuer: env.otherVid })), /not the IUT/);
  });
  it("ID-002: an identityMismatch addressed to the contested issuer instead of the sender", async () => {
    await fails("ID-002", new Mutant(fresh(), (d) => ({ ...d, recipient: SENDER })), /not addressed to the transport sender/);
  });
  it("ID-002: an identityMismatch that echoes the request id, or leaks an identity in its message", async () => {
    await fails("ID-002", new Mutant(fresh(), (d) => ({ ...d, payload: { ...(d.payload as object), inResponseTo: { typeUri: CARRIER_TYPE, id: "x" } } })), /echoes inResponseTo\.id/);
    await fails("ID-002", new Mutant(fresh(), (d) => ({ ...d, payload: { ...(d.payload as object), message: `sender ${SENDER}` } })), /leaks an identity/);
  });
  it("TIME-101 and TIME-003: a wide window (lenient mode on a read task) lets stale documents through", async () => {
    const lenient = new BoundaryAdapter({ servedVids: [IUT], handlers: [handlerFor("read")], strictness: "lenient" });
    await fails("TIME-101", lenient);
    await fails("TIME-003", new BoundaryAdapter({ servedVids: [IUT], handlers: [handlerFor("read")], strictness: "lenient" }));
  });
  it("ENV-009 and ENV-010: an adapter that answers an unknown type or version with the wrong code", async () => {
    const wrongCode = (d: Record<string, unknown>) => ({ ...d, payload: { ...(d.payload as object), code: "malformedRequest" } });
    await fails("ENV-009", new Mutant(fresh(), wrongCode), /expected code unsupportedType/);
    await fails("ENV-010", new Mutant(fresh(), wrongCode), /expected code unsupportedVersion/);
  });
});

describe("PRF-012 negative: no proof-verification claim, and a proof is never accepted unverified", () => {
  it("the adapter does not declare proofVerify or a cryptosuite", async () => {
    const caps = await fresh().capabilities();
    assert.ok(!(caps.optional ?? []).includes("proofVerify"));
    assert.deepEqual(caps.cryptosuites, []);
    await assert.rejects(() => fresh().verifyProof({ bytes: "{}" }), /not implemented/);
  });
  it("PRF-012: the timestamp-spellings proof fixture, sent as a request, is refused rather than accepted", async () => {
    const doc = fixture<Record<string, unknown>>("proof/eddsa-jcs-2022-timestamp-spellings.json");
    assert.ok(typeof doc.proof === "object", "the fixture is a signed document");
    const a = fresh();
    await a.setClock("2026-11-12T10:00:00Z");
    const body: Record<string, unknown> = { ...doc, type: CARRIER_TYPE, recipient: IUT, issuer: SENDER, issuedAt: "2026-11-12T10:00:00Z", payload: carrierPayload, id: "urn:uuid:11111111-1111-4111-8111-111111111111" };
    assert.ok(body.proof !== undefined, "the document carries a proof");
    const res = await a.send({ from: { kind: "actor", vid: SENDER }, bytes: JSON.stringify(body) });
    assert.equal(res.replies.length, 1);
    const reply = JSON.parse(res.replies[0]!) as { payload: { code: string } };
    assert.equal(reply.payload.code, "malformedRequest");
    assert.equal((await a.observe({ query: "handled" })).value, 0);
  });
});
