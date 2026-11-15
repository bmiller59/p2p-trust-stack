// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance vectors ERR-001/002, LIF-001/002/003 and RSP-001/002 (Tier 1) run against the in-process
 * adapter, which serves one carrier task. The Tier 2 vectors in the same files (ERR-003, RSP-004) need
 * signed replies (phase P4): they are reported not applicable, never passed. The vector files are byte
 * copies of the suite's, with provenance; test names embed the vector ids.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { BoundaryAdapter } from "./conformance/adapter.ts";
import type { BoundaryHandler } from "./conformance/adapter.ts";
import type { Adapter, SendParams, SendResult } from "./conformance/contract.ts";
import { VECTORS_DIR, allVectors, deterministicId, runVector } from "./conformance/vector-runner.ts";
import type { Env } from "./conformance/vector-runner.ts";
import type { SpecPolicy, TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { CARRIER_TYPE } from "./helpers.ts";

const IUT = "did:web:iut.example";
const SENDER = "did:web:a.example";
const spec: SpecPolicy = {
  typeUri: CARRIER_TYPE,
  isBearer: false,
  isProofRequired: false,
  isRecipientRequired: true,
  isIssuedAtRequired: true,
  payloadSchema: { type: "object", required: ["subject"], properties: { subject: { type: "string" } } },
};
const carrierPayload = { subject: "did:web:alice.example" };
const carrier: BoundaryHandler = {
  spec,
  handle: (doc) => ({ id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000dd", threadId: doc.threadId ?? doc.id, type: `${CARRIER_TYPE}#response`, issuer: doc.recipient, recipient: doc.issuer, payload: {} }) as TrustTaskDocument<unknown>,
  carrier: { typeUri: CARRIER_TYPE, class: "consequential", validPayload: carrierPayload },
};
const env: Env = { iutVid: IUT, senderVid: SENDER, carrier: CARRIER_TYPE, carrierPayload, clockStart: "2026-11-12T10:00:00Z" };
const fresh = (): BoundaryAdapter => new BoundaryAdapter({ servedVids: [IUT], handlers: [carrier] });

const wanted = ["ERR-001", "ERR-002", "LIF-001", "LIF-002", "LIF-003", "RSP-001", "RSP-002"];
const tier2 = ["ERR-003", "RSP-004"];

describe("vector files carry provenance", () => {
  const prov = JSON.parse(readFileSync(join(VECTORS_DIR, "PROVENANCE.json"), "utf8")) as { files: { path: string; sha256: string }[] };
  it("every copied vector file matches its recorded SHA-256", () => {
    assert.deepEqual(prov.files.map((f) => f.path).sort(), ["dup.json", "env.json", "err.json", "id.json", "lif.json", "rsp.json", "time.json"]);
    for (const f of prov.files) assert.equal(createHash("sha256").update(readFileSync(join(VECTORS_DIR, f.path))).digest("hex"), f.sha256, f.path);
  });
  it("the vectors under test are exactly the ones present in the files", () => {
    assert.deepEqual(allVectors().map((v) => v.vector.id).sort(), [...wanted, ...tier2].sort());
  });
});

describe("Tier 1 vectors pass against the adapter", () => {
  for (const { file, vector } of allVectors().filter((v) => wanted.includes(v.vector.id))) {
    it(`${vector.id}: ${vector.title}`, async () => {
      assert.equal(vector.tier, 1);
      const out = await runVector(fresh(), file, vector, env);
      assert.deepEqual(out.failures, []);
      assert.ok(out.pass);
    });
  }
});

describe("Tier 2 vectors are not applicable at Tier 1", () => {
  it("the adapter claims tierMax 1, so ERR-003 and RSP-004 are skipped rather than passed", async () => {
    assert.equal((await fresh().capabilities()).tierMax, 1);
    for (const { vector } of allVectors().filter((v) => tier2.includes(v.vector.id))) assert.equal(vector.tier, 2, vector.id);
  });
});

/** Wraps the adapter and corrupts replies, to show the runner does not pass vacuously. */
class Mutant implements Adapter {
  private readonly inner: BoundaryAdapter;
  private readonly mutate: (doc: Record<string, unknown>) => Record<string, unknown> | undefined;
  private readonly answerInbound: boolean;
  constructor(inner: BoundaryAdapter, mutate: (doc: Record<string, unknown>) => Record<string, unknown> | undefined, answerInbound = false) {
    this.inner = inner;
    this.mutate = mutate;
    this.answerInbound = answerInbound;
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
    if (this.answerInbound && res.replies.length === 0) {
      const inbound = JSON.parse(params.bytes) as Record<string, unknown>;
      if (String(inbound.type).includes("/trust-task-error/")) {
        return { ...res, replies: [JSON.stringify({ id: "x", type: "https://trusttasks.org/spec/trust-task-error/0.6", threadId: inbound.threadId, issuer: IUT, recipient: inbound.issuer, payload: { code: "malformedRequest", retryable: false } })], transport: { kind: "document" } };
      }
    }
    return { ...res, replies: res.replies.map((r) => JSON.stringify(this.mutate(JSON.parse(r) as Record<string, unknown>) ?? {})) };
  }
}

describe("non-vacuity: a broken adapter fails the vectors that name the rule", () => {
  const byId = (id: string) => allVectors().find((v) => v.vector.id === id)!;
  const failsWith = async (id: string, adapter: Adapter, text: RegExp): Promise<void> => {
    const { file, vector } = byId(id);
    const out = await runVector(adapter, file, vector, env);
    assert.ok(!out.pass, `${id} should fail`);
    assert.ok(out.failures.some((f) => text.test(f)), `${id}: ${out.failures.join(" | ")}`);
  };
  it("ERR-001: an error with no retryable", async () => {
    await failsWith("ERR-001", new Mutant(fresh(), (d) => { const p = { ...(d.payload as object) } as Record<string, unknown>; delete p.retryable; return { ...d, payload: p }; }), /retryable/);
  });
  it("ERR-001: an error that reuses the request id", async () => {
    await failsWith("ERR-001", new Mutant(fresh(), (d) => ({ ...d, id: deterministicId("ERR-001", "req") })), /reply id equals the request id/);
  });
  it("ERR-002 and LIF-001: an inbound error that gets an answer", async () => {
    await failsWith("ERR-002", new Mutant(fresh(), (d) => d, true), /expected silence/);
    await failsWith("LIF-001", new Mutant(fresh(), (d) => d, true), /expected silence/);
  });
  it("RSP-002: a reply on the wrong thread", async () => {
    await failsWith("RSP-002", new Mutant(fresh(), (d) => ({ ...d, threadId: "urn:uuid:other" })), /threadId/);
  });
  it("LIF-003: control served as a task", async () => {
    const a = new BoundaryAdapter({ servedVids: [IUT], handlers: [carrier, { ...carrier, spec: { ...spec, typeUri: "https://trusttasks.org/spec/trust-task-control/0.1" }, carrier: undefined }] });
    const { file, vector } = byId("LIF-003");
    const out = await runVector(a, file, vector, env);
    assert.ok(!out.pass);
  });
});
