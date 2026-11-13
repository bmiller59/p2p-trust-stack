// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BoundaryAdapter } from "./conformance/adapter.ts";
import type { BoundaryHandler } from "./conformance/adapter.ts";
import { RPC_METHODS } from "./conformance/contract.ts";
import type { Adapter } from "./conformance/contract.ts";
import type { SpecPolicy, TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { CARRIER_TYPE } from "./helpers.ts";

const A = "did:web:a.example";
const B = "did:web:b.example";
const spec: SpecPolicy = { typeUri: CARRIER_TYPE, isBearer: false, isProofRequired: false, isRecipientRequired: true, isIssuedAtRequired: true };
const widget: BoundaryHandler = {
  spec,
  handle: (doc) => ({ id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000dd", threadId: doc.id, type: `${CARRIER_TYPE}#response`, payload: {} }) as TrustTaskDocument<unknown>,
  carrier: { typeUri: CARRIER_TYPE, class: "consequential", validPayload: { subject: "did:web:alice.example" } },
};
const request = (recipient: string, extra: Record<string, unknown> = {}): string =>
  JSON.stringify({ id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000ee", type: CARRIER_TYPE, issuer: "did:web:p.example", recipient, issuedAt: "2026-11-01T00:00:00Z", payload: { subject: "x" }, ...extra });

describe("adapter skeleton implements the suite adapter contract", () => {
  const adapter = new BoundaryAdapter({ servedVids: [A, B], handlers: [widget] });

  it("has every contract method", () => {
    for (const m of RPC_METHODS) assert.equal(typeof (adapter as unknown as Record<string, unknown>)[m], "function", m);
    const _typed: Adapter = adapter;
    assert.ok(_typed);
  });

  it("declares honest capabilities: Tier 1, no proof verification, the pins", async () => {
    const c = await adapter.capabilities();
    assert.equal(c.tierMax, 1);
    assert.deepEqual(c.supportedTypes, [CARRIER_TYPE]);
    assert.deepEqual(c.cryptosuites, []);
    assert.ok(!c.optional.includes("proofVerify"));
    assert.deepEqual(c.pins, { framework: "0.6.0", error: "0.6", binding: "none" });
  });

  it("methods not yet built say so rather than pretending", async () => {
    await assert.rejects(adapter.restart(), /not implemented/);
    await assert.rejects(adapter.trigger(), /not implemented/);
    await assert.rejects(adapter.verifyProof({ bytes: "{}" }), /not implemented/);
  });

  it("serves either identifier as recipient (myVid selector) and refuses a third with wrongRecipient", async () => {
    await adapter.setClock("2026-11-01T00:00:30Z");
    for (const [i, vid] of [A, B].entries()) {
      const r = await adapter.send({ from: { kind: "none" }, bytes: request(vid, { id: `urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000010${i}` }) });
      assert.equal((JSON.parse(r.replies[0]!) as { type: string }).type, `${CARRIER_TYPE}#response`, vid);
    }
    const bad = await adapter.send({ from: { kind: "none" }, bytes: request("did:web:c.example", { id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-000000000109" }) });
    assert.equal((JSON.parse(bad.replies[0]!) as { payload: { code: string } }).payload.code, "wrongRecipient");
  });

  it("answers an unregistered type unsupportedType, never answers an inbound error, and a proof present is refused (interim policy)", async () => {
    const un = await adapter.send({ from: { kind: "none" }, bytes: request(A, { type: "https://trusttasks.org/spec/nothing/here/0.1", id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000010a" }) });
    assert.equal((JSON.parse(un.replies[0]!) as { payload: { code: string } }).payload.code, "unsupportedType");
    const err = await adapter.send({ from: { kind: "none" }, bytes: request(A, { type: "https://trusttasks.org/spec/trust-task-error/0.6", id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000010b" }) });
    assert.deepEqual(err.replies, []);
    const withProof = await adapter.send({ from: { kind: "none" }, bytes: request(A, { id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000010c", proof: { type: "DataIntegrityProof" } }) });
    assert.equal((JSON.parse(withProof.replies[0]!) as { payload: { code: string } }).payload.code, "malformedRequest");
  });

  it("clock, snapshot, diff and reset behave", async () => {
    await adapter.reset();
    await adapter.setClock("2026-11-01T00:00:30Z");
    const snap = await adapter.snapshot();
    assert.equal((await adapter.diff(snap)).changed, false);
    await adapter.send({ from: { kind: "none" }, bytes: request(A) });
    assert.equal((await adapter.diff(snap)).changed, true);
    assert.equal((await adapter.observe({ query: "handled" })).value, 1);
    // window edge: advance past max age + skew, a fresh id with the old issuedAt is expired
    await adapter.advance(6 * 60_000);
    const late = await adapter.send({ from: { kind: "none" }, bytes: request(A, { id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000010d" }) });
    assert.equal((JSON.parse(late.replies[0]!) as { payload: { code: string } }).payload.code, "expired");
    await adapter.reset();
    assert.equal((await adapter.observe({ query: "handled" })).value, 0);
  });
});
