// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Ceremony documents (conformance P8): the 2PC outcome to reply mapping of suite design section 12,
 * and the wire form of the ceremony types (plan 2.3). Pure tests; the handler tests come with the
 * handler.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ceremonyVerdict } from "../../../../src/services/trust-tasks/boundary/ceremony-outcome.ts";
import type { CeremonyFacts } from "../../../../src/services/trust-tasks/boundary/ceremony-outcome.ts";
import { REASON_VOCABULARY } from "../../../../src/services/trust-tasks/boundary/errors.ts";
import { fromWireTypeUri, toWireTypeUri } from "../../../../src/services/trust-tasks/boundary/urn-codec.ts";
import { tryParseTypeUri } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { CEREMONY_CO_SIGN_TYPE, CEREMONY_PROPOSE_TYPE } from "../../../../src/services/trust-tasks/type-uris.ts";

const NOW = Date.parse("2026-11-12T10:00:00Z");
const open = { status: "pending" as const, expiresAt: NOW + 60_000, errorCode: null, errorReason: null, retryable: null };
const facts = (over: Partial<CeremonyFacts> & { proposal?: Partial<CeremonyFacts["proposal"]> }): CeremonyFacts => ({
  now: NOW,
  ...over,
  proposal: { ...open, ...over.proposal },
});

describe("2PC-001/003 outcome to reply", () => {
  it("committed outcome with a crystallized proposal is a response; no transaction recorded still is", () => {
    assert.deepEqual(ceremonyVerdict(facts({ outcome: "committed", proposal: { status: "crystallized" } })), { kind: "respond" });
    assert.deepEqual(ceremonyVerdict(facts({ proposal: { status: "crystallized" } })), { kind: "respond" });
  });
  it("a response needs the effect: a committed outcome on a proposal not yet crystallized is indeterminate", () => {
    assert.deepEqual(ceremonyVerdict(facts({ outcome: "committed" })), { kind: "indeterminate", retryable: true });
  });
  it("a crystallized proposal whose transaction is in flight or unknown is not answered as committed", () => {
    for (const outcome of ["inFlight", "unknown"] as const) {
      assert.equal(ceremonyVerdict(facts({ outcome, proposal: { status: "crystallized" } })).kind, "indeterminate");
    }
  });
});

describe("pending ceremonies are next-step until the deadline", () => {
  it("pending within the deadline, with or without a transaction in flight, is next-step", () => {
    assert.deepEqual(ceremonyVerdict(facts({})), { kind: "next-step" });
    assert.deepEqual(ceremonyVerdict(facts({ outcome: "inFlight" })), { kind: "next-step" });
  });
  it("an unknown outcome on an open proposal is indeterminate, never guessed", () => {
    assert.deepEqual(ceremonyVerdict(facts({ outcome: "unknown" })), { kind: "indeterminate", retryable: true });
  });
});

describe("failures are taskFailed with a closed reason; expiry is deadlineLapsed", () => {
  it("the deadline reached (half-open) while pending, and the stored expired status, are deadlineLapsed, not retryable", () => {
    const lapsed = { kind: "error", code: "taskFailed", reason: "deadlineLapsed", retryable: false };
    assert.deepEqual(ceremonyVerdict(facts({ proposal: { expiresAt: NOW } })), lapsed);
    assert.deepEqual(ceremonyVerdict(facts({ proposal: { status: "expired" } })), lapsed);
    assert.deepEqual(ceremonyVerdict(facts({ proposal: { expiresAt: NOW - 1 }, outcome: "inFlight" })), lapsed);
  });
  it("a failed proposal reports its recorded code and reason", () => {
    const v = ceremonyVerdict(facts({ proposal: { status: "failed", errorCode: "taskFailed", retryable: false, reason: "nameTaken" } }));
    assert.deepEqual(v, { kind: "error", code: "taskFailed", reason: "nameTaken", retryable: false });
    const unavailable = ceremonyVerdict(facts({ proposal: { status: "failed", errorCode: "unavailable", retryable: true, reason: "storeFailed" } }));
    assert.deepEqual(unavailable, { kind: "error", code: "unavailable", reason: "storeFailed", retryable: true });
  });
  it("an aborted outcome reads the participant's recorded abort reason; without one it is a plain taskFailed", () => {
    assert.deepEqual(ceremonyVerdict(facts({ outcome: "aborted", abortReason: { code: "taskFailed", retryable: false, reason: "policyDenied" } })), { kind: "error", code: "permissionDenied", reason: "policyDenied", retryable: false });
    assert.deepEqual(ceremonyVerdict(facts({ outcome: "aborted" })), { kind: "error", code: "taskFailed", retryable: false });
  });
  it("a reason outside the closed vocabulary, or an unknown code, is an opaque internalError", () => {
    assert.deepEqual(ceremonyVerdict(facts({ outcome: "aborted", abortReason: { code: "taskFailed", retryable: false, reason: "somethingNew" } })), { kind: "error", code: "internalError", retryable: false });
    assert.deepEqual(ceremonyVerdict(facts({ proposal: { status: "failed", errorCode: "weird", retryable: false } })), { kind: "error", code: "internalError", retryable: false });
  });
  it("every reason in the closed vocabulary survives the mapping with its own code and retryability", () => {
    for (const reason of REASON_VOCABULARY) {
      const v = ceremonyVerdict(facts({ outcome: "aborted", abortReason: { code: "taskFailed", retryable: true, reason } }));
      assert.equal(v.kind, "error");
      if (v.kind === "error") assert.equal(v.reason, reason);
    }
  });
  it("an aborted proposal maps to an error, never a response", () => {
    assert.equal(ceremonyVerdict(facts({ proposal: { status: "aborted" } })).kind, "error");
  });
});

describe("wire form of the ceremony types (plan 2.3)", () => {
  it("both ceremony types have a valid URN form, with and without a fragment, that round-trips", () => {
    for (const internal of [CEREMONY_PROPOSE_TYPE, CEREMONY_CO_SIGN_TYPE]) {
      for (const fragment of ["", "#request", "#response"]) {
        const wire = toWireTypeUri(`${internal}${fragment}`);
        assert.ok(wire !== undefined, `${internal}${fragment}`);
        assert.ok(tryParseTypeUri(wire) !== null, wire);
        assert.equal(fromWireTypeUri(wire), `${internal}${fragment}`);
      }
    }
    assert.equal(toWireTypeUri(CEREMONY_PROPOSE_TYPE), "urn:p2pts:tasks:spec:ceremony:propose:0.1");
    assert.equal(toWireTypeUri(CEREMONY_CO_SIGN_TYPE), "urn:p2pts:tasks:spec:ceremony:co-sign:0.1");
  });
});
