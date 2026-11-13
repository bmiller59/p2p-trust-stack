// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Lifecycle (framework 4.12) and the internal-status seam (plan P1: every internal status maps to
 * exactly one lifecycle state). LIF-001 and LIF-002 at the state-machine level; the wire-level
 * vectors run in vectors-err-lif-rsp.test.ts.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  LIFECYCLE_STATES,
  LifecycleError,
  PERMITTED_NEXT,
  PROPOSAL_STATUS_STATE,
  TERMINAL_STATES,
  TRUST_TASK_STATUSES,
  TRUST_TASK_STATUS_STATE,
  TX_OUTCOMES,
  TX_OUTCOME_STATE,
  canTransition,
  isTerminal,
  mayEmitError,
  mayEmitResponse,
  stateForErrorCode,
  transition,
} from "../../../../src/services/trust-tasks/boundary/lifecycle.ts";
import type { LifecycleState } from "../../../../src/services/trust-tasks/boundary/lifecycle.ts";
import { STANDARD_CODES } from "../../../../src/services/trust-tasks/boundary/runtime.ts";

const coreRoot = join(import.meta.dirname, "..", "..", "..", "..");

describe("framework 4.12 state machine", () => {
  it("has the nine framework states and exactly four terminal ones", () => {
    assert.deepEqual([...LIFECYCLE_STATES], ["received", "validated", "accepted", "executing", "suspended", "responded", "errored", "cancelled", "expired"]);
    assert.deepEqual([...TERMINAL_STATES].sort(), ["cancelled", "errored", "expired", "responded"]);
  });

  it("permitted next states are the framework's table", () => {
    assert.deepEqual(PERMITTED_NEXT.received, ["validated", "errored", "expired"]);
    assert.deepEqual(PERMITTED_NEXT.validated, ["accepted", "errored", "expired"]);
    assert.deepEqual(PERMITTED_NEXT.accepted, ["executing", "suspended", "cancelled", "errored"]);
    assert.deepEqual(PERMITTED_NEXT.executing, ["responded", "errored", "cancelled", "suspended"]);
    assert.deepEqual(PERMITTED_NEXT.suspended, ["executing", "cancelled", "expired"]);
  });

  it("LIF-001: a terminal state stays terminal, whatever arrives", () => {
    for (const from of TERMINAL_STATES) {
      assert.ok(isTerminal(from));
      for (const to of LIFECYCLE_STATES) {
        assert.equal(canTransition(from, to), false, `${from}->${to}`);
        assert.throws(() => transition(from, to), LifecycleError);
      }
    }
  });

  it("no state is reachable that the table does not allow; every permitted move is accepted", () => {
    for (const from of LIFECYCLE_STATES) {
      for (const to of LIFECYCLE_STATES) {
        if (PERMITTED_NEXT[from].includes(to)) assert.equal(transition(from, to), to);
        else assert.throws(() => transition(from, to), LifecycleError, `${from}->${to}`);
      }
    }
  });

  it("LIF-002: a refusal before acceptance never passes through accepted", () => {
    // validated -> errored is permitted; accepted is reached only by the claim step
    assert.equal(transition("validated", "errored"), "errored");
    assert.equal(canTransition("errored", "accepted"), false);
    assert.equal(canTransition("received", "accepted"), false);
  });

  it("an accepted document that executes to completion: accepted -> executing -> responded", () => {
    let s: LifecycleState = transition("validated", "accepted");
    s = transition(s, "executing");
    assert.equal(transition(s, "responded"), "responded");
  });

  it("an error code reports the state it terminates in", () => {
    assert.equal(stateForErrorCode("expired"), "expired");
    assert.equal(stateForErrorCode("cancelled"), "cancelled");
    for (const c of STANDARD_CODES.filter((c) => c !== "expired" && c !== "cancelled")) assert.equal(stateForErrorCode(c), "errored", c);
    assert.equal(stateForErrorCode("vrc/relationships/issue:notAccepted"), "errored");
    assert.equal(stateForErrorCode("proof_required"), "errored"); // 0.1 spelling normalised
  });
});

describe("every internal status maps to exactly one lifecycle state", () => {
  const valid = new Set<string>(LIFECYCLE_STATES);

  it("trust_tasks.status", () => {
    assert.deepEqual(Object.keys(TRUST_TASK_STATUS_STATE).sort(), [...TRUST_TASK_STATUSES].sort());
    for (const s of TRUST_TASK_STATUSES) assert.ok(valid.has(TRUST_TASK_STATUS_STATE[s]), s);
    assert.deepEqual({ ...TRUST_TASK_STATUS_STATE }, { recorded: "accepted", pending: "accepted", allowed: "executing", denied: "errored", completed: "responded", failed: "errored" });
  });

  it("ceremony and governance-change proposals (the schema's status column and both stores' unions)", () => {
    for (const s of Object.values(PROPOSAL_STATUS_STATE)) assert.ok(valid.has(s));
    const schema = readFileSync(join(coreRoot, "src", "tx", "schema.ts"), "utf8");
    const comment = /status\s+TEXT NOT NULL DEFAULT 'pending',\s*--\s*([a-z| ]+)/.exec(schema);
    assert.ok(comment, "the ceremony_proposals status comment is findable");
    assert.deepEqual(comment![1]!.split("|").map((s) => s.trim()).sort(), Object.keys(PROPOSAL_STATUS_STATE).sort());
    for (const file of ["ceremony-store.ts", "governance-change-store.ts"]) {
      const src = readFileSync(join(coreRoot, "src", "tx", file), "utf8");
      const union = /status: ('pending'[^;]+);/.exec(src);
      assert.ok(union, file);
      const members = [...union![1]!.matchAll(/'([a-z]+)'/g)].map((m) => m[1]!).sort();
      assert.deepEqual(members, Object.keys(PROPOSAL_STATUS_STATE).sort(), file);
    }
  });

  it("the settled readings: held is accepted, deadline lapse is errored (not expired), reset is cancelled, commit is responded", () => {
    assert.equal(PROPOSAL_STATUS_STATE.pending, "accepted");
    assert.equal(PROPOSAL_STATUS_STATE.expired, "errored");
    assert.equal(PROPOSAL_STATUS_STATE.aborted, "cancelled");
    assert.equal(PROPOSAL_STATUS_STATE.crystallized, "responded");
    assert.equal(PROPOSAL_STATUS_STATE.failed, "errored");
  });

  it("two-phase-commit outcomes: responded only on committed; unknown is never guessed", () => {
    assert.deepEqual(Object.keys(TX_OUTCOME_STATE).sort(), [...TX_OUTCOMES].sort());
    assert.equal(TX_OUTCOME_STATE.committed, "responded");
    assert.equal(TX_OUTCOME_STATE.aborted, "errored");
    assert.equal(TX_OUTCOME_STATE.unknown, "accepted");
    assert.equal(TX_OUTCOME_STATE.inFlight, "executing");
    for (const o of TX_OUTCOMES) assert.equal(mayEmitResponse(o), o === "committed", o);
    for (const o of TX_OUTCOMES) assert.equal(mayEmitError(o), o === "aborted", o);
    for (const o of TX_OUTCOMES) assert.ok(!(mayEmitResponse(o) && mayEmitError(o)));
  });
});
