// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * AUTHZ-001 / decision C5: `policy/evaluate` takes its actor from the VERIFIED sender only. Without
 * one the answer is `permissionDenied`, before anything about the community is looked at.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createLegacyEvaluateHandler, POLICY_EVALUATE_WIRE_TYPE } from "../../../../src/services/trust-tasks/boundary/legacy-evaluate.ts";
import { TaskError } from "../../../../src/services/trust-tasks/boundary/errors.ts";
import type { DataSource } from "../../../../src/db/data-source.ts";
import type { HandlerContext } from "../../../../src/services/trust-tasks/boundary/handlers.ts";
import type { TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";

const doc = {
  id: "urn:uuid:11111111-1111-4111-8111-111111111111",
  type: POLICY_EVALUATE_WIRE_TYPE + "#request",
  issuer: "did:example:claimed-admin",
  recipient: "did:example:community",
  payload: { action: "issue_credential" },
} as unknown as TrustTaskDocument<unknown>;

const ctxOf = (over: Partial<HandlerContext>): HandlerContext => ({
  parties: { issuer: "did:example:claimed-admin", recipient: "did:example:community" },
  sender: undefined, myVid: undefined, now: 0, clock: () => "2026-01-01T00:00:00Z", newId: () => "urn:uuid:x", ...over,
});

// A db that fails the test if it is touched: the refusal must come before any lookup.
const untouchable = new Proxy({}, { get() { throw new Error("db touched before the sender check"); } }) as unknown as DataSource;

describe("evaluate actor (AUTHZ-001)", () => {
  it("no sender and no verified signer: permissionDenied, nothing looked up, in-band issuer ignored", async () => {
    const h = createLegacyEvaluateHandler(untouchable);
    await assert.rejects(
      async () => h.handle(doc, ctxOf({})),
      (e: unknown) => e instanceof TaskError && e.code === "permissionDenied" && e.retryable === false,
    );
  });

  it("an empty sender string is not a sender", async () => {
    const h = createLegacyEvaluateHandler(untouchable);
    await assert.rejects(async () => h.handle(doc, ctxOf({ sender: "" })), (e: unknown) => e instanceof TaskError && e.code === "permissionDenied");
  });

  it("a sender (or a verified signer) passes the actor check and reaches the community lookup", async () => {
    const lookups: string[] = [];
    const db = { get: async (_sql: string, ...args: unknown[]) => { lookups.push(String(args[0])); return undefined; }, all: async () => [] } as unknown as DataSource;
    const h = createLegacyEvaluateHandler(db);
    for (const over of [{ sender: "did:example:alice" }, { verifiedSigner: "did:example:bob" }]) {
      await assert.rejects(async () => h.handle(doc, ctxOf(over)), (e: unknown) => e instanceof TaskError && e.code === "wrongRecipient");
    }
    assert.equal(lookups.length, 2);
  });
});
