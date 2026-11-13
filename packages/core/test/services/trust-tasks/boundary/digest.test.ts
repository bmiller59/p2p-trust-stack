// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BoundaryAdapter } from "./conformance/adapter.ts";
import type { BoundaryHandler } from "./conformance/adapter.ts";
import { VRC_PROPOSE_SPEC } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import type { SpecPolicy, TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { CARRIER_TYPE, fixture } from "./helpers.ts";

interface Case {
  name: string;
  first?: string;
  second: string;
  secondAt?: string;
  expect: "duplicate" | "idConflict" | "expired";
}
interface Item11 {
  consumer: string;
  now: string;
  first: string;
  cases: Case[];
}
const fx = fixture<Item11>("consume/item11-digest.json");

// A consequential widget task that models only payload.subject (the fixture's stated payload type).
const widgetSpec: SpecPolicy = {
  typeUri: CARRIER_TYPE,
  isBearer: false,
  isProofRequired: false,
  isRecipientRequired: true,
  isIssuedAtRequired: true,
};
const widget: BoundaryHandler = {
  spec: widgetSpec,
  handle: (doc) =>
    ({
      id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000cc",
      threadId: doc.id,
      type: `${CARRIER_TYPE}#response`,
      issuer: fx.consumer,
      recipient: doc.issuer,
      issuedAt: "2026-11-01T00:00:30Z",
      payload: { applied: true },
    }) as TrustTaskDocument<unknown>,
};

describe("DUP item-11 digest vectors (fixtures/consume/item11-digest.json) through the adopted runtime", () => {
  for (const c of fx.cases) {
    it(`${c.name} -> ${c.expect}`, async () => {
      const adapter = new BoundaryAdapter({ servedVids: [fx.consumer], handlers: [widget] });
      await adapter.setClock(fx.now);
      const first = await adapter.send({ from: { kind: "none" }, bytes: c.first ?? fx.first });
      assert.equal(first.replies.length, 1, "first document is handled");
      assert.equal((JSON.parse(first.replies[0]!) as { type: string }).type, `${CARRIER_TYPE}#response`);

      if (c.secondAt !== undefined) await adapter.setClock(c.secondAt);
      const second = await adapter.send({ from: { kind: "none" }, bytes: c.second });
      assert.equal(second.replies.length, 1);
      const reply = JSON.parse(second.replies[0]!) as { type: string; payload: { code?: string } };
      if (c.expect === "duplicate") {
        // The prior response is returned and the handler ran once.
        assert.equal(reply.type, `${CARRIER_TYPE}#response`);
        assert.equal((await adapter.observe({ query: "handled" })).value, 1);
      } else {
        assert.ok(reply.type.includes("/trust-task-error/"));
        assert.equal(reply.payload.code, c.expect);
      }
    });
  }

  it("the generated vrc/relationships propose and issue policies have the shape the plan relies on", () => {
    assert.equal(VRC_PROPOSE_SPEC.isProofRequired, false);
    assert.equal(VRC_PROPOSE_SPEC.isRecipientRequired, true);
    assert.equal(VRC_PROPOSE_SPEC.isIssuedAtRequired, false);
  });
});
