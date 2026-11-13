// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ACCEPTANCE_WINDOW } from "../../../../src/services/trust-tasks/boundary/pins.ts";
import {
  CONSEQUENTIAL_FRESHNESS,
  DEFAULT_FRESHNESS,
  recordExpiry,
  validateBasic,
  validateFreshness,
} from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import type { FreshnessPolicy, TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { CARRIER_TYPE, fixture } from "./helpers.ts";

interface Row {
  name: string;
  policy: string;
  now: string;
  issuedAt?: string;
  expiresAt?: string;
  verdict: "accept" | "expired" | "malformedRequest";
  recordExpiry?: string | null;
}
interface Freshness {
  policies: Record<string, FreshnessPolicy>;
  cases: Row[];
}
const fx = fixture<Freshness>("consume/freshness.json");

describe("TIME freshness (fixtures/consume/freshness.json) through the adopted runtime", () => {
  it("the fixture's default and consequential policies equal the runtime constants and our pins", () => {
    // The fixture spells requireIssuedAt out; the runtime leaves it unset for "false".
    const norm = (p: FreshnessPolicy | undefined): object => ({ ...p, requireIssuedAt: p?.requireIssuedAt ?? false });
    assert.deepEqual(norm(DEFAULT_FRESHNESS), norm(fx.policies["default"]));
    assert.deepEqual(norm(CONSEQUENTIAL_FRESHNESS), norm(fx.policies["consequential"]));
    assert.equal(CONSEQUENTIAL_FRESHNESS.skewMs, ACCEPTANCE_WINDOW.skewMs);
    assert.equal(CONSEQUENTIAL_FRESHNESS.maxAgeMs, ACCEPTANCE_WINDOW.maxAgeMs);
    assert.equal(CONSEQUENTIAL_FRESHNESS.expiryHorizonMs, ACCEPTANCE_WINDOW.expiryHorizonMs);
  });

  for (const row of fx.cases) {
    it(`${row.name} -> ${row.verdict}`, () => {
      const policy = fx.policies[row.policy];
      assert.ok(policy, `policy ${row.policy}`);
      const now = Date.parse(row.now);
      const doc = {
        id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000bb",
        type: CARRIER_TYPE,
        ...(row.issuedAt === undefined ? {} : { issuedAt: row.issuedAt }),
        ...(row.expiresAt === undefined ? {} : { expiresAt: row.expiresAt }),
        payload: {},
      } as TrustTaskDocument<unknown>;
      // Item 4: expiry first (no recipient), then the freshness bound.
      const refusal = validateBasic(doc, now, "did:web:consumer.example") ?? validateFreshness(doc, now, policy);
      if (row.verdict === "accept") {
        assert.equal(refusal, null);
        const expiry = recordExpiry(doc, policy, now);
        if (row.recordExpiry === null || row.recordExpiry === undefined) assert.equal(expiry, undefined);
        else assert.equal(expiry, Date.parse(row.recordExpiry));
      } else {
        assert.equal(refusal?.code, row.verdict);
      }
    });
  }
});
