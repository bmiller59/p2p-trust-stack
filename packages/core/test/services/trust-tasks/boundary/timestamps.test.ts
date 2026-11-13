// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseDateTimeStamp } from "../../../../src/services/trust-tasks/boundary/datetime.ts";
import { DEFAULT_FRESHNESS, validateFreshness } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import type { TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { CARRIER_TYPE, fixture } from "./helpers.ts";

interface Timestamps {
  valid: { value: string; epochMs: number; why: string }[];
  invalid: { value: string; why: string }[];
}
const ts = fixture<Timestamps>("consume/timestamps.json");

const docWith = (issuedAt: string): TrustTaskDocument<unknown> =>
  ({ id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000aa", type: CARRIER_TYPE, issuedAt, payload: {} }) as TrustTaskDocument<unknown>;

describe("TIME timestamps (fixtures/consume/timestamps.json)", () => {
  for (const v of ts.valid) {
    it(`valid ${v.value}: copied parser and adopted runtime both read instant ${v.epochMs}`, () => {
      assert.equal(parseDateTimeStamp(v.value), v.epochMs, "copied parseDateTimeStamp");
      // The adopted runtime: reading issuedAt at exactly that instant is inside the window.
      assert.equal(validateFreshness(docWith(v.value), v.epochMs, DEFAULT_FRESHNESS), null);
      // One hour earlier it is beyond the skew tolerance (future), proving the instant was actually read.
      const early = validateFreshness(docWith(v.value), v.epochMs - 3_600_000, DEFAULT_FRESHNESS);
      assert.equal(early?.code, "malformedRequest");
    });
  }
  for (const v of ts.invalid) {
    it(`invalid ${v.value} (${v.why}): copied parser and adopted runtime both refuse`, () => {
      assert.equal(parseDateTimeStamp(v.value), undefined, "copied parseDateTimeStamp");
      const r = validateFreshness(docWith(v.value), Date.UTC(2026, 0, 1), DEFAULT_FRESHNESS);
      assert.equal(r?.code, "malformedRequest");
    });
  }
});
