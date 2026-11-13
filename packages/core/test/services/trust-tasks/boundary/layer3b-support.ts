// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { simplePayloadValidator } from "../../../../src/services/trust-tasks/boundary/payload-validator.ts";

export {
  DISCOVERY_PAYLOAD_SCHEMA,
  DISCOVERY_RESPONSE_TYPE_URI,
  NEXT_STEP_PAYLOAD_SCHEMA,
  NEXT_STEP_TYPE_URI,
} from "../../../../src/services/trust-tasks/boundary/runtime.ts";

/** Errors the boundary's own small schema reader finds, empty when the payload conforms. */
export function simpleSchemaCheck(schema: unknown, payload: unknown): string[] {
  const r = simplePayloadValidator.validate(schema, payload);
  return typeof r === "boolean" ? (r ? [] : ["invalid"]) : [...(r.errors ?? [])];
}
