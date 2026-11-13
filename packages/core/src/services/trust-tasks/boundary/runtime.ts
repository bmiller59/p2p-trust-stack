// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The single import site for the registry TypeScript runtime (`@openvtc/trust-tasks`, pinned in
 * package.json; see `pins.ts`). Nothing else under `src/` imports the library, so replacing it
 * with a vendored copy is a one-file change. Re-exports only what the boundary uses.
 */
export {
  CONSEQUENTIAL_FRESHNESS,
  STANDARD_CODES,
  TRUST_TASK_ERROR_TYPE_URI,
  DEFAULT_FRESHNESS,
  InMemoryReplayGuard,
  StaticTransport,
  UnauthenticatedTransport,
  canonicalJson,
  consequentialChecks,
  consumeInbound,
  documentDigest,
  isStandardCode,
  issuedAtNow,
  normalizeCode,
  notConsequentialChecks,
  recordExpiry,
  rejectWith,
  rejectWithRecipient,
  sameSpecification,
  toErrorPayload,
  tryParseTypeUri,
  validateBasic,
  validateFreshness,
} from "@openvtc/trust-tasks/runtime";
export type {
  ConsumeChecks,
  ConsumeOptions,
  ConsumeOutcome,
  ErrorResponse,
  FreshnessPolicy,
  PayloadPolicy,
  PayloadValidator,
  ProofPolicy,
  RejectReason,
  ReplayGuard,
  ReplayVerdict,
  SpecPolicy,
  StandardCode,
  TransportHandler,
  TrustTaskDocument,
} from "@openvtc/trust-tasks/runtime";
export { SPEC as VRC_PROPOSE_SPEC } from "@openvtc/trust-tasks/vrc/relationships/propose/0.1/payload";
export { SPEC as VRC_ISSUE_SPEC } from "@openvtc/trust-tasks/vrc/relationships/issue/0.1/payload";

import type { TrustTaskDocument } from "@openvtc/trust-tasks/runtime";

/**
 * Choose the `myVid` the library's `consumeInbound` is given. The library takes a single recipient
 * identifier, so a listener that serves several (hosted communities) picks it here: the document's
 * own `recipient` when it is one of the served identifiers, otherwise the default identifier, so a
 * document addressed to anyone else gets `wrongRecipient` from the library rather than slipping
 * through. A document with no `recipient` also gets the default identifier.
 */
export function selectMyVid(
  doc: Pick<TrustTaskDocument<unknown>, "recipient">,
  served: ReadonlySet<string> | readonly string[],
  defaultVid: string,
): string {
  const set = served instanceof Set ? served : new Set(served);
  const r = doc.recipient;
  return typeof r === "string" && set.has(r) ? r : defaultVid;
}
