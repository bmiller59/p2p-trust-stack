// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Pinned versions and windows for the Trust Tasks boundary (conformance plan, sections 3.3 and 3.8).
 *
 * Constants live only here. Windows equal the framework defaults the adopted runtime ships; a test
 * asserts the equality, so a library bump that moves a default fails loudly instead of silently
 * changing acceptance behaviour.
 */

/** Exact pin of the registry TypeScript runtime (package.json carries the same string, no range). */
export const TRUST_TASKS_LIBRARY = "@openvtc/trust-tasks";
export const TRUST_TASKS_LIBRARY_VERSION = "0.29.0";

/** Specification pins the boundary targets. */
export const FRAMEWORK_VERSION = "0.6.0";
export const ERROR_SPEC_VERSION = "0.6";
export const HTTPS_BINDING_VERSION = "0.3";
export const TSP_BINDING_VERSION = "0.1";

/** Acceptance window, in milliseconds. Half-open at `expiresAt`. */
export const SKEW_MS = 60_000;
export const MAX_AGE_MS = 5 * 60_000;
export const EXPIRY_HORIZON_MS = 30 * 24 * 60 * 60_000;

export interface AcceptanceWindow {
  readonly skewMs: number;
  readonly maxAgeMs: number;
  readonly expiryHorizonMs: number;
}

export const ACCEPTANCE_WINDOW: AcceptanceWindow = Object.freeze({
  skewMs: SKEW_MS,
  maxAgeMs: MAX_AGE_MS,
  expiryHorizonMs: EXPIRY_HORIZON_MS,
});
