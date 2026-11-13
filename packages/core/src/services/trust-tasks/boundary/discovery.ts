// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The `trust-task-discovery` 0.4 responder and the `trust-task-control` refusal (conformance plan
 * P4b, layer 3b).
 *
 * Discovery is registry-driven: the answer is computed from the handler registry at request time, so
 * it lists exactly the types the boundary serves and cannot drift from them. Only valid Type URIs
 * are listed (the internal `task:p2pts:...` compatibility names are not Type URIs and are served for
 * one release without being advertised; their wire URNs are listed), bare (no fragment), without
 * duplicates, sorted. Patterns are slug globs: `*`, `<prefix>/*` (a slug that starts with
 * `<prefix>/`), or an exact slug; anything else matches literally. No patterns means `*`.
 *
 * The `acceptanceWindow` is the pinned window (`pins.ts`), stated in whole seconds and never wider
 * than what the pipeline enforces. It carries `expiryHorizonSeconds` because the pipeline honours a
 * stated `expiresAt` up to the horizon. It is a description of current policy, not a promise.
 *
 * `trust-task-control` is optional (framework 11.8: support is optional, `unsupportedType` is the
 * conformant refusal). It has no handler, so the pipeline refuses it as `unsupportedType`; this
 * module only names the type so tests and discovery can assert it is never advertised.
 */
import { TaskError } from './errors.js';
import { HandlerRegistry } from './handlers.js';
import type { HandlerContext, PipelineHandler } from './handlers.js';
import { ACCEPTANCE_WINDOW, FRAMEWORK_VERSION } from './pins.js';
import type { AcceptanceWindow } from './pins.js';
import { CONTROL_TYPE_URI, DISCOVERY_PAYLOAD_SCHEMA, DISCOVERY_RESPONSE_TYPE_URI, DISCOVERY_TYPE_URI, issuedAtNow, tryParseTypeUri } from './runtime.js';
import type { TrustTaskDocument } from './runtime.js';

export { CONTROL_TYPE_URI, DISCOVERY_TYPE_URI };

/** The request payload bound (the specification's parser hardening). */
export const MAX_PATTERNS = 16;

export interface DiscoveryAcceptanceWindow {
  maxAgeSeconds: number;
  clockSkewSeconds: number;
  expiryHorizonSeconds: number;
}

export interface DiscoveryResponsePayload {
  supportedTypes: string[];
  frameworkVersion: string;
  acceptanceWindow: DiscoveryAcceptanceWindow;
}

export function windowSeconds(w: AcceptanceWindow = ACCEPTANCE_WINDOW): DiscoveryAcceptanceWindow {
  return { maxAgeSeconds: w.maxAgeMs / 1000, clockSkewSeconds: w.skewMs / 1000, expiryHorizonSeconds: w.expiryHorizonMs / 1000 };
}

/** Whether `slug` matches one slug-glob pattern. */
export function slugMatches(pattern: string, slug: string): boolean {
  if (pattern === '*') return true;
  if (pattern.length > 2 && pattern.endsWith('/*') && !pattern.slice(0, -2).includes('*')) return slug.startsWith(pattern.slice(0, -1));
  return pattern === slug;
}

/** The types the registry serves that discovery advertises: valid, bare, unique, sorted. */
export function advertisedTypes(registry: HandlerRegistry): { type: string; slug: string }[] {
  const out = new Map<string, string>();
  for (const t of registry.types()) {
    const parsed = tryParseTypeUri(t);
    if (parsed === null || parsed.variant !== null) continue;
    out.set(t, parsed.slug);
  }
  return [...out.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([type, slug]) => ({ type, slug }));
}

export function discover(registry: HandlerRegistry, patterns: readonly string[] | undefined): DiscoveryResponsePayload {
  const want = patterns === undefined || patterns.length === 0 ? ['*'] : patterns;
  const supportedTypes = advertisedTypes(registry)
    .filter(({ slug }) => want.some((p) => slugMatches(p, slug)))
    .map(({ type }) => type);
  return { supportedTypes, frameworkVersion: FRAMEWORK_VERSION, acceptanceWindow: windowSeconds() };
}

/**
 * The discovery handler. Pass the registry it describes (it is read at request time, so handlers
 * registered later, including the discovery handler itself, are listed). Register it in that same
 * registry, or use {@link registerDiscovery}.
 */
export function createDiscoveryHandler(registry: HandlerRegistry): PipelineHandler {
  return {
    types: [DISCOVERY_TYPE_URI],
    spec: {
      typeUri: DISCOVERY_TYPE_URI,
      isBearer: false,
      isProofRequired: false, // RECOMMENDED; the attested profile requires it for every request
      isRecipientRequired: true,
      isIssuedAtRequired: false,
      payloadSchema: DISCOVERY_PAYLOAD_SCHEMA,
    },
    consequential: false,
    handle(doc: TrustTaskDocument<unknown>, ctx: HandlerContext) {
      const p = (doc.payload ?? {}) as { patterns?: unknown };
      let patterns: string[] | undefined;
      if (p.patterns !== undefined) {
        if (!Array.isArray(p.patterns) || p.patterns.length > MAX_PATTERNS || p.patterns.some((x) => typeof x !== 'string' || x === '')) {
          throw new TaskError({ code: 'malformedRequest', internalMessage: 'patterns must be at most 16 non-empty strings' });
        }
        patterns = p.patterns as string[];
      }
      return {
        id: ctx.newId(),
        type: DISCOVERY_RESPONSE_TYPE_URI,
        threadId: typeof doc.threadId === 'string' && doc.threadId !== '' ? doc.threadId : doc.id,
        ...(typeof doc.parentThreadId === 'string' && doc.parentThreadId !== '' ? { parentThreadId: doc.parentThreadId } : {}),
        issuer: ctx.myVid ?? doc.recipient,
        recipient: doc.issuer,
        issuedAt: ctx.clock?.() ?? issuedAtNow(),
        payload: discover(registry, patterns),
      } as unknown as TrustTaskDocument<unknown>;
    },
  };
}

/** Register the discovery handler in `registry` (idempotent). */
export function registerDiscovery(registry: HandlerRegistry): HandlerRegistry {
  if (registry.find(DISCOVERY_TYPE_URI) === undefined) registry.register(createDiscoveryHandler(registry));
  return registry;
}
