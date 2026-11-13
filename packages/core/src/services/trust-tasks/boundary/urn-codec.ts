// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Boundary-only URN codec for the private task types (conformance plan 2.3).
 *
 * The framework's URN form is `urn:<NID>:<prefix>:spec:<slug-segments>:<MAJOR.MINOR>` with a `/` in
 * the slug written `:`. The internal names (`task:p2pts:<family>:<slug>:<version>`, type-uris.ts) are
 * not valid Type URIs and stay as they are inside the code and the stored data; only the wire form is
 * converted. The wire form is `urn:p2pts:tasks:spec:<family>:<slug>:<version>`; the `tasks` prefix is
 * proposed, not confirmed. The error type is never minted privately.
 */
import { tryParseTypeUri } from './runtime.js';

export const WIRE_NID = 'p2pts';
export const WIRE_PREFIX = 'tasks';
const INTERNAL = /^task:p2pts:([^:#]+):([^:#]+):(\d+\.\d+)(#(?:request|response))?$/;
const SLUG_SEGMENT = /^[a-z][a-z0-9-]*$/;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/** Whether `internal` is a private task name that has a valid wire form. */
export function toWireTypeUri(internal: string): string | undefined {
  const m = INTERNAL.exec(internal);
  if (m === null) return undefined;
  const [, family, slug, version, fragment] = m;
  if (!SLUG_SEGMENT.test(family!) || !SLUG_SEGMENT.test(slug!) || !VERSION.test(version!)) return undefined;
  const wire = `urn:${WIRE_NID}:${WIRE_PREFIX}:spec:${family}:${slug}:${version}${fragment ?? ''}`;
  return tryParseTypeUri(wire) === null ? undefined : wire;
}

/** The internal name for a wire URN produced by {@link toWireTypeUri}, or undefined. */
export function fromWireTypeUri(wire: string): string | undefined {
  const m = new RegExp(`^urn:${WIRE_NID}:${WIRE_PREFIX}:spec:([^:#]+):([^:#]+):(\\d+\\.\\d+)(#(?:request|response))?$`).exec(wire);
  if (m === null) return undefined;
  const internal = `task:${WIRE_NID}:${m[1]}:${m[2]}:${m[3]}${m[4] ?? ''}`;
  return toWireTypeUri(internal) === wire ? internal : undefined;
}
