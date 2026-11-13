// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The handler registry (conformance plan P2): which wire types the boundary serves and who answers
 * them. A handler owns business logic only; the pipeline owns parsing, validation, freshness,
 * recipient and sender checks, the duplicate record and every error on the wire.
 */
import { sameSpecification, tryParseTypeUri } from './runtime.js';
import type { ErrorResponse, SpecPolicy, TrustTaskDocument } from './runtime.js';

export interface HandlerContext {
  /** The in-band parties after the transport cross-check. */
  readonly parties: { readonly issuer?: string; readonly recipient?: string };
  /** The transport-authenticated sender, when the carrier has one. */
  readonly sender: string | undefined;
  /** The identifier the pipeline is answering as for this document. */
  readonly myVid: string | undefined;
  /** The pipeline's one clock, as epoch milliseconds and as a whole-second timestamp. */
  readonly now: number;
  readonly clock: () => string;
  readonly newId: () => string;
}

export type HandlerResult = TrustTaskDocument<unknown> | ErrorResponse | void;

export interface PipelineHandler {
  /** Every exact wire type this handler answers (the current form first, then compatibility forms). */
  readonly types: readonly string[];
  /** Specification policy; the pipeline substitutes the received type for `typeUri`. */
  readonly spec: SpecPolicy;
  /** Consequential tasks get the duplicate record and the strict windows; others are repeat-safe. */
  readonly consequential: boolean;
  /**
   * Business logic. Throw a `TaskError` for a typed refusal; anything else reaches the wire as an
   * opaque `internalError`. Return the response document, or nothing for a fire-and-forget task.
   */
  handle(doc: TrustTaskDocument<unknown>, ctx: HandlerContext): Promise<HandlerResult> | HandlerResult;
}

export class HandlerRegistry {
  private readonly byType = new Map<string, PipelineHandler>();

  constructor(handlers: readonly PipelineHandler[] = []) {
    for (const h of handlers) this.register(h);
  }

  register(handler: PipelineHandler): void {
    if (handler.types.length === 0) throw new Error('a handler must serve at least one type');
    for (const t of handler.types) {
      if (this.byType.has(t)) throw new Error(`type already served: ${t}`);
    }
    for (const t of handler.types) this.byType.set(t, handler);
  }

  /** The handler for exactly this wire type. */
  find(type: string): PipelineHandler | undefined {
    return this.byType.get(type);
  }

  /** Every wire type served. */
  types(): string[] {
    return [...this.byType.keys()];
  }

  /**
   * A handler for the same specification at another version (so the caller can answer
   * `unsupportedVersion` rather than `unsupportedType`), with the versions served.
   */
  sameSpecification(type: string): { handler: PipelineHandler; servedVersions: string[] } | undefined {
    const got = tryParseTypeUri(type.replace(/#(request|response)$/, ''));
    if (got === null) return undefined;
    let first: PipelineHandler | undefined;
    const versions = new Set<string>();
    for (const [t, h] of this.byType) {
      const want = tryParseTypeUri(t);
      if (want === null || !sameSpecification(got, want)) continue;
      first ??= h;
      versions.add(`${want.major}.${want.minor}`);
    }
    return first === undefined ? undefined : { handler: first, servedVersions: [...versions].sort() };
  }
}
