// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The `trust-task-next-step` builder (conformance plan P4b; framework 8.6, "a hold is a next step").
 *
 * A task that was understood but cannot complete yet (a human still decides, approvers are still
 * needed) is answered with this document, never with an error and never with silence. Where the
 * consumer offers no status task the payload uses `continuation: resubmit` and `expects` names the
 * originating Type URI; the requester then re-issues the request as a new document (fresh `id`, same
 * thread). The builder emits a fresh document with the request's thread, the reply addressing of the
 * error builder, and a closed payload (`expects`, `continuation`, `inResponseTo`, `message`, `ext`).
 * It signs nothing: the pipeline signs every reply it sends, this one included, at Tier 2.
 *
 * Handlers that hold (the ceremony documents of P8, `propose` of P6) call this; nothing is wired to
 * it yet in this phase.
 */
import { randomUUID } from 'node:crypto';
import { issuedAtNow, NEXT_STEP_TYPE_URI } from './runtime.js';
import type { ErrorRequestRef } from './errors.js';

export type NextStepContinuation = 'resubmit' | 'proceed';

export interface NextStepExpectation {
  /** The Type URI the recipient expects next, including any `#request` fragment. */
  typeUri: string;
  /** Why this continuation is expected. Non-normative; keep it free of anything the addressee may not learn. */
  reason?: string;
  /** Structured data the producer may use when composing the expected document. */
  hint?: Record<string, unknown>;
}

export interface NextStepInput {
  /** The continuations accepted: ALTERNATIVES, at least one. */
  expects: readonly NextStepExpectation[];
  /** Default `resubmit` (the specification's default, always stated explicitly on the wire). */
  continuation?: NextStepContinuation;
  message?: string;
  ext?: Record<string, unknown>;
}

export interface NextStepPayload {
  expects: NextStepExpectation[];
  continuation: NextStepContinuation;
  inResponseTo?: { typeUri: string; id?: string };
  message?: string;
  ext?: Record<string, unknown>;
}

export interface NextStepDocument {
  id: string;
  type: typeof NEXT_STEP_TYPE_URI;
  threadId: string;
  parentThreadId?: string;
  issuer?: string;
  recipient?: string;
  issuedAt: string;
  payload: NextStepPayload;
  proof?: unknown;
}

export interface NextStepBuildOptions {
  newId?: () => string;
  /** The one clock, whole-second timestamp. */
  now?: () => string;
  /** The identifier answered as. Default: the request's `recipient`. */
  issuer?: string;
  /** Default: the request's `issuer`. */
  recipient?: string;
}

const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);
const MESSAGE_MAX = 512;

/**
 * Build the next-step answering `request`. Throws `TypeError` for a programming error (no
 * expectation, an expectation without a Type URI, an unknown continuation); a next-step never
 * carries more than the closed payload above.
 */
export function buildNextStep(request: ErrorRequestRef, input: NextStepInput, options: NextStepBuildOptions = {}): NextStepDocument {
  if (!Array.isArray(input.expects) || input.expects.length === 0) throw new TypeError('a next-step needs at least one expectation');
  const expects: NextStepExpectation[] = input.expects.map((e) => {
    const typeUri = str(e.typeUri);
    if (typeUri === undefined) throw new TypeError('every expectation names a typeUri');
    return {
      typeUri,
      ...(str(e.reason) === undefined ? {} : { reason: e.reason! }),
      ...(e.hint === undefined ? {} : { hint: e.hint }),
    };
  });
  const continuation = input.continuation ?? 'resubmit';
  if (continuation !== 'resubmit' && continuation !== 'proceed') throw new TypeError(`unknown continuation: ${String(continuation)}`);

  const id = (options.newId ?? randomUUID)();
  const reqId = str(request.id);
  const reqType = str(request.type);
  const payload: NextStepPayload = { expects, continuation };
  if (reqType !== undefined) payload.inResponseTo = reqId === undefined ? { typeUri: reqType } : { typeUri: reqType, id: reqId };
  if (str(input.message) !== undefined) payload.message = input.message!.slice(0, MESSAGE_MAX);
  if (input.ext !== undefined) payload.ext = input.ext;

  const doc: NextStepDocument = {
    id,
    type: NEXT_STEP_TYPE_URI,
    threadId: str(request.threadId) ?? reqId ?? id,
    issuedAt: (options.now ?? issuedAtNow)(),
    payload,
  };
  const parent = str(request.parentThreadId);
  if (parent !== undefined) doc.parentThreadId = parent;
  const issuer = str(options.issuer) ?? str(request.recipient);
  if (issuer !== undefined) doc.issuer = issuer;
  const recipient = str(options.recipient) ?? str(request.issuer);
  if (recipient !== undefined) doc.recipient = recipient;
  return doc;
}

/** Whether a document is a next-step (any fragment). */
export function isNextStep(doc: { type?: unknown } | undefined): boolean {
  return typeof doc?.type === 'string' && doc.type.replace(/#(request|response)$/, '') === NEXT_STEP_TYPE_URI;
}
