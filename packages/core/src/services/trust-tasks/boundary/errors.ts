// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Typed error model for the Trust Task boundary (conformance plan, sections 3.6 and 3.9; framework
 * section 8).
 *
 * Pure and transport-agnostic. It owns four things:
 *
 *   1. the error DOCUMENT (`trust-task-error`, pinned to `ERROR_SPEC_VERSION`) with its payload
 *      `{code, retryable, inResponseTo, message, details?, retryAfter?}`, built from any request
 *      reference or none;
 *   2. the closed vocabularies: standard and extended codes, the `details.reason` set, and the
 *      fixed wire messages (a message is looked up from the code and reason, never taken from the
 *      caller, so no internal fact or contested value can reach the wire, framework 8.2.1);
 *   3. the status function of the HTTPS binding 0.3 (section 4), with one catch-all: anything that is
 *      not a typed error becomes an opaque `internalError`;
 *   4. the map from the legacy codes the bridge used before this phase.
 *
 * Signing (Tier 2) is not done here; the signer wraps the document this module builds (phase P4).
 */
import { randomUUID } from 'node:crypto';
import { TRUST_TASK_ERROR_TYPE } from '../type-uris.js';
import { parseDateTimeStamp } from './datetime.js';
import {
  STANDARD_CODES,
  TRUST_TASK_ERROR_TYPE_URI,
  canonicalJson,
  isStandardCode,
  issuedAtNow,
  normalizeCode,
} from './runtime.js';
import type { StandardCode } from './runtime.js';

export type { StandardCode };

// ─────────────────────────────────────────────────────────────────────────────
// Codes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extended code grammar (framework 8.5; the `trust-task-error` 0.6 payload schema pattern):
 * `<slug>:<local>`, the slug lowercase path segments, the local part lowerCamelCase-ish.
 */
const EXTENDED_CODE = /^[a-z][a-z0-9]*(-[a-z0-9]+)*(\/[a-z][a-z0-9]*(-[a-z0-9]+)*)*:[a-z][a-zA-Z0-9_]*$/;

export function isExtendedCode(code: string): boolean {
  return EXTENDED_CODE.test(code);
}

/** A code that may appear on the wire: a standard code (canonical spelling) or a well-formed extended one. */
export function isWireCode(code: unknown): code is string {
  return typeof code === 'string' && ((STANDARD_CODES as readonly string[]).includes(code) || isExtendedCode(code));
}

/**
 * Default `retryable` per code (framework 8.3). `taskFailed` is "varies"; false unless the
 * emitter knows better. An extended code is treated as `taskFailed` by a receiver that does not
 * recognise it (8.5), so it defaults the same way.
 */
export const DEFAULT_RETRYABLE: Readonly<Record<StandardCode, boolean>> = Object.freeze({
  malformedRequest: false,
  unsupportedType: false,
  unsupportedVersion: false,
  unsupportedExtension: false,
  expired: false,
  proofRequired: false,
  proofInvalid: false,
  permissionDenied: false,
  wrongRecipient: false,
  identityMismatch: false,
  idConflict: false,
  cancelled: false,
  taskFailed: false,
  unavailable: true,
  indeterminate: true,
  internalError: true,
});

export function defaultRetryable(code: string): boolean {
  return isStandardCode(code) ? DEFAULT_RETRYABLE[normalizeCode(code) as StandardCode] : false;
}

/** HTTPS binding 0.3, section 4: the status for a document carrying this code. Informative; the code is authoritative. */
export const HTTP_STATUS_BY_CODE: Readonly<Record<StandardCode, number>> = Object.freeze({
  malformedRequest: 400,
  permissionDenied: 403,
  idConflict: 409,
  internalError: 500,
  unavailable: 503,
  indeterminate: 503,
  unsupportedType: 422,
  unsupportedVersion: 422,
  expired: 422,
  proofRequired: 422,
  proofInvalid: 422,
  identityMismatch: 422,
  wrongRecipient: 422,
  cancelled: 422,
  taskFailed: 422,
  unsupportedExtension: 422,
});

/** Statuses for the non-error dispositions of the binding (section 4). */
export const HTTP_STATUS_OK = 200;
/** A duplicate of a document whose first execution is still in progress. Not `accepted`. */
export const HTTP_STATUS_DUPLICATE_IN_FLIGHT = 202;
/** A document that is answered with nothing: a duplicate with no retained response, or an inbound error. */
export const HTTP_STATUS_NO_CONTENT = 204;

/**
 * The single status function. A standard code maps through the table; an extended code is the
 * `taskFailed` bucket (422); a value that is no code at all is a server fault (500).
 */
export function httpStatusForCode(code: string): number {
  if (typeof code !== 'string') return 500;
  const normal = normalizeCode(code);
  if (isStandardCode(normal)) return HTTP_STATUS_BY_CODE[normal as StandardCode];
  return isExtendedCode(code) ? HTTP_STATUS_BY_CODE.taskFailed : 500;
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire messages (fixed vocabulary)
// ─────────────────────────────────────────────────────────────────────────────

/** Derived from the framework's public meaning of each code (8.3), nothing else. */
const CODE_MESSAGES: Readonly<Record<StandardCode, string>> = Object.freeze({
  malformedRequest: 'The document is not valid.',
  unsupportedType: 'The task type is not supported.',
  unsupportedVersion: 'The task version is not supported.',
  unsupportedExtension: 'A required extension is not supported.',
  expired: 'The document has expired.',
  proofRequired: 'A proof is required.',
  proofInvalid: 'The proof is not valid.',
  permissionDenied: 'The request is not permitted.',
  wrongRecipient: 'The document is not addressed to this recipient.',
  identityMismatch: 'The identity in the document does not match the sender.',
  idConflict: 'The document id was already used for different content.',
  cancelled: 'The task was stopped.',
  taskFailed: 'The task could not be completed.',
  unavailable: 'The service is temporarily unavailable.',
  indeterminate: 'A determination could not be made.',
  internalError: 'An internal error occurred.',
});

// ─────────────────────────────────────────────────────────────────────────────
// Closed `details.reason` vocabulary (plan section 3.9)
// ─────────────────────────────────────────────────────────────────────────────

export interface ReasonSpec {
  /** The standard code the reason is reported under. */
  readonly code: StandardCode;
  readonly retryable: boolean;
  readonly message: string;
}

/**
 * The closed set. A reason outside it is a programming error and is reported as an opaque
 * `internalError` rather than leaked. `notFoundOrNotPermitted` is what an approver who is
 * ineligible receives, so "no such ceremony" and "not yours" are indistinguishable on the wire.
 */
export const REASONS = Object.freeze({
  policyDenied: { code: 'permissionDenied', retryable: false, message: 'The request was refused by policy.' },
  notAdmin: { code: 'permissionDenied', retryable: false, message: 'The requester is not an administrator.' },
  notFoundOrNotPermitted: { code: 'permissionDenied', retryable: false, message: 'Not found or not permitted.' },
  nameTaken: { code: 'taskFailed', retryable: false, message: 'The name is not available.' },
  deadlineLapsed: { code: 'taskFailed', retryable: false, message: 'The ceremony deadline has passed.' },
  alreadyCommitted: { code: 'taskFailed', retryable: false, message: 'The ceremony has already been committed.' },
  notAccepted: { code: 'taskFailed', retryable: false, message: 'No accepted proposal exists.' },
  vcInvalid: { code: 'taskFailed', retryable: false, message: 'The credential is not valid.' },
  outcomeEvidenceInvalid: { code: 'taskFailed', retryable: false, message: 'The outcome evidence is not valid.' },
  notFound: { code: 'taskFailed', retryable: false, message: 'The requested item was not found.' },
  storeFailed: { code: 'unavailable', retryable: true, message: 'The record could not be stored.' },
} as const satisfies Record<string, ReasonSpec>);

export type Reason = keyof typeof REASONS;

export const REASON_VOCABULARY: readonly Reason[] = Object.freeze(Object.keys(REASONS) as Reason[]);

export function isReason(value: unknown): value is Reason {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(REASONS, value);
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed error (what handlers and participants throw)
// ─────────────────────────────────────────────────────────────────────────────

export interface TaskErrorInit {
  /** Standard or extended code. Default: the reason's code, else `taskFailed`. */
  code?: string;
  /** Closed vocabulary; reported as `details.reason`. */
  reason?: Reason;
  /** Default: the reason's, else the code's default (framework 8.3). */
  retryable?: boolean;
  /** RFC 3339; reported only when `retryable` is true. */
  retryAfter?: string;
  /** Extra task-specific members, bounded on emission (framework 8.2.2). Never free text from the requester. */
  details?: Record<string, unknown>;
  /** Internal description for logs only. Never put on the wire. */
  internalMessage?: string;
  cause?: unknown;
}

/**
 * A refusal or failure with a defined wire form. Throw this from a handler; anything else that is
 * thrown reaches the wire as an opaque `internalError` (the catch-all in `toWireError`).
 */
export class TaskError extends Error {
  readonly code: string;
  readonly reason: Reason | undefined;
  readonly retryable: boolean;
  readonly retryAfter: string | undefined;
  readonly details: Record<string, unknown> | undefined;

  constructor(init: TaskErrorInit = {}) {
    super(init.internalMessage ?? init.code ?? init.reason ?? 'task error', init.cause === undefined ? undefined : { cause: init.cause });
    this.name = 'TaskError';
    this.reason = init.reason;
    this.code = init.code ?? (init.reason !== undefined && isReason(init.reason) ? REASONS[init.reason].code : 'taskFailed');
    this.retryable =
      init.retryable ??
      (init.reason !== undefined && isReason(init.reason) ? REASONS[init.reason].retryable : defaultRetryable(this.code));
    this.retryAfter = init.retryAfter;
    this.details = init.details;
  }
}

/** Convenience: an error for one of the closed reasons. */
export function taskErrorForReason(reason: Reason, init: Omit<TaskErrorInit, 'reason'> = {}): TaskError {
  return new TaskError({ ...init, reason });
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire error (the resolved payload) and the catch-all
// ─────────────────────────────────────────────────────────────────────────────

/** The members of a `trust-task-error` payload this module emits (besides `inResponseTo`). */
export interface WireError {
  code: string;
  retryable: boolean;
  message: string;
  retryAfter?: string;
  details?: Record<string, unknown>;
}

/** Framework 8.2.2: without a declared bound, at most 4096 bytes of canonical JSON and 16 members. */
export const DETAILS_MAX_BYTES = 4096;
export const DETAILS_MAX_MEMBERS = 16;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** Whether `details` is within the framework bound. A value that cannot be canonicalised is out of bound. */
export function detailsWithinBound(details: unknown): boolean {
  if (!isPlainObject(details)) return false;
  if (Object.keys(details).length > DETAILS_MAX_MEMBERS) return false;
  try {
    return Buffer.byteLength(canonicalJson(details), 'utf8') <= DETAILS_MAX_BYTES;
  } catch {
    return false;
  }
}

const INTERNAL: WireError = Object.freeze({
  code: 'internalError',
  retryable: DEFAULT_RETRYABLE.internalError,
  message: CODE_MESSAGES.internalError,
});

/**
 * Resolve anything thrown (or returned as a failure) to the payload members. The catch-all: a
 * non-`TaskError`, an ill-formed code or an unknown reason becomes an opaque `internalError`.
 * Nothing from `error.message` is ever copied.
 */
export function toWireError(error: unknown): WireError {
  if (!(error instanceof TaskError)) return { ...INTERNAL };
  const code = isStandardCode(error.code) ? normalizeCode(error.code) : error.code;
  if (!isWireCode(code)) return { ...INTERNAL };
  if (error.reason !== undefined && !isReason(error.reason)) return { ...INTERNAL };

  const message = error.reason !== undefined
    ? REASONS[error.reason].message
    : isStandardCode(code)
      ? CODE_MESSAGES[code as StandardCode]
      : CODE_MESSAGES.taskFailed;
  const wire: WireError = { code, retryable: error.retryable === true, message };

  if (wire.retryable && error.retryAfter !== undefined && parseDateTimeStamp(error.retryAfter) !== undefined) {
    wire.retryAfter = error.retryAfter;
  }

  const custom = error.details !== undefined && isPlainObject(error.details) ? error.details : {};
  const withReason: Record<string, unknown> = { ...custom, ...(error.reason !== undefined ? { reason: error.reason } : {}) };
  if (Object.keys(withReason).length > 0) {
    if (detailsWithinBound(withReason)) wire.details = withReason;
    else if (error.reason !== undefined) wire.details = { reason: error.reason };
    // otherwise `details` is dropped: the code, retryable and retryAfter still carry the failure
  }
  return wire;
}

// ─────────────────────────────────────────────────────────────────────────────
// The error document
// ─────────────────────────────────────────────────────────────────────────────

/** The members of the request an error needs. Any of them may be absent (an unparseable request). */
export interface ErrorRequestRef {
  id?: unknown;
  type?: unknown;
  threadId?: unknown;
  parentThreadId?: unknown;
  issuer?: unknown;
  recipient?: unknown;
}

export interface ErrorPayload extends WireError {
  inResponseTo?: { typeUri: string; id?: string };
}

export interface TrustTaskErrorDocument {
  id: string;
  type: typeof TRUST_TASK_ERROR_TYPE_URI;
  threadId: string;
  parentThreadId?: string;
  issuer?: string;
  recipient?: string;
  issuedAt: string;
  payload: ErrorPayload;
  proof?: unknown;
}

export interface ErrorBuildOptions {
  /** Fresh document id. Default: a random UUID. Inject the suite's id source in tests. */
  newId?: () => string;
  /** One clock for every timestamp this boundary writes. Default: now, whole seconds. */
  now?: () => string;
  /**
   * Override the addressee. Under `identityMismatch` the error MUST go to the transport-authenticated
   * sender and never to the contested in-band issuer (framework 8.1); pass that sender here. With no
   * transport sender the in-band issuer is addressed.
   */
  recipient?: string;
}

const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

/**
 * Build the `trust-task-error` document for `request` (which may be absent or partial).
 * `threadId` continues the request's thread, else is the request's own id, else the error's own id
 * (framework 4.9). The error is a fresh document with a fresh `id`; it is never answered when sent
 * back to us (`isInboundError`). `inResponseTo.id` is withheld for `identityMismatch` because the
 * addressee did not necessarily compose the contested document.
 */
export function buildErrorDocument(
  request: ErrorRequestRef | undefined,
  error: unknown,
  options: ErrorBuildOptions = {},
): TrustTaskErrorDocument {
  const wire = toWireError(error);
  const id = (options.newId ?? randomUUID)();
  const reqId = str(request?.id);
  const reqType = str(request?.type);

  const payload: ErrorPayload = { ...wire };
  if (reqType !== undefined) {
    payload.inResponseTo = normalizeCode(wire.code) === 'identityMismatch' || reqId === undefined
      ? { typeUri: reqType }
      : { typeUri: reqType, id: reqId };
  }

  const doc: TrustTaskErrorDocument = {
    id,
    type: TRUST_TASK_ERROR_TYPE_URI,
    threadId: str(request?.threadId) ?? reqId ?? id,
    issuedAt: (options.now ?? issuedAtNow)(),
    payload,
  };
  const parent = str(request?.parentThreadId);
  if (parent !== undefined) doc.parentThreadId = parent;
  const issuer = str(request?.recipient);
  if (issuer !== undefined) doc.issuer = issuer;
  const recipient = options.recipient ?? str(request?.issuer);
  if (recipient !== undefined) doc.recipient = recipient;
  return doc;
}

const ERROR_TYPE_PREFIX = 'https://trusttasks.org/spec/trust-task-error/';

/**
 * Whether a document is itself an error (any registry version, any fragment, or the bridge's
 * pre-P1 error type). An inbound error is never answered: replying would start an error loop
 * (framework section 8), and it changes the lifecycle state of nothing (`lifecycle.ts`).
 */
export function isInboundError(doc: { type?: unknown } | undefined): boolean {
  const t = str(doc?.type);
  if (t === undefined) return false;
  const bare = t.split('#')[0]!;
  return bare.startsWith(ERROR_TYPE_PREFIX) || bare === TRUST_TASK_ERROR_TYPE;
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy codes (the bridge before this phase)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * What each code the `POST /trust-tasks` bridge used to emit becomes. The old HTTP statuses
 * (404 and 401) become the binding's 422; `payload.code` and `payload.message` stay where they
 * were but carry the new values.
 */
export const LEGACY_CODE_MAP: Readonly<Record<string, StandardCode>> = Object.freeze({
  malformedRequest: 'malformedRequest',
  'policy/invalid': 'malformedRequest',
  endpointNotFound: 'unsupportedType',
  communityNotFound: 'wrongRecipient',
  'proof/unattributable': 'identityMismatch',
});

export function fromLegacyCode(code: string): StandardCode | undefined {
  return Object.prototype.hasOwnProperty.call(LEGACY_CODE_MAP, code) ? LEGACY_CODE_MAP[code] : undefined;
}
