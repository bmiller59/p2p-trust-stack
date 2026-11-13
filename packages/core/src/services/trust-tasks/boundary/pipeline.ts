// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The Tier 1 consumer pipeline (conformance plan P2): pure, transport-agnostic, shared by every
 * carrier. A carrier hands it the raw bytes it received and the transport-authenticated sender (or
 * none); it returns what to send back. It wraps the registry runtime's `consumeInbound`, so the
 * order of checks is the library's (envelope, type and version, payload, expiry and recipient,
 * freshness, sender cross-check, proof policy, spec policy, duplicate claim, handler), and it owns
 * everything the library leaves to the consumer: byte limits, parsing, the handler registry, the
 * mapping of every refusal onto the typed error model (`errors.ts`, fixed wire messages), the
 * catch-all for unexpected failures, and the HTTPS binding's status for each outcome.
 *
 * Proof: until the DID-resolving verifier lands (phase P4) a document that carries a `proof` is
 * refused (`rejectIfPresent`). There is no switch for that: proof checks are never off.
 *
 * Strictness: `lenient` exists for one release so existing clients of the legacy evaluate task can
 * move. It relaxes ONLY the freshness window and the recipient-membership check, ONLY for
 * non-consequential handlers, and reports every document it let through that strict mode would
 * have refused (`onLenient`). Consequential handlers are always strict.
 *
 * Retention (decision A4): nothing here stores anything. The result says whether a document was
 * refused before the pipeline reached the duplicate claim (`refusedBeforeProof`), which is the line
 * the persistence layer (P3) must not store a body on the near side of.
 */
import { randomUUID } from 'node:crypto';
import { TaskError, buildErrorDocument, httpStatusForCode, isInboundError } from './errors.js';
import type { ErrorRequestRef, TrustTaskErrorDocument } from './errors.js';
import { HandlerRegistry } from './handlers.js';
import type { HandlerContext, PipelineHandler } from './handlers.js';
import { simplePayloadValidator } from './payload-validator.js';
import { EXPIRY_HORIZON_MS, MAX_AGE_MS, SKEW_MS } from './pins.js';
import {
  DEFAULT_FRESHNESS,
  InMemoryReplayGuard,
  StaticTransport,
  UnauthenticatedTransport,
  consequentialChecks,
  consumeInbound,
  validateFreshness,
} from './runtime.js';
import type { ConsumeChecks, ErrorResponse, FreshnessPolicy, ReplayGuard, SpecPolicy, TrustTaskDocument } from './runtime.js';

export type Strictness = 'strict' | 'lenient';

/** Largest body accepted, in bytes (matches the HTTPS carrier's body limit). */
export const DEFAULT_MAX_BODY_BYTES = 1_048_576;

/** Never matches a served recipient. */
const UNSERVED = 'urn:trust-tasks:unserved';
/** Matches no type: the library then answers `unsupportedType` after its envelope check. */
const UNSERVED_SPEC: SpecPolicy = { typeUri: 'urn:trust-tasks:unserved-type', isBearer: false, isProofRequired: false, isRecipientRequired: false };
const FRAGMENT = /#(request|response)$/;

export interface LenientEvent {
  readonly check: 'freshness' | 'recipient';
  readonly type: string;
  readonly detail: string;
}

export interface PipelineOptions {
  handlers: HandlerRegistry | readonly PipelineHandler[];
  /** Identifiers this listener answers as; the first is the default unless `defaultVid` is given. */
  servedVids?: readonly string[];
  /** Answers "is this recipient one of ours?" for sets that live in a database (hosted communities). */
  isServed?: (recipient: string) => Promise<boolean> | boolean;
  /** The identifier errors are issued by when the document names none of ours. */
  defaultVid?: string;
  /**
   * Duplicate record for consequential handlers. Default: in memory (lost on restart); a deployment
   * passes the durable `AcceptedIdStore` (accepted-store.ts) over its data source.
   */
  guard?: ReplayGuard;
  /** One clock, epoch milliseconds. Default `Date.now`. */
  now?: () => number;
  newId?: () => string;
  strictness?: Strictness;
  onLenient?: (event: LenientEvent) => void;
  /** Called with whatever a handler or the pipeline itself threw that was not a `TaskError`. */
  onUnexpected?: (err: unknown) => void;
  maxBodyBytes?: number;
}

export interface PipelineInput {
  /** The body exactly as received. */
  raw: Uint8Array | string;
  /** The identity the carrier authenticated, if any. */
  sender?: string | undefined;
}

export type PipelineKind =
  | 'response' //   200 the handler's response
  | 'error' //      a typed error document
  | 'absorbed' //   204 an inbound error, or an accepted fire-and-forget task
  | 'duplicate' //  200 with the prior response, 204 when none is kept
  | 'inFlight' //   202
  | 'refused'; //   status only: nothing addressable, so no document

export interface PipelineResult {
  kind: PipelineKind;
  status: number;
  /** The document to send (a response, a typed error, or a stored prior response); never signed in P2. */
  document?: unknown;
  /** For `refused` only: a minimal unsigned body that is not a Trust Task document. */
  minimal?: { code: string; message: string; retryable: boolean };
  /** Wire code of an error or refusal. */
  code?: string;
  /** The body exactly as received, for retention once it has passed verification (P3). */
  raw: string | undefined;
  /** The parsed document, when the body parsed to an object. */
  received?: Record<string, unknown>;
  /** True when the document was refused before the duplicate claim: such bodies are never stored. */
  refusedBeforeProof: boolean;
  /** The identifier the pipeline answered as. */
  issuer?: string;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);
const isoSeconds = (ms: number): string => `${new Date(Math.floor(ms / 1000) * 1000).toISOString().slice(0, 19)}Z`;

const MINIMAL: Record<'undecodable' | 'unparseable' | 'notObject' | 'unaddressable', string> = {
  undecodable: 'The request body is not valid text.',
  unparseable: 'The request body is not valid JSON.',
  notObject: 'The request body is not a document.',
  unaddressable: 'The document cannot be addressed.',
};

export class Pipeline {
  private readonly registry: HandlerRegistry;
  private readonly served: readonly string[];
  private readonly guard: ReplayGuard;
  private readonly nowFn: () => number;
  private readonly newId: () => string;
  private readonly strictness: Strictness;
  private readonly maxBytes: number;

  private readonly options: PipelineOptions;

  constructor(options: PipelineOptions) {
    this.options = options;
    this.registry = options.handlers instanceof HandlerRegistry ? options.handlers : new HandlerRegistry(options.handlers);
    this.served = options.servedVids ?? [];
    this.guard = options.guard ?? new InMemoryReplayGuard();
    this.nowFn = options.now ?? Date.now;
    this.newId = options.newId ?? randomUUID;
    this.strictness = options.strictness ?? 'strict';
    this.maxBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  }

  get handlers(): HandlerRegistry {
    return this.registry;
  }

  /** The replay guard in use (tests and the settle sweep of P3). */
  get replayGuard(): ReplayGuard {
    return this.guard;
  }

  private defaultVid(): string | undefined {
    return this.options.defaultVid ?? this.served[0];
  }

  async process(input: PipelineInput): Promise<PipelineResult> {
    const size = typeof input.raw === 'string' ? Buffer.byteLength(input.raw, 'utf8') : input.raw.byteLength;
    if (size > this.maxBytes) return this.refuse('oversize', undefined);
    let raw: string;
    if (typeof input.raw === 'string') raw = input.raw;
    else {
      try {
        raw = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input.raw);
      } catch {
        return this.refuse('undecodable', undefined);
      }
    }
    return this.processText(raw, input.sender);
  }

  private refuse(kind: 'oversize' | 'undecodable' | 'unparseable' | 'notObject' | 'unaddressable', raw: string | undefined, received?: Record<string, unknown>): PipelineResult {
    const oversize = kind === 'oversize';
    const minimal = {
      code: 'malformedRequest',
      message: oversize ? 'The request body is too large.' : MINIMAL[kind as keyof typeof MINIMAL],
      retryable: false,
    };
    return { kind: 'refused', status: oversize ? 413 : httpStatusForCode('malformedRequest'), minimal, code: minimal.code, raw, ...(received === undefined ? {} : { received }), refusedBeforeProof: true };
  }

  private async processText(raw: string, sender: string | undefined): Promise<PipelineResult> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return this.refuse('unparseable', raw);
    }
    if (!isObject(parsed)) return this.refuse('notObject', raw);
    const doc = parsed as unknown as TrustTaskDocument<unknown>;
    const received = parsed;
    const now = this.nowFn();
    const clock = (): string => isoSeconds(this.nowFn());

    // An inbound error is never answered (no error loops) and changes nothing.
    if (isInboundError(doc)) return { kind: 'absorbed', status: 204, raw, received, refusedBeforeProof: true };

    // Who we answer as for this document. Even a document with no usable `id` is answered as us, to
    // its in-band issuer (the suite's generic reply checks require it); `inResponseTo.id` and
    // `threadId` are simply absent or the error's own when there is no request id to name.
    const recipient = str(doc.recipient);
    let served = false;
    let asVid: string | undefined = this.defaultVid();
    const ref = (): ErrorRequestRef => ({ id: doc.id, type: doc.type, threadId: doc.threadId, parentThreadId: doc.parentThreadId, issuer: doc.issuer, recipient: doc.recipient });
    const errorDoc = (error: unknown, over: { recipient?: string } = {}): TrustTaskErrorDocument =>
      buildErrorDocument(ref(), error, { newId: this.newId, now: clock, ...(asVid === undefined ? {} : { issuer: asVid }), ...over });
    const refused = (error: unknown, over: { recipient?: string } = {}, beforeProof = true): PipelineResult => {
      const document = errorDoc(error, over);
      return { kind: 'error', status: httpStatusForCode(document.payload.code), document, code: document.payload.code, raw, received, refusedBeforeProof: beforeProof, ...(asVid === undefined ? {} : { issuer: asVid }) };
    };
    try {
      served = recipient !== undefined && (this.served.includes(recipient) || (await this.options.isServed?.(recipient)) === true);
    } catch (err) {
      // The served set could not be consulted (for example the database is down): not a verdict on the document.
      this.options.onUnexpected?.(err);
      return refused(err);
    }
    if (served) asVid = recipient;

    // A request never carries a response variant or an explicit request variant on its type.
    if (typeof doc.type === 'string' && typeof doc.id === 'string' && FRAGMENT.test(doc.type)) {
      return refused(new TaskError({ code: 'malformedRequest', internalMessage: 'a variant fragment on a request type' }));
    }

    // Route.
    const type = typeof doc.type === 'string' ? doc.type : '';
    const exact = this.registry.find(type);
    const near = exact === undefined ? this.registry.sameSpecification(type) : undefined;
    const handler = exact ?? near?.handler;
    const spec: SpecPolicy = exact !== undefined ? { ...exact.spec, typeUri: type } : near !== undefined ? { ...near.handler.spec, typeUri: near.handler.types[0]! } : UNSERVED_SPEC;

    // Strictness applies to non-consequential handlers only.
    const lenient = this.strictness === 'lenient' && handler !== undefined && !handler.consequential;
    let myVid = served ? recipient! : (this.defaultVid() ?? UNSERVED);
    let checks: ConsumeChecks;
    if (handler === undefined || handler.consequential) {
      checks = handler === undefined ? { freshness: DEFAULT_FRESHNESS, replay: { kind: 'notConsequential' } } : consequentialChecks(this.guard);
    } else {
      checks = { freshness: this.readFreshness(doc), replay: { kind: 'notConsequential' } };
    }
    if (lenient) {
      const strict = validateFreshness(doc, now, checks.freshness);
      if (strict !== null) this.options.onLenient?.({ check: 'freshness', type, detail: strict.code });
      checks = { freshness: { skewMs: Number.MAX_SAFE_INTEGER }, replay: checks.replay };
      if (recipient !== undefined && !served) {
        this.options.onLenient?.({ check: 'recipient', type, detail: 'not a served identifier' });
        myVid = recipient;
      }
    }

    // Informational columns of the durable record (type and thread); a guard that has no use for them ignores this.
    if (handler?.consequential === true && typeof doc.id === 'string') {
      (this.guard as { describe?: (id: string, info: { type?: string; threadId?: string }) => void }).describe?.(doc.id, {
        ...(typeof doc.type === 'string' ? { type: doc.type } : {}),
        ...(typeof doc.threadId === 'string' ? { threadId: doc.threadId } : {}),
      });
    }

    const transport = sender === undefined ? new UnauthenticatedTransport() : new StaticTransport({ issuer: sender });
    let handlerError: ErrorResponse | undefined;
    let outcome: Awaited<ReturnType<typeof consumeInbound>>;
    try {
      outcome = await consumeInbound({
        transport,
        spec,
        proofPolicy: { kind: 'rejectIfPresent' },
        payloadPolicy: { kind: 'validate', validate: simplePayloadValidator },
        checks,
        doc,
        myVid,
        now,
        newErrorId: this.newId,
        clock,
        handler: async (accepted, parties) => {
          const ctx: HandlerContext = { parties, sender, myVid: asVid, now, clock, newId: this.newId };
          try {
            return await handler!.handle(accepted, ctx);
          } catch (err) {
            // Caught here so the library settles the claim by the error's `retryable`, not by the throw.
            if (!(err instanceof TaskError)) this.options.onUnexpected?.(err);
            handlerError = errorDoc(err) as unknown as ErrorResponse;
            return handlerError;
          }
        },
      });
    } catch (err) {
      this.options.onUnexpected?.(err);
      return refused(err, {}, false);
    }

    switch (outcome.kind) {
      case 'handled':
        return { kind: 'response', status: 200, document: outcome.response, raw, received, refusedBeforeProof: false, ...(asVid === undefined ? {} : { issuer: asVid }) };
      case 'accepted':
        return { kind: 'absorbed', status: 204, raw, received, refusedBeforeProof: false };
      case 'suppressed':
        return this.refuse('unaddressable', raw, received);
      case 'duplicate':
        if (outcome.inFlight) return { kind: 'inFlight', status: 202, raw, received, refusedBeforeProof: false };
        return outcome.priorResponse === undefined
          ? { kind: 'duplicate', status: 204, raw, received, refusedBeforeProof: false }
          : { kind: 'duplicate', status: 200, document: outcome.priorResponse, raw, received, refusedBeforeProof: false };
      case 'rejected': {
        if (handlerError !== undefined && outcome.error === handlerError) {
          const code = handlerError.payload.code;
          return { kind: 'error', status: httpStatusForCode(code), document: handlerError, code, raw, received, refusedBeforeProof: false, ...(asVid === undefined ? {} : { issuer: asVid }) };
        }
        const lib = outcome.error;
        const p = lib.payload;
        const details = near !== undefined && p.code === 'unsupportedVersion' ? { servedVersions: near.servedVersions } : undefined;
        const te = new TaskError({
          code: p.code,
          retryable: p.retryable,
          ...(p.retryAfter === undefined ? {} : { retryAfter: p.retryAfter }),
          ...(details === undefined ? {} : { details }),
          internalMessage: p.message,
        });
        const afterClaim = p.code === 'idConflict' || p.code === 'unavailable';
        return refused(te, { ...(str(lib.recipient) === undefined ? {} : { recipient: str(lib.recipient)! }) }, !afterClaim);
      }
    }
  }

  /** Strict window for a repeat-safe task: the pinned window when it dates itself, none when it does not. */
  private readFreshness(doc: TrustTaskDocument<unknown>): FreshnessPolicy {
    if (doc.issuedAt === undefined && doc.expiresAt === undefined) return DEFAULT_FRESHNESS;
    return { skewMs: SKEW_MS, maxAgeMs: MAX_AGE_MS, expiryHorizonMs: EXPIRY_HORIZON_MS };
  }
}

export function createPipeline(options: PipelineOptions): Pipeline {
  return new Pipeline(options);
}
