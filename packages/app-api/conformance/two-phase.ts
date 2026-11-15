// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The two-phase trigger actions of the suite's contract (docs/04 section 12.1, optional capability `trigger.twoPhase`), mapped
 * onto the REAL coordinator and participant.
 *
 * Nothing here replaces the transaction machinery. The VRC receive participant (the one the `issue` handler enlists) is wrapped by
 * {@link FaultableParticipant}; the real `TransactionCoordinator` still writes `TX_STARTED`, collects the votes, logs the decision
 * and fans out commit or abort, and the handler still reads `TransactionManager.getOutcome`. A fault only changes what ONE
 * participant does in phase 1 of the next `store_remote_vrc` transaction:
 *
 *   commit            nothing changes; `deliver: false` additionally drops the reply after commit (the adapter's `send` returns none)
 *   abort             the participant prepares, then fails (the coordinator sees a thrown error, counts it as no and logs `aborted`);
 *                     `reason` is recorded as the closed abort reason, `internal` is the text of the failure and stays off the wire
 *   voteNo            the participant prepares, then votes no with the recorded `reason`
 *   inflight/unknown  the participant prepares and then parks: no vote reaches the coordinator, so no decision is logged and the
 *                     handler (and with it the request) is still running. `settle` releases it with a commit or an abort vote.
 *
 * `inflight` and `unknown` are the same here: both are a transaction that has started and has no logged decision. The real
 * coordinator cannot be made to forget a started transaction without being changed, so the two are not told apart
 * (`getOutcome` reads `inFlight` in both).
 */
import { TaskError, isReason } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import { recordAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { Reason } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { Operation, Outcome, Participant, Vote } from '@p2p-trust-stack/core/tx/types.js';

export type TwoPhaseFault =
  | { outcome: 'commit'; deliver: boolean }
  | { outcome: 'abort'; reason?: Reason; internal?: string }
  | { outcome: 'voteNo'; reason?: Reason }
  | { outcome: 'inflight' }
  | { outcome: 'unknown' };

const FAULTED_OP = 'store_remote_vrc';
/** An aborted exchange is `taskFailed`, not retryable (docs/04 section 12), whatever the default code of the reason's own failure (storeFailed alone is `unavailable`, retryable). */
const ABORTED = { code: 'taskFailed', retryable: false } as const;

/** A closed-vocabulary abort reason, or undefined when absent. */
export function parseReason(args: Record<string, unknown>): Reason | undefined {
  const v = args.reason;
  if (v === undefined) return undefined;
  if (!isReason(v)) throw new Error('reason must be a token of the closed details.reason vocabulary');
  return v;
}

export function parseTwoPhase(args: Record<string, unknown>): TwoPhaseFault {
  const str = (k: string): string | undefined => {
    const v = args[k];
    if (v === undefined) return undefined;
    if (typeof v !== 'string' || v === '') throw new Error(`twoPhase ${k} must be a non-empty string`);
    return v;
  };
  const reason = parseReason(args);
  switch (args.outcome) {
    case 'commit':
      if (args.deliver !== undefined && typeof args.deliver !== 'boolean') throw new Error('twoPhase deliver must be a boolean');
      return { outcome: 'commit', deliver: args.deliver !== false };
    case 'abort': {
      const internal = str('internal');
      return { outcome: 'abort', ...(reason === undefined ? {} : { reason }), ...(internal === undefined ? {} : { internal }) };
    }
    case 'voteNo':
      return { outcome: 'voteNo', ...(reason === undefined ? {} : { reason }) };
    case 'inflight':
      return { outcome: 'inflight' };
    case 'unknown':
      return { outcome: 'unknown' };
    default:
      throw new Error('twoPhase outcome must be commit, abort, voteNo, inflight or unknown');
  }
}

interface Parked {
  txId: string;
  release: (vote: Vote, reason?: Reason) => void;
}

/** One-shot fault state: what the next issue transaction does, and the transaction parked by `inflight` or `unknown`. */
export class TwoPhaseFaults {
  private armed: TwoPhaseFault | undefined;
  private parked: Parked | undefined;
  private parkWaiter: (() => void) | undefined;
  private dropReply = false;

  arm(fault: TwoPhaseFault): void {
    this.armed = fault;
  }

  /** Consumed by the participant when a faulted transaction prepares. */
  take(): TwoPhaseFault | undefined {
    const fault = this.armed;
    this.armed = undefined;
    if (fault?.outcome === 'commit' && !fault.deliver) this.dropReply = true;
    return fault;
  }

  /** True once if the transaction just run committed with `deliver: false`. */
  takeDroppedReply(): boolean {
    const drop = this.dropReply;
    this.dropReply = false;
    return drop;
  }

  get isParked(): boolean {
    return this.parked !== undefined;
  }

  /** Resolves when a transaction parks. Call before sending, so a park cannot be missed. */
  parkSignal(): Promise<'parked'> {
    return new Promise((resolve) => {
      this.parkWaiter = () => resolve('parked');
    });
  }

  park(txId: string): Promise<{ vote: Vote; reason?: Reason }> {
    return new Promise((resolve) => {
      this.parked = { txId, release: (vote, reason) => resolve({ vote, ...(reason === undefined ? {} : { reason }) }) };
      const waiter = this.parkWaiter;
      this.parkWaiter = undefined;
      waiter?.();
    });
  }

  /** Let the parked transaction vote. */
  release(vote: Vote, reason?: Reason): void {
    const parked = this.parked;
    if (parked === undefined) throw new Error('no transaction is waiting to be settled');
    this.parked = undefined;
    parked.release(vote, reason);
  }

  clear(): void {
    this.armed = undefined;
    this.dropReply = false;
    this.parkWaiter = undefined;
    if (this.parked !== undefined) this.release('no');
  }
}

/** The real participant, with phase 1 of a faulted transaction altered by {@link TwoPhaseFaults}. Everything else is delegated. */
export class FaultableParticipant implements Participant {
  readonly pid: string;
  private readonly inner: Participant;
  private readonly faults: TwoPhaseFaults;

  constructor(inner: Participant, faults: TwoPhaseFaults) {
    this.inner = inner;
    this.faults = faults;
    this.pid = inner.pid;
  }

  handlesOperation(op: Operation): boolean {
    return this.inner.handlesOperation?.(op) ?? true;
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    if (!operations.some((o) => o.op === FAULTED_OP)) return this.inner.prepare(txId, operations);
    const fault = this.faults.take();
    if (fault === undefined || fault.outcome === 'commit') return this.inner.prepare(txId, operations);
    const vote = await this.inner.prepare(txId, operations);
    if (vote === 'no') return 'no';
    switch (fault.outcome) {
      case 'abort':
        if (fault.reason !== undefined) recordAbortReason(txId, new TaskError({ ...ABORTED, reason: fault.reason, internalMessage: fault.internal ?? 'conformance fault: abort' }));
        throw new Error(fault.internal ?? 'conformance fault: the coordinator aborted the transaction');
      case 'voteNo':
        if (fault.reason !== undefined) recordAbortReason(txId, new TaskError({ ...ABORTED, reason: fault.reason, internalMessage: 'conformance fault: vote no' }));
        return 'no';
      default: {
        const settled = await this.faults.park(txId);
        if (settled.vote === 'no' && settled.reason !== undefined) recordAbortReason(txId, new TaskError({ ...ABORTED, reason: settled.reason, internalMessage: 'conformance fault: settled as abort' }));
        return settled.vote;
      }
    }
  }
  commit(txId: string): Promise<void> {
    return this.inner.commit(txId);
  }
  abort(txId: string): Promise<void> {
    return this.inner.abort(txId);
  }
  compensate(txId: string): Promise<void> {
    return this.inner.compensate(txId);
  }
  inquiry(txId: string): Promise<Outcome> {
    return this.inner.inquiry(txId);
  }
  query(op: string, params?: Record<string, unknown>): Promise<unknown> {
    if (this.inner.query === undefined) return Promise.reject(new Error('the participant has no query'));
    return this.inner.query(op, params);
  }
}
