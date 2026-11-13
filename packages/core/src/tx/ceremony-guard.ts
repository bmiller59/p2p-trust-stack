// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Shared ceremony-proposal guards (conformance plan P5; rows TIME, DUP, 2PC-004, 2PC-005).
 *
 * One place decides whether a proposal is still open, so the core coordinator and every participant
 * (utility server, agent) refuse the same requests the same way:
 *
 *  - `isLapsed` / `assertOpen`: a pending proposal whose `expiresAt` has been reached (`>=`) is no
 *    longer open. `assertOpen` throws a typed `TaskError`; `closeIfLapsed` also flips the stored
 *    status to `expired` (and records the failure code) so the next read reports the truth.
 *  - `assertResettable`: `ceremony_reset` is allowed only from `failed` / `expired`.
 *  - a bounded in-memory registry of the reason a transaction was refused, keyed by transaction id,
 *    so a boundary can read why a participant voted `no` (plan 3.9). Never persisted, never grows
 *    past `ABORT_REASON_CAP`.
 *
 * The thrown errors keep the historical message text (`proposal is <status>`) as the internal
 * message so existing log readers and tests are unaffected; the wire form is the closed reason.
 */
import type { CeremonyProposal, CeremonyStore } from './ceremony-store.js';
import { TaskError, taskErrorForReason } from '../services/trust-tasks/boundary/errors.js';
import type { Reason } from '../services/trust-tasks/boundary/errors.js';

/** True when the proposal can no longer take approvals because its deadline has been reached. */
export function isLapsed(proposal: Pick<CeremonyProposal, 'expiresAt'>, now: number = Date.now()): boolean {
  return now >= proposal.expiresAt;
}

/**
 * Throw unless the proposal is `pending` and its deadline has not been reached.
 *   - past deadline            -> `deadlineLapsed`
 *   - `crystallized`           -> `alreadyCommitted`
 *   - `failed`/`expired`/`aborted` -> `taskFailed` (internal message `proposal is <status>`)
 * Pure: it does not change storage (see `closeIfLapsed`).
 */
export function assertOpen(proposal: Pick<CeremonyProposal, 'status' | 'expiresAt'>, now: number = Date.now()): void {
  if (proposal.status === 'crystallized') {
    throw taskErrorForReason('alreadyCommitted', { internalMessage: 'proposal is crystallized' });
  }
  if (proposal.status === 'expired') {
    throw taskErrorForReason('deadlineLapsed', { internalMessage: 'proposal is expired' });
  }
  if (proposal.status !== 'pending') {
    throw new TaskError({ code: 'taskFailed', retryable: false, internalMessage: `proposal is ${proposal.status}` });
  }
  if (isLapsed(proposal, now)) {
    throw taskErrorForReason('deadlineLapsed', { internalMessage: 'proposal expired' });
  }
}

/**
 * If the proposal is pending and lapsed, store `expired` with its failure code and return the
 * refreshed proposal; otherwise return the proposal as given. Call before `assertOpen` on any path
 * that must leave the stored state truthful even when the request itself is then refused.
 */
export async function closeIfLapsed(
  store: CeremonyStore,
  proposal: CeremonyProposal,
  now: number = Date.now(),
): Promise<CeremonyProposal> {
  if (proposal.status !== 'pending' || !isLapsed(proposal, now)) return proposal;
  await store.markExpired(proposal.proposalId);
  return { ...proposal, status: 'expired', errorCode: 'taskFailed', retryable: false, errorReason: EXPIRED_TEXT };
}

export const EXPIRED_TEXT = 'The ceremony deadline has passed.';

/** `ceremony_reset` is allowed only from `failed` or `expired` (a lapsed pending one counts as expired). */
export function assertResettable(proposal: Pick<CeremonyProposal, 'status'>): void {
  if (proposal.status === 'failed' || proposal.status === 'expired') return;
  if (proposal.status === 'crystallized') {
    throw taskErrorForReason('alreadyCommitted', { internalMessage: 'cannot reset a crystallized ceremony' });
  }
  throw new TaskError({
    code: 'taskFailed',
    retryable: false,
    internalMessage: `cannot reset a ${proposal.status} ceremony (only failed or expired)`,
  });
}

/** The code, retryability and (when known) closed reason of any thrown value, for a `failed` row. */
export function describeFailure(err: unknown): { code: string; retryable: boolean; reason?: Reason } {
  if (err instanceof TaskError) {
    return { code: err.code, retryable: err.retryable, ...(err.reason === undefined ? {} : { reason: err.reason }) };
  }
  return { code: 'internalError', retryable: false };
}

// ── abort-reason registry ────────────────────────────────────────────────────

export interface AbortReason {
  code: string;
  retryable: boolean;
  reason?: Reason;
}

export const ABORT_REASON_CAP = 256;
const abortReasons = new Map<string, AbortReason>();

/** Remember why `txId` was refused (a participant calls this before voting `no`). Bounded, FIFO. */
export function recordAbortReason(txId: string, err: unknown): AbortReason {
  const r = describeFailure(err);
  abortReasons.delete(txId);
  abortReasons.set(txId, r);
  while (abortReasons.size > ABORT_REASON_CAP) {
    const oldest = abortReasons.keys().next().value;
    if (oldest === undefined) break;
    abortReasons.delete(oldest);
  }
  return r;
}

export function getAbortReason(txId: string): AbortReason | undefined {
  return abortReasons.get(txId);
}

export function clearAbortReasons(): void {
  abortReasons.clear();
}
