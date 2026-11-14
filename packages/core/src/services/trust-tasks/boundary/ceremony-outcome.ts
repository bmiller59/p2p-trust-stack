// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * What a ceremony document is answered with, decided from the internal facts (conformance plan 3.9,
 * suite design section 12). Pure: the handler turns the verdict into a `#response`, a
 * `trust-task-next-step` or a `trust-task-error`.
 *
 *   committed outcome AND crystallized proposal  -> respond (the effect exists)
 *   pending, deadline not reached, not aborted    -> next-step (blocked, the exchange stays open)
 *   aborted outcome / failed / aborted proposal   -> error: taskFailed with the recorded closed reason
 *   expired, or pending past the deadline         -> error: taskFailed, details.reason deadlineLapsed
 *   outcome unknown on an open proposal           -> indeterminate (retryable), never guessed
 *
 * A "yes" vote is not an input: only the coordinator's outcome and the stored proposal are, so a
 * response can never precede the effect. An unrecorded or out-of-vocabulary abort reason is
 * reported as an opaque `internalError`, never leaked.
 */
import type { CeremonyProposal } from '../../../tx/ceremony-store.js';
import { REASONS, isReason } from './errors.js';
import type { Reason } from './errors.js';
import type { TxOutcome } from './lifecycle.js';

export type CeremonyVerdict =
  | { kind: 'respond' }
  | { kind: 'next-step' }
  | { kind: 'error'; code: 'taskFailed' | 'internalError' | 'permissionDenied' | 'unavailable' | 'malformedRequest' | 'idConflict'; reason?: Reason; retryable: boolean }
  | { kind: 'indeterminate'; retryable: true };

export interface CeremonyFacts {
  proposal: Pick<CeremonyProposal, 'status' | 'expiresAt' | 'errorCode' | 'errorReason' | 'retryable'> & { reason?: string | null };
  /** `TransactionManager.getOutcome` for the ceremony's transaction; `undefined` when none was begun. */
  outcome?: TxOutcome;
  now: number;
  /** The abort reason the participant recorded for the transaction, if any. */
  abortReason?: { code: string; retryable: boolean; reason?: string };
}

const LAPSED: CeremonyVerdict = { kind: 'error', code: 'taskFailed', reason: 'deadlineLapsed', retryable: REASONS.deadlineLapsed.retryable };

/** Standard codes a participant may record without a closed reason; anything else is opaque. */
const PASS_THROUGH: ReadonlySet<string> = new Set(['taskFailed', 'unavailable', 'permissionDenied', 'malformedRequest', 'idConflict']);

function failure(reason: { code: string; retryable: boolean; reason?: string } | undefined): CeremonyVerdict {
  if (reason === undefined) return { kind: 'error', code: 'taskFailed', retryable: false };
  if (reason.reason !== undefined) {
    if (!isReason(reason.reason)) return { kind: 'error', code: 'internalError', retryable: false };
    return { kind: 'error', code: REASONS[reason.reason].code, reason: reason.reason, retryable: REASONS[reason.reason].retryable };
  }
  if (PASS_THROUGH.has(reason.code)) {
    return { kind: 'error', code: reason.code as Extract<CeremonyVerdict, { kind: 'error' }>['code'], retryable: reason.retryable };
  }
  return { kind: 'error', code: 'internalError', retryable: false };
}

export function ceremonyVerdict(facts: CeremonyFacts): CeremonyVerdict {
  const { proposal, outcome, now } = facts;
  if (proposal.status === 'crystallized') {
    // The effect exists; answer only if the coordinator agrees. Anything else is not yet knowable.
    return outcome === undefined || outcome === 'committed' ? { kind: 'respond' } : outcome === 'aborted' ? failure(facts.abortReason) : { kind: 'indeterminate', retryable: true };
  }
  if (proposal.status === 'expired') return LAPSED;
  if (proposal.status === 'failed' || proposal.status === 'aborted') {
    const recorded = proposal.errorCode === undefined || proposal.errorCode === null
      ? facts.abortReason
      : { code: proposal.errorCode, retryable: proposal.retryable === true, ...(proposal.reason == null ? {} : { reason: proposal.reason }) };
    return failure(recorded);
  }
  // pending
  if (outcome === 'aborted') return failure(facts.abortReason);
  if (outcome === 'committed') return { kind: 'indeterminate', retryable: true }; // committed but the proposal is not crystallized yet: never guess
  if (now >= proposal.expiresAt) return LAPSED;
  if (outcome === 'unknown') return { kind: 'indeterminate', retryable: true };
  return { kind: 'next-step' };
}
