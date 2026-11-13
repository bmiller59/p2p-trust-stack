// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Document lifecycle for the Trust Task boundary (framework 4.12) and the seam between the internal
 * two-phase-commit machinery and it (conformance plan section 3.9, suite design section 12).
 *
 * Pure. Three things:
 *
 *   1. the framework's states and permitted transitions, with `transition()` refusing anything else
 *      (a terminal state stays terminal; an inbound error moves nothing);
 *   2. which lifecycle state an error code reports (`stateForErrorCode`);
 *   3. total tables from every internal status string the stack uses to exactly one lifecycle state.
 *      Where the stack's own status type is a closed union the table is typed against it, so adding
 *      a status without mapping it fails the typecheck.
 *
 * Nothing here is persisted yet; the repository fields arrive with the persistence phase.
 */
import type { CeremonyProposal } from '../../../tx/ceremony-store.js';
import type { GovernanceChangeProposal } from '../../../tx/governance-change-store.js';
import { isStandardCode, normalizeCode } from './runtime.js';

export const LIFECYCLE_STATES = [
  'received',
  'validated',
  'accepted',
  'executing',
  'suspended',
  'responded',
  'errored',
  'cancelled',
  'expired',
] as const;

export type LifecycleState = (typeof LIFECYCLE_STATES)[number];

/** Framework 4.12, "Permitted next states". */
export const PERMITTED_NEXT: Readonly<Record<LifecycleState, readonly LifecycleState[]>> = Object.freeze({
  received: ['validated', 'errored', 'expired'],
  validated: ['accepted', 'errored', 'expired'],
  accepted: ['executing', 'suspended', 'cancelled', 'errored'],
  executing: ['responded', 'errored', 'cancelled', 'suspended'],
  suspended: ['executing', 'cancelled', 'expired'],
  responded: [],
  errored: [],
  cancelled: [],
  expired: [],
});

export const TERMINAL_STATES: readonly LifecycleState[] = Object.freeze(
  LIFECYCLE_STATES.filter((s) => PERMITTED_NEXT[s].length === 0),
);

export function isTerminal(state: LifecycleState): boolean {
  return PERMITTED_NEXT[state].length === 0;
}

export function canTransition(from: LifecycleState, to: LifecycleState): boolean {
  return PERMITTED_NEXT[from].includes(to);
}

export class LifecycleError extends Error {
  readonly from: LifecycleState;
  readonly to: LifecycleState;
  constructor(from: LifecycleState, to: LifecycleState) {
    super(`lifecycle: ${from} -> ${to} is not a permitted transition`);
    this.name = 'LifecycleError';
    this.from = from;
    this.to = to;
  }
}

/** Return `to` if the move is permitted from `from`; throw `LifecycleError` otherwise. */
export function transition(from: LifecycleState, to: LifecycleState): LifecycleState {
  if (!canTransition(from, to)) throw new LifecycleError(from, to);
  return to;
}

/**
 * The state an error document reports. `expired` is the envelope's `expiresAt` having passed;
 * `cancelled` is the consumer stopping of its own accord; everything else is `errored`. A ceremony
 * deadline that lapses is `taskFailed` with `details.reason: "deadlineLapsed"`, hence `errored`
 * (settled; `expired` is reserved for the envelope).
 */
export function stateForErrorCode(code: string): LifecycleState {
  const normal = isStandardCode(code) ? normalizeCode(code) : code;
  if (normal === 'expired') return 'expired';
  if (normal === 'cancelled') return 'cancelled';
  return 'errored';
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal status -> lifecycle state (total tables)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * `trust_tasks.status` (the document log). Free text in the schema; these are the values the
 * stack writes or reads: `recorded` (default), `pending` (a held proposal's response), `allowed`
 * and `denied` (policy gate and co-signature), `completed` (an effect response), and `failed`
 * (expected by the UIs; written by the participant-conformance phase).
 */
export const TRUST_TASK_STATUSES = ['recorded', 'pending', 'allowed', 'denied', 'completed', 'failed'] as const;
export type TrustTaskStatus = (typeof TRUST_TASK_STATUSES)[number];

export const TRUST_TASK_STATUS_STATE: Readonly<Record<TrustTaskStatus, LifecycleState>> = Object.freeze({
  recorded: 'accepted',
  pending: 'accepted', // held: understood and blocked, the exchange stays open (next-step)
  allowed: 'executing', // a gate passed; the effect step follows
  denied: 'errored',
  completed: 'responded',
  failed: 'errored',
});

/**
 * `ceremony_proposals.status` and `governance_change_proposals.status`: the same five values. Typed
 * against the stores' unions. `aborted` is only ever written by the operator reset, a consumer-side
 * stop, hence `cancelled`; `expired` is the ceremony deadline, which is `errored` on the wire.
 */
export type ProposalStatus = CeremonyProposal['status'];
export const PROPOSAL_STATUS_STATE: Readonly<Record<ProposalStatus, LifecycleState>> = Object.freeze({
  pending: 'accepted',
  crystallized: 'responded',
  expired: 'errored',
  failed: 'errored',
  aborted: 'cancelled',
});
// A second ceremony kind keeps its own union; it must stay in step with the first.
const _governanceChangeAgrees: Record<GovernanceChangeProposal['status'], LifecycleState> = PROPOSAL_STATUS_STATE;
void _governanceChangeAgrees;

/**
 * The coordinator's view of a transaction (plan 3.5). Today only `committed` and `aborted` exist;
 * `inFlight` and `unknown` are the values the outcome accessor will add. `unknown` is never guessed
 * as `responded` or `errored`: it stays `accepted` and may be reported as `indeterminate`.
 */
export const TX_OUTCOMES = ['committed', 'aborted', 'inFlight', 'unknown'] as const;
export type TxOutcome = (typeof TX_OUTCOMES)[number];

export const TX_OUTCOME_STATE: Readonly<Record<TxOutcome, LifecycleState>> = Object.freeze({
  committed: 'responded',
  aborted: 'errored',
  inFlight: 'executing',
  unknown: 'accepted',
});

/** A `#response` is emitted only when the observable outcome is `committed`, never on a "yes" vote. */
export function mayEmitResponse(outcome: TxOutcome): boolean {
  return outcome === 'committed';
}

/** A `trust-task-error` is emitted for an aborted exchange (or a refusal before one exists). */
export function mayEmitError(outcome: TxOutcome): boolean {
  return outcome === 'aborted';
}
