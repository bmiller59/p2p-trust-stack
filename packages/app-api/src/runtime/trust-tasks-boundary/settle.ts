// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The settle sweep for the duplicate record (plan 3.5): a claim that has a transaction id is resolved
 * from the coordinator's durable outcome, never guessed. Committed completes the claim, aborted
 * completes it (or releases it when the failure was retryable), and a transaction still in flight or
 * unknown leaves the claim in place, so a resend keeps answering 202 until the outcome is known.
 *
 * The receipt is not rebuilt for a settled claim: a resend of a settled document is absorbed (204),
 * and the sender can resend with a fresh id to be re-receipted idempotently.
 */
import type { AcceptedIdStore, SettleOutcome } from '@p2p-trust-stack/core/services/trust-tasks/boundary/accepted-store.js';
import { getAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';

export interface OutcomeSource {
  getOutcome(txId: string): Promise<string>;
}

export async function settleAcceptedClaims(store: AcceptedIdStore, manager: OutcomeSource): Promise<{ completed: number; released: number; pending: number }> {
  return store.settle(async (txId) => {
    const raw = await manager.getOutcome(txId);
    const outcome: SettleOutcome = raw === 'committed' || raw === 'aborted' || raw === 'inFlight' ? raw : 'unknown';
    return { outcome, retryable: getAbortReason(txId)?.retryable === true };
  });
}
