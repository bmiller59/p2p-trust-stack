// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CeremonyDocParticipant: transaction participant behind the `ceremony-doc` boundary handler
 * (conformance phase P8c). Operations `ceremony_begin`, `ceremony_approve` and `ceremony_reset` over
 * the existing `CeremonyStore` and the ceremony guards (`closeIfLapsed`, `assertOpen`,
 * `assertResettable`); every refusal is recorded in the abort-reason registry before the `no` vote so
 * the boundary can put the closed reason on the wire.
 *
 * Rules (the same as the utility server's ceremony participant, which hosts the production founding):
 *   - identities are DIDs: the proposer must be one of the named admins, and the admin set is the
 *     co-signature quorum (every named admin accepts the role; the proposer approving alone is not a trigger);
 *   - one clock: `nowMs` arrives with every operation and drives the deadline (`>=` is lapsed);
 *   - an approver who is not an admin and a ceremony that does not exist get the same refusal
 *     (`notFoundOrNotPermitted`), decided before anything about the ceremony's state is revealed;
 *   - a repeated approval by the same admin is a no-op (also after commit); a first approval after
 *     commit is `alreadyCommitted`; a late approval flips the ceremony to `expired` and is refused;
 *   - begin with an existing id and the same content returns the existing state, other content is `idConflict`;
 *   - reset only from failed or expired; a crystallized ceremony is never reset (`alreadyCommitted`);
 *   - when the quorum is met the injected effect runs; a refusal there stores the ceremony as `failed` with
 *     its code and the closed reason (as the stored `error_reason`), so a later read reports the same thing.
 *
 * The effect is injected: the production establishment (name check, `createVtc`, fan-out) belongs to the
 * server that hosts the community; this participant only decides WHEN it runs and what the ceremony records.
 */
import { createHash } from 'node:crypto';
import { TaskError, taskErrorForReason } from '../services/trust-tasks/boundary/errors.js';
import type { DataSource } from '../db/data-source.js';
import { CeremonyStore } from './ceremony-store.js';
import type { CeremonyProposal } from './ceremony-store.js';
import { assertOpen, assertResettable, closeIfLapsed, describeFailure, isLapsed, recordAbortReason } from './ceremony-guard.js';
import type { Operation, Outcome, Participant, Vote } from './types.js';
import { logger } from '../util/logger.js';

export const CEREMONY_BEGIN = 'ceremony_begin';
export const CEREMONY_APPROVE = 'ceremony_approve';
export const CEREMONY_RESET = 'ceremony_reset';
/** A denial (`task-consent/decision` with `deny`): closes the pending ceremony for every approver. */
export const CEREMONY_DENY = 'ceremony_deny';

export const DEFAULT_CEREMONY_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface CeremonyBeginParams {
  ceremonyId: string;
  proposerDid: string;
  name: string;
  kind: 'vtc' | 'vtn';
  threshold: number;
  adminDids: string[];
  parentCommunityDid?: string | null;
  /** The proposer's proof value from the verified begin document; recorded as their approval when the participant counts the begin. */
  signature?: string;
  nowMs: number;
}
export interface CeremonyApproveParams {
  ceremonyId: string;
  approverDid: string;
  /** The approver's proof value from the verified document (what they signed). */
  signature: string;
  /** The hash the approver names; when present it must equal the stored one. */
  proposalHash?: string;
  nowMs: number;
}
export interface CeremonyDenyParams {
  ceremonyId: string;
  approverDid: string;
  nowMs: number;
}
export interface CeremonyResetParams {
  ceremonyId: string;
  actorDid: string;
  nowMs: number;
}

/** What the quorum establishes. */
export interface CeremonyEstablishment {
  ceremonyId: string;
  name: string;
  kind: 'vtc' | 'vtn';
  adminDids: string[];
  threshold: number;
  parentCommunityDid: string | null;
  approvals: Array<{ approverDid: string; signature: string }>;
}

/** The effect of a met quorum. Throw a `TaskError` to refuse (for example `nameTaken`); it must be idempotent per ceremony id. */
export interface CeremonyEffect {
  establish(input: CeremonyEstablishment): Promise<void>;
}

export interface CeremonyDocParticipantOptions {
  ttlMs?: number;
  /**
   * Count the begin document as the proposer's own approval (default false: every named admin, the proposer included, co-signs).
   * The proposer signed the proposal and is one of the named admins, so the begin can be read as their approval.
   */
  proposerApproves?: boolean;
}

/** Everyone who may act on a ceremony: the named admins and the proposer. */
export function declaredAdmins(p: Pick<CeremonyProposal, 'adminDids' | 'proposerDid'>): Set<string> {
  return new Set<string>([...p.adminDids, p.proposerDid]);
}

const sameSet = (a: readonly string[], b: readonly string[]): boolean => JSON.stringify([...new Set(a)].sort()) === JSON.stringify([...new Set(b)].sort());

export class CeremonyDocParticipant implements Participant {
  readonly pid: string;
  readonly store: CeremonyStore;
  private readonly txDb: DataSource;
  private readonly effect: CeremonyEffect;
  private ttlMs: number;
  private readonly proposerApproves: boolean;

  constructor(pid: string, txDb: DataSource, effect: CeremonyEffect, options: CeremonyDocParticipantOptions = {}) {
    this.pid = pid;
    this.txDb = txDb;
    this.store = new CeremonyStore(txDb);
    this.effect = effect;
    this.ttlMs = options.ttlMs ?? DEFAULT_CEREMONY_TTL_MS;
    this.proposerApproves = options.proposerApproves === true;
  }

  /** The approval window of ceremonies begun from now on (milliseconds); a running ceremony keeps the deadline it was begun with. */
  setTtlMs(ms: number): void {
    if (!Number.isFinite(ms) || ms < 1) throw new RangeError('ttlMs must be a positive number of milliseconds');
    this.ttlMs = ms;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === CEREMONY_BEGIN || op.op === CEREMONY_APPROVE || op.op === CEREMONY_RESET || op.op === CEREMONY_DENY;
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      try {
        if (op.op === CEREMONY_BEGIN) await this.begin(op.params as unknown as CeremonyBeginParams);
        else if (op.op === CEREMONY_APPROVE) await this.approve(op.params as unknown as CeremonyApproveParams);
        else if (op.op === CEREMONY_RESET) await this.reset(op.params as unknown as CeremonyResetParams);
        else if (op.op === CEREMONY_DENY) await this.deny(op.params as unknown as CeremonyDenyParams);
        else return 'no';
      } catch (err) {
        logger.error(`[ceremony-doc] refused for tx ${txId}, ${op.op}:`, (err as Error)?.message);
        // The 2PC vote carries no reason: the closed reason is kept for the boundary to read.
        recordAbortReason(txId, err);
        return 'no';
      }
    }
    await this.txDb.run("INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome) VALUES (?, ?, 'prepared')", txId, this.pid);
    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run("UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?", txId, this.pid);
  }

  async abort(txId: string): Promise<void> {
    await this.txDb.run("UPDATE tx_participant_state SET outcome = 'aborted' WHERE tx_id = ? AND pid = ?", txId, this.pid);
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>('SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?', txId, this.pid);
    return (row?.outcome as Outcome) ?? 'unknown';
  }

  async query(op: string): Promise<unknown> {
    throw new Error(`CeremonyDocParticipant does not support query: ${op}`);
  }

  // ── operations ────────────────────────────────────────────────────

  private async begin(p: CeremonyBeginParams): Promise<void> {
    if (!p?.ceremonyId || !p.proposerDid || !p.name || !Array.isArray(p.adminDids) || p.adminDids.length === 0) {
      throw new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: 'incomplete ceremony_begin' });
    }
    if (!p.adminDids.includes(p.proposerDid)) {
      throw taskErrorForReason('notAdmin', { internalMessage: 'the proposer is not one of the named admins' });
    }
    const kind = p.kind;
    const parent = p.parentCommunityDid ?? null;
    const existing = await this.store.getProposal(p.ceremonyId);
    if (existing) {
      // Who may learn anything about an existing ceremony is decided first.
      if (!declaredAdmins(existing).has(p.proposerDid)) {
        throw taskErrorForReason('notFoundOrNotPermitted', { internalMessage: 'a ceremony with this id exists and the caller is not on it' });
      }
      const same = existing.name === p.name && existing.kind === kind && existing.threshold === p.threshold
        && existing.proposerDid === p.proposerDid && existing.parentCommunityDid === parent && sameSet(existing.adminDids, p.adminDids);
      if (same) return;
      throw new TaskError({ code: 'idConflict', retryable: false, internalMessage: `ceremony ${p.ceremonyId} already exists with different content` });
    }
    const expiresAt = p.nowMs + this.ttlMs;
    const canonical = JSON.stringify({
      ceremonyId: p.ceremonyId, name: p.name, kind, adminDids: [...p.adminDids].sort(), threshold: p.threshold,
      proposerDid: p.proposerDid, parentCommunityDid: parent, expiresAt,
    });
    await this.store.createProposal({
      proposalId: p.ceremonyId,
      proposerDid: p.proposerDid,
      vtcDid: `did:p2pts:ceremony:${p.ceremonyId.replace(/[^A-Za-z0-9]/g, '').slice(0, 12) || 'x'}`,
      name: p.name,
      kind,
      adminDids: p.adminDids,
      threshold: p.threshold,
      expiresAt,
      proposalHash: createHash('sha256').update(canonical).digest('base64'),
      parentCommunityDid: parent,
    });
    if (this.proposerApproves) {
      await this.store.recordApproval(p.ceremonyId, p.proposerDid, p.signature ?? '');
      const created = (await this.store.getProposal(p.ceremonyId))!;
      if (new Set(declaredAdmins(created)).size <= 1) await this.crystallize(created, [{ approverDid: p.proposerDid, signature: p.signature ?? '' }], p.nowMs);
    }
  }

  private async approve(p: CeremonyApproveParams): Promise<void> {
    if (!p?.ceremonyId || !p.approverDid) throw new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: 'incomplete ceremony_approve' });
    const stored = await this.store.getProposal(p.ceremonyId);
    // Unknown ceremony and ineligible approver are one answer.
    if (!stored || !declaredAdmins(stored).has(p.approverDid)) {
      throw taskErrorForReason('notFoundOrNotPermitted', { internalMessage: 'unknown ceremony or approver is not an admin' });
    }
    const prior = await this.store.getApprovals(p.ceremonyId);
    // Repeating an approval is a no-op while the ceremony is open or committed.
    if (prior.some((a) => a.approverDid === p.approverDid) && (stored.status === 'crystallized' || (stored.status === 'pending' && !isLapsed(stored, p.nowMs)))) {
      // A met quorum whose effect outcome was unknown (left pending) is retried by the repeat; anything else is a no-op.
      if (stored.status === 'pending' && new Set(prior.map((a) => a.approverDid)).size >= Math.max(declaredAdmins(stored).size, 1)) {
        await this.crystallize(stored, prior.map((a) => ({ approverDid: a.approverDid, signature: a.signature })), p.nowMs);
      }
      return;
    }

    const proposal = await closeIfLapsed(this.store, stored, p.nowMs);
    assertOpen(proposal, p.nowMs);
    if (p.proposalHash !== undefined && p.proposalHash !== proposal.proposalHash) {
      throw new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: 'the approval names a different proposal hash' });
    }
    await this.store.recordApproval(p.ceremonyId, p.approverDid, p.signature);
    const approvals = await this.store.getApprovals(p.ceremonyId);
    const needed = Math.max(declaredAdmins(proposal).size, 1);
    if (new Set(approvals.map((a) => a.approverDid)).size < needed) return;
    await this.crystallize(proposal, approvals.map((a) => ({ approverDid: a.approverDid, signature: a.signature })), p.nowMs);
  }

  private async crystallize(proposal: CeremonyProposal, approvals: CeremonyEstablishment['approvals'], nowMs: number): Promise<void> {
    try {
      await this.effect.establish({
        ceremonyId: proposal.proposalId,
        name: proposal.name,
        kind: proposal.kind,
        adminDids: proposal.adminDids,
        threshold: proposal.threshold,
        parentCommunityDid: proposal.parentCommunityDid,
        approvals,
      });
    } catch (err) {
      // An effect whose outcome cannot be read is neither a success nor a refusal: the ceremony stays pending (nothing is
      // recorded as failed), the transaction aborts with `indeterminate` and a repeated approval retries the effect.
      if (err instanceof TaskError && err.code === 'indeterminate') throw err;
      const why = describeFailure(err);
      // The stored reason is the closed vocabulary key when there is one (never free text), so a later read says the same.
      await this.store.markFailed(proposal.proposalId, why.reason ?? 'effectFailed', why.code, why.retryable);
      throw err;
    }
    await this.store.updateStatus(proposal.proposalId, 'crystallized', nowMs);
  }

  /**
   * A denial closes the pending ceremony (stored `aborted`; an aborted ceremony is not resettable). Same eligibility
   * rule as an approval (an unknown ceremony and a non-admin are one answer); a repeat is a no-op; after commit it is
   * `alreadyCommitted`; a lapsed ceremony is `deadlineLapsed`.
   */
  private async deny(p: CeremonyDenyParams): Promise<void> {
    if (!p?.ceremonyId || !p.approverDid) throw new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: 'incomplete ceremony_deny' });
    const stored = await this.store.getProposal(p.ceremonyId);
    if (!stored || !declaredAdmins(stored).has(p.approverDid)) {
      throw taskErrorForReason('notFoundOrNotPermitted', { internalMessage: 'unknown ceremony or approver is not an admin' });
    }
    const proposal = await closeIfLapsed(this.store, stored, p.nowMs);
    if (proposal.status === 'aborted') return;
    assertOpen(proposal, p.nowMs);
    await this.store.updateStatus(p.ceremonyId, 'aborted');
  }

  private async reset(p: CeremonyResetParams): Promise<void> {
    if (!p?.ceremonyId || !p.actorDid) throw new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: 'incomplete ceremony_reset' });
    const stored = await this.store.getProposal(p.ceremonyId);
    if (!stored || !declaredAdmins(stored).has(p.actorDid)) {
      throw taskErrorForReason('notFoundOrNotPermitted', { internalMessage: 'unknown ceremony or caller is not an admin' });
    }
    assertResettable(await closeIfLapsed(this.store, stored, p.nowMs));
    await this.store.updateStatus(p.ceremonyId, 'aborted');
  }
}
