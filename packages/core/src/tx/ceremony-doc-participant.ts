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
 *   - when the quorum is met the injected effect is first CHECKED, at prepare (D1.3): a refusal there stores the
 *     ceremony as `failed` with its code and the closed reason (as the stored `error_reason`, so a later read reports
 *     the same thing) and the vote is `no`. The effect is APPLIED at commit, from the intent recorded in
 *     `tx_participant_state.pending_ops`, together with the approval that completed the quorum; an abort drops the
 *     intent and leaves nothing, a crash between apply and the status update is repaired by running the commit again
 *     (the effect is idempotent per ceremony id; `reconcile` re-drives prepared transactions after a restart).
 *
 * The effect is injected: the production establishment (name check, `createVtc`, fan-out) belongs to the
 * server that hosts the community; this participant only decides WHEN it is checked and applied and what the
 * ceremony records.
 *
 * Approvals (D1.1): a boundary approval is the proof of the whole co-sign document, verified by the pipeline
 * (signer equals issuer) before the handler runs. A host that relies on that sets `requireVerifiedApprovals`: an
 * approval that does not carry `verified: true` from the handler is refused, and every approval handed to the effect
 * is marked `verified`, so the governance guard does not re-verify it as a signature over the proposal hash.
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
  /** Set by the boundary handler: the document's actor was authenticated by the pipeline (verified proof or carrier). */
  verified?: boolean;
  nowMs: number;
}
export interface CeremonyApproveParams {
  ceremonyId: string;
  approverDid: string;
  /** The approver's proof value from the verified document (what they signed). */
  signature: string;
  /** The hash the approver names; when present it must equal the stored one. */
  proposalHash?: string;
  /** Set by the boundary handler: the document's actor was authenticated by the pipeline (verified proof or carrier). */
  verified?: boolean;
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
  /** `verified`: the approval was verified by the boundary (D1.1), so a guard must not re-verify it as a signature over the hash. */
  approvals: Array<{ approverDid: string; signature: string; verified: boolean }>;
}

/** What a begin names, handed to `checkProposal` before anything is stored. */
export interface CeremonyProposalInput {
  ceremonyId: string;
  proposerDid: string;
  name: string;
  kind: 'vtc' | 'vtn';
  adminDids: string[];
  threshold: number;
  parentCommunityDid: string | null;
}

/**
 * The effect of a met quorum, in two steps (D1.3). `check` runs at prepare and must be free of writes: throw a
 * `TaskError` to refuse (`nameTaken`, `policyDenied`, ...), or an `indeterminate` TaskError when the outcome cannot be
 * read. `apply` runs at commit and cannot veto: it must be idempotent per ceremony id, because a commit is re-run
 * after a crash. `checkProposal` (optional) refuses a begin before anything is stored (for example an unknown admin).
 */
export interface CeremonyEffect {
  checkProposal?(input: CeremonyProposalInput): Promise<void>;
  check(input: CeremonyEstablishment): Promise<void>;
  apply(input: CeremonyEstablishment): Promise<void>;
}

/** What prepare records for commit: one approval to record and, when it completes the quorum, the establishment. */
interface PendingApproval {
  kind: 'approve';
  ceremonyId: string;
  approverDid: string;
  signature: string;
  nowMs: number;
}

export interface CeremonyDocParticipantOptions {
  ttlMs?: number;
  /**
   * Count the begin document as the proposer's own approval (default false: every named admin, the proposer included, co-signs).
   * The proposer signed the proposal and is one of the named admins, so the begin can be read as their approval.
   */
  proposerApproves?: boolean;
  /** D1.1 for a host that relies on the pipeline-verified proof: approvals must come from the handler (`verified: true`). Default false. */
  requireVerifiedApprovals?: boolean;
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
  private readonly requireVerified: boolean;

  constructor(pid: string, txDb: DataSource, effect: CeremonyEffect, options: CeremonyDocParticipantOptions = {}) {
    this.pid = pid;
    this.txDb = txDb;
    this.store = new CeremonyStore(txDb);
    this.effect = effect;
    this.ttlMs = options.ttlMs ?? DEFAULT_CEREMONY_TTL_MS;
    this.proposerApproves = options.proposerApproves === true;
    this.requireVerified = options.requireVerifiedApprovals === true;
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
    const pending: PendingApproval[] = [];
    for (const op of operations) {
      try {
        if (op.op === CEREMONY_BEGIN) {
          const queued = await this.begin(op.params as unknown as CeremonyBeginParams);
          if (queued !== undefined) pending.push(queued);
        } else if (op.op === CEREMONY_APPROVE) {
          const queued = await this.approve(op.params as unknown as CeremonyApproveParams);
          if (queued !== undefined) pending.push(queued);
        } else if (op.op === CEREMONY_RESET) await this.reset(op.params as unknown as CeremonyResetParams);
        else if (op.op === CEREMONY_DENY) await this.deny(op.params as unknown as CeremonyDenyParams);
        else return 'no';
      } catch (err) {
        logger.error(`[ceremony-doc] refused for tx ${txId}, ${op.op}:`, (err as Error)?.message);
        // The 2PC vote carries no reason: the closed reason is kept for the boundary to read.
        recordAbortReason(txId, err);
        return 'no';
      }
    }
    // Durably record 'prepared' and what to apply BEFORE voting yes.
    await this.txDb.run(
      "INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome, pending_ops) VALUES (?, ?, 'prepared', ?)",
      txId, this.pid, pending.length === 0 ? null : JSON.stringify(pending),
    );
    return 'yes';
  }

  /**
   * Phase 2: record the approvals prepare queued and, when one completes the quorum, apply the effect and mark the
   * ceremony crystallized. Idempotent: a second commit of a committed transaction does nothing, a commit repeated after a
   * crash re-applies (the effect is idempotent per ceremony id). A failure that is not a refusal (the store or the effect
   * threw something else, or `indeterminate`) leaves the transaction `prepared` with its intent so the next commit,
   * `reconcile` or a repeated approval retries it.
   */
  async commit(txId: string): Promise<void> {
    const row = await this.txDb.get<{ outcome: string; pending_ops: string | null }>('SELECT outcome, pending_ops FROM tx_participant_state WHERE tx_id = ? AND pid = ?', txId, this.pid);
    if (row?.outcome === 'committed') return;
    if (row?.outcome === 'prepared' && row.pending_ops) {
      for (const op of JSON.parse(row.pending_ops) as PendingApproval[]) await this.applyApproval(op);
    }
    await this.txDb.run("UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?", txId, this.pid);
  }

  /** The decision was abort: the intent is dropped, nothing of it was applied. */
  async abort(txId: string): Promise<void> {
    await this.txDb.run("UPDATE tx_participant_state SET outcome = 'aborted', pending_ops = NULL WHERE tx_id = ? AND pid = ?", txId, this.pid);
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

  /**
   * Restart repair. For every transaction this participant prepared and never finished, ask the coordinator what was
   * decided (`getOutcome`) and finish it the same way: a committed decision applies the recorded intent, an aborted one
   * drops it, anything else is left alone. Run once at boot after the coordinator's own `recover()`. Returns what it did.
   */
  async reconcile(getOutcome: (txId: string) => Promise<'committed' | 'aborted' | 'inFlight' | 'unknown'>): Promise<{ committed: string[]; aborted: string[]; failed: string[] }> {
    const result = { committed: [] as string[], aborted: [] as string[], failed: [] as string[] };
    const rows = await this.txDb.all<{ tx_id: string }>("SELECT tx_id FROM tx_participant_state WHERE pid = ? AND outcome = 'prepared'", this.pid);
    for (const { tx_id: txId } of rows) {
      const decided = await getOutcome(txId);
      try {
        if (decided === 'committed') {
          await this.commit(txId);
          result.committed.push(txId);
        } else if (decided === 'aborted') {
          await this.abort(txId);
          result.aborted.push(txId);
        }
      } catch (err) {
        logger.error(`[ceremony-doc] reconcile of ${txId} failed:`, (err as Error)?.message);
        result.failed.push(txId);
      }
    }
    return result;
  }

  // ── operations ────────────────────────────────────────────────────

  /** Returns what to apply at commit (the proposer's own approval, when `proposerApproves`), or nothing. */
  private async begin(p: CeremonyBeginParams): Promise<PendingApproval | undefined> {
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
      if (same) return undefined;
      throw new TaskError({ code: 'idConflict', retryable: false, internalMessage: `ceremony ${p.ceremonyId} already exists with different content` });
    }
    // A host refuses what it can never establish (an admin it does not know) before anything is stored.
    await this.effect.checkProposal?.({ ceremonyId: p.ceremonyId, proposerDid: p.proposerDid, name: p.name, kind, adminDids: p.adminDids, threshold: p.threshold, parentCommunityDid: parent });
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
    if (!this.proposerApproves) return undefined;
    this.requireProof(p.verified);
    const created = (await this.store.getProposal(p.ceremonyId))!;
    const own: PendingApproval = { kind: 'approve', ceremonyId: p.ceremonyId, approverDid: p.proposerDid, signature: p.signature ?? '', nowMs: p.nowMs };
    // A single-admin ceremony is complete with this approval: its effect is checked now, applied at commit.
    if (declaredAdmins(created).size <= 1) await this.checkQuorum(created, [{ approverDid: p.proposerDid, signature: own.signature }]);
    return own;
  }

  /** The D1.1 rule of a host that relies on the pipeline-verified proof. */
  private requireProof(verified: boolean | undefined): void {
    if (this.requireVerified && verified !== true) {
      throw taskErrorForReason('notFoundOrNotPermitted', { internalMessage: 'the approval was not verified by the boundary' });
    }
  }

  /** Returns what to apply at commit: the approval to record, and with it the effect when it completes the quorum. */
  private async approve(p: CeremonyApproveParams): Promise<PendingApproval | undefined> {
    if (!p?.ceremonyId || !p.approverDid) throw new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: 'incomplete ceremony_approve' });
    const stored = await this.store.getProposal(p.ceremonyId);
    // Unknown ceremony and ineligible approver are one answer.
    if (!stored || !declaredAdmins(stored).has(p.approverDid)) {
      throw taskErrorForReason('notFoundOrNotPermitted', { internalMessage: 'unknown ceremony or approver is not an admin' });
    }
    this.requireProof(p.verified);
    const intent: PendingApproval = { kind: 'approve', ceremonyId: p.ceremonyId, approverDid: p.approverDid, signature: p.signature, nowMs: p.nowMs };
    const prior = await this.store.getApprovals(p.ceremonyId);
    // Repeating an approval is a no-op while the ceremony is open or committed.
    if (prior.some((a) => a.approverDid === p.approverDid) && (stored.status === 'crystallized' || (stored.status === 'pending' && !isLapsed(stored, p.nowMs)))) {
      // A met quorum whose effect did not finish (outcome unknown, or the commit did not complete) is retried by the repeat; anything else is a no-op.
      if (stored.status === 'pending' && new Set(prior.map((a) => a.approverDid)).size >= Math.max(declaredAdmins(stored).size, 1)) {
        await this.checkQuorum(stored, prior.map((a) => ({ approverDid: a.approverDid, signature: a.signature })));
        return intent;
      }
      return undefined;
    }

    const proposal = await closeIfLapsed(this.store, stored, p.nowMs);
    assertOpen(proposal, p.nowMs);
    if (p.proposalHash !== undefined && p.proposalHash !== proposal.proposalHash) {
      throw new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: 'the approval names a different proposal hash' });
    }
    const prospective = [...prior.map((a) => ({ approverDid: a.approverDid, signature: a.signature })), { approverDid: p.approverDid, signature: p.signature }];
    const needed = Math.max(declaredAdmins(proposal).size, 1);
    if (new Set(prospective.map((a) => a.approverDid)).size >= needed) {
      try {
        await this.checkQuorum(proposal, prospective);
      } catch (err) {
        // The admin did approve: that fact is the ceremony's own record and stays (a refusal or an unreadable outcome does not
        // undo it, and a repeat of an unreadable one retries). Only the effect is held back.
        await this.store.recordApproval(p.ceremonyId, p.approverDid, p.signature);
        throw err;
      }
    }
    return intent;
  }

  /** The prepare half of the effect (no writes besides the ceremony's own failure record): a refusal fails the ceremony and throws. */
  private async checkQuorum(proposal: CeremonyProposal, approvals: Array<{ approverDid: string; signature: string }>): Promise<void> {
    try {
      await this.effect.check(this.establishment(proposal, approvals));
    } catch (err) {
      // An effect whose outcome cannot be read is neither a success nor a refusal: the ceremony stays pending (nothing is
      // recorded as failed), the transaction aborts with `indeterminate` and a repeated approval retries the effect.
      if (err instanceof TaskError && err.code === 'indeterminate') throw err;
      const why = describeFailure(err);
      // The stored reason is the closed vocabulary key when there is one (never free text), so a later read says the same.
      await this.store.markFailed(proposal.proposalId, why.reason ?? 'effectFailed', why.code, why.retryable);
      throw err;
    }
  }

  private establishment(proposal: CeremonyProposal, approvals: Array<{ approverDid: string; signature: string }>): CeremonyEstablishment {
    return {
      ceremonyId: proposal.proposalId,
      name: proposal.name,
      kind: proposal.kind,
      adminDids: proposal.adminDids,
      threshold: proposal.threshold,
      parentCommunityDid: proposal.parentCommunityDid,
      approvals: approvals.map((a) => ({ ...a, verified: this.requireVerified })),
    };
  }

  /** The commit half: record the approval, and when the quorum is met apply the effect and mark the ceremony crystallized. */
  private async applyApproval(op: PendingApproval): Promise<void> {
    await this.store.recordApproval(op.ceremonyId, op.approverDid, op.signature);
    const proposal = await this.store.getProposal(op.ceremonyId);
    if (proposal === null || proposal.status !== 'pending') return;
    const approvals = await this.store.getApprovals(op.ceremonyId);
    if (new Set(approvals.map((a) => a.approverDid)).size < Math.max(declaredAdmins(proposal).size, 1)) return;
    try {
      await this.effect.apply(this.establishment(proposal, approvals.map((a) => ({ approverDid: a.approverDid, signature: a.signature }))));
    } catch (err) {
      // Commit cannot veto. A refusal that slipped past the check (a race since prepare) is recorded as the ceremony's failure, truthfully,
      // and the transaction still finishes; anything else (indeterminate, an unreadable store) leaves the commit to be re-run.
      if (err instanceof TaskError && err.code !== 'indeterminate') {
        const why = describeFailure(err);
        await this.store.markFailed(op.ceremonyId, why.reason ?? 'effectFailed', why.code, why.retryable);
        return;
      }
      throw err;
    }
    await this.store.updateStatus(op.ceremonyId, 'crystallized', op.nowMs);
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
