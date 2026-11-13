// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CeremonyCoordinator — server-side orchestrator for multi-admin VTC/VTN
 * founding ceremonies (Phase 3).
 *
 * Three stages: proposal → approval collection → crystallization.
 * Admins are added via addAdminDid() before crystallization; crystallization
 * occurs when the M-of-N threshold is met and all TOIP governance rules pass.
 */

import { randomUUID } from 'node:crypto';
import { sha256 } from '../crypto/primitives.js';
import { CeremonyStore } from './ceremony-store.js';
import { assertOpen, closeIfLapsed, isLapsed } from './ceremony-guard.js';
import { GovernanceGuard } from '../services/governance-guard.js';
import type { DataSource } from '../db/data-source.js';
import type { TransactionManager } from './manager.js';
import { logger } from '../util/logger.js';

const DEFAULT_PROPOSAL_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface InitiateProposalInput {
  name: string;
  kind: 'vtc' | 'vtn';
  adminDids: string[];
  threshold: number;
  proposerDid: string;
  parentCommunityDid?: string;
  ttlMs?: number;
}

export interface CeremonyCoordinatorDeps {
  store: CeremonyStore;
  guard: GovernanceGuard;
  manager: TransactionManager;
  appDb: DataSource;
}
export class CeremonyCoordinator {
  private readonly store: CeremonyStore;
  private readonly guard: GovernanceGuard;
  private readonly appDb: DataSource;

  constructor(deps: CeremonyCoordinatorDeps) {
    this.store = deps.store;
    this.guard = deps.guard;
    this.appDb = deps.appDb;
  }

  // ═══════════════════════════════════════════════════════════════
  // Stage 1 — Proposal Initiation
  // ═══════════════════════════════════════════════════════════════

  async initiateProposal(input: InitiateProposalInput): Promise<string> {
    const proposalId = randomUUID();
    const vtcDid = `did:p2pts:community:${input.kind === 'vtn' ? 'vtn' : 'vtc'}:${proposalId.slice(0, 12)}`;
    const now = Date.now();
    const expiresAt = now + (input.ttlMs ?? DEFAULT_PROPOSAL_TTL_MS);

    // Canonical proposal hash — what admins sign
    const canonical = JSON.stringify({
      proposalId, vtcDid, name: input.name, kind: input.kind,
      adminDids: [...input.adminDids].sort(), threshold: input.threshold,
      proposerDid: input.proposerDid, expiresAt,
      parentCommunityDid: input.parentCommunityDid ?? null,
    });
    const proposalHash = Buffer.from(sha256(new TextEncoder().encode(canonical))).toString('base64');

    await this.store.createProposal({
      proposalId, proposerDid: input.proposerDid, vtcDid,
      name: input.name, kind: input.kind,
      adminDids: input.adminDids, threshold: input.threshold,
      expiresAt, proposalHash,
      parentCommunityDid: input.parentCommunityDid ?? null,
    });

    logger.info(`[ceremony] proposal ${proposalId.slice(0, 8)}: ${input.name} (${input.kind}, threshold=${input.threshold})`);
    return proposalId;
  }

  // ═══════════════════════════════════════════════════════════════
  // Stage 2 — Approval Collection
  // ═══════════════════════════════════════════════════════════════

  async recordApproval(
    proposalId: string, approverDid: string, signature: string,
  ): Promise<{ recorded: boolean; crystallized: boolean; approvalCount: number }> {
    const proposal = await this.store.getProposal(proposalId);
    if (!proposal) throw new Error(`proposal ${proposalId} not found`);

    // A repeated approval by the same approver is idempotent (also after the proposal committed):
    // no second row, no error, the current count.
    const prior = await this.store.getApprovals(proposalId);
    const idempotentState = proposal.status === 'crystallized'
      || (proposal.status === 'pending' && !isLapsed(proposal));
    if (idempotentState && prior.some((a) => a.approverDid === approverDid)) {
      return { recorded: false, crystallized: proposal.status === 'crystallized', approvalCount: prior.length };
    }

    // One clock and one rule for "still open" (deadline reached counts as lapsed); a late approval
    // flips the stored status to `expired` before it is refused.
    assertOpen(await closeIfLapsed(this.store, proposal));

    const recorded = await this.store.recordApproval(proposalId, approverDid, signature);
    const count = await this.store.countApprovals(proposalId);

    let crystallized = false;
    if (await this.store.isCrystallizable(proposalId)) {
      await this.crystallize(proposalId);
      crystallized = true;
    }

    return { recorded, crystallized, approvalCount: count };
  }

  // ═══════════════════════════════════════════════════════════════
  // Admin management
  // ═══════════════════════════════════════════════════════════════

  async addAdmin(proposalId: string, adminDid: string): Promise<void> {
    const proposal = await this.store.getProposal(proposalId);
    if (!proposal) throw new Error(`proposal ${proposalId} not found`);
    assertOpen(await closeIfLapsed(this.store, proposal));
    await this.store.addAdminDid(proposalId, adminDid);
  }

  // ═══════════════════════════════════════════════════════════════
  // Stage 3 — Crystallization
  // ═══════════════════════════════════════════════════════════════

  private async crystallize(proposalId: string): Promise<void> {
    const proposal = await this.store.getProposal(proposalId);
    if (!proposal) throw new Error(`proposal ${proposalId} not found`);
    assertOpen(await closeIfLapsed(this.store, proposal));
    const approvals = await this.store.getApprovals(proposalId);

    // Full governance validation. `reason` now carries the `requireConsent` requirement
    // when a ceremony has too few valid approvals (e.g. "… — needs threshold_m
    // approval(s) from 'community-admins'"), so the thrown error says what would
    // satisfy the quorum rather than only that it was refused.
    const result = await this.guard.validateCrystallization(proposal, approvals);
    if (!result.allowed) {
      await this.store.markFailed(proposalId, `crystallization denied: ${result.reason}`, 'permissionDenied', false);
      throw new Error(`crystallization denied: ${result.reason}`);
    }
    const parentCheck = await this.guard.validateParentVtnPolicy(
      proposal.parentCommunityDid, proposal.kind);
    if (!parentCheck.allowed) {
      await this.store.markFailed(proposalId, `parent VTN policy denied: ${parentCheck.reason}`, 'permissionDenied', false);
      throw new Error(`parent VTN policy denied: ${parentCheck.reason}`);
    }

    // Resolve admin DIDs → identity UUIDs
    if (proposal.adminDids.length === 0) throw new Error('no admin DIDs');
    const placeholders = proposal.adminDids.map(() => '?').join(',');
    const adminRows = await this.appDb.all<{ uuid: string }>(
      `SELECT i.uuid FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid
        WHERE d.did IN (${placeholders})`, ...proposal.adminDids);
    const adminIdentityUuids = adminRows.map(r => r.uuid);

    // Use createVtc — its own gates (min 2 admins for VTC, threshold >= 2) apply here
    const { createVtc } = await import('../services/vtc.js');
    let parentUuid: string | undefined;
    if (proposal.parentCommunityDid) {
      const p = await this.appDb.get<{ uuid: string }>(
        `SELECT i.uuid FROM identities i JOIN did_documents d ON d.identity_uuid = i.uuid
          WHERE d.did = ?`, proposal.parentCommunityDid);
      parentUuid = p?.uuid;
    }
    await createVtc(this.appDb, {
      name: proposal.name, kind: proposal.kind,
      adminIdentityUuids, threshold: proposal.threshold,
      parentCommunityUuid: parentUuid,
    });

    await this.store.updateStatus(proposalId, 'crystallized', Date.now());
    logger.info(`[ceremony] ${proposalId.slice(0, 8)}: crystallized → VTC created`);
  }

  // ═══════════════════════════════════════════════════════════════
  // Query helpers
  // ═══════════════════════════════════════════════════════════════

  async getProposal(proposalId: string) {
    const proposal = await this.store.getProposal(proposalId);
    if (!proposal) return null;
    const approvals = await this.store.getApprovals(proposalId);
    const crystallizable = await this.store.isCrystallizable(proposalId);
    return { proposal, approvals, crystallizable };
  }

  async listPending() { return this.store.listPending(); }
}
