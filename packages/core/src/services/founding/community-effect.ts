// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CommunityFoundingEffect: the real `CeremonyEffect` of the boundary ceremony host (item 1, decisions D1.1 to D1.3).
 * It is what a met quorum of `ceremony:propose` / `ceremony:co-sign` documents establishes: a community (VTC or VTN)
 * with its founding admins, their founding VMCs and the trust-task records of the establishment, through the same
 * steps and rules as the legacy REST/TSP ceremony participant.
 *
 *   checkProposal (begin)  every named admin DID maps to an identity the server holds; refused before anything is stored.
 *   check (prepare)        no writes. Name available, the parent VTN's policy, the crystallization policy over the approvals
 *                          (D1.1: boundary approvals are pre-verified, so the guard does not re-verify them as signatures
 *                          over the hash; anything not marked verified still is), and `checkCreateVtc` (human VTA, active
 *                          endpoint, mutual VRC, threshold). Refusals are TaskErrors with the closed reason.
 *   apply (commit)         the atomic `vtc-establish` drive (`createVtc`, founding VMCs and every trust-task record in ONE
 *                          database transaction), then the post-commit fan-out hook. Idempotent per ceremony id: an
 *                          establishment already recorded under the ceremony's thread is returned, not created again.
 *
 * The utility server supplies the fan-out (`afterEstablished`, queue-backed and retriable); this class does not know the
 * delivery queue. Stub identities (endpoint-less did:peer:4 rows of the TSP bridge) are mapped to the real VTA that
 * shares their DID or key, exactly as the legacy participant does (`resolveFoundingAdminUuid`).
 */
import type { DataSource } from '../../db/data-source.js';
import * as identitiesRepo from '../../db/repositories/identities-repo.js';
import * as membershipsRepo from '../../db/repositories/memberships-repo.js';
import type { MembershipRow } from '../../db/repositories/memberships-repo.js';
import * as trustTasksRepo from '../../db/repositories/trust-tasks-repo.js';
import { TaskError, taskErrorForReason } from '../trust-tasks/boundary/errors.js';
import { driveAtomically, driveCeremony } from '../trust-tasks/driver.js';
import { VTC_ESTABLISH_TYPE } from '../trust-tasks/type-uris.js';
import { GovernanceGuard } from '../governance-guard.js';
import { createPolicyEngine } from '../policy-engine-config.js';
import {
  checkCommunityNameAvailable, checkCreateVtc, CreateVtcConflictError, CreateVtcNotFoundError, CreateVtcValidationError,
} from '../vtc.js';
import type { CreateVtcInput, CreateVtcResult } from '../vtc.js';
import type { CeremonyEffect, CeremonyEstablishment, CeremonyProposalInput } from '../../tx/ceremony-doc-participant.js';
import { logger } from '../../util/logger.js';
import { registerFoundingExecutors } from './executors.js';
import { resolveFoundingAdminUuids } from './admin-resolution.js';

/** What the post-commit fan-out needs. */
export interface EstablishedCommunity {
  ceremonyId: string;
  communityUuid: string;
  foundingAdmins: MembershipRow[];
  /** True when the community already existed (a commit re-run after a crash), so the hook may have run before. */
  replayed: boolean;
}

export interface CommunityFoundingEffectOptions {
  /** Post-commit fan-out (queue-backed, retriable). A failure is logged and never fails the commit. */
  afterEstablished?: (community: EstablishedCommunity) => Promise<void>;
  /** The guard; default one over `appDb` with the configured policy engine. */
  guard?: GovernanceGuard;
}

export class CommunityFoundingEffect implements CeremonyEffect {
  private readonly db: DataSource;
  private readonly guard: GovernanceGuard;
  private readonly afterEstablished: ((community: EstablishedCommunity) => Promise<void>) | undefined;

  constructor(appDb: DataSource, options: CommunityFoundingEffectOptions = {}) {
    this.db = appDb;
    this.guard = options.guard ?? new GovernanceGuard(appDb, createPolicyEngine());
    this.afterEstablished = options.afterEstablished;
    registerFoundingExecutors();
  }

  async checkProposal(input: CeremonyProposalInput): Promise<void> {
    const named = await resolveFoundingAdminUuids(this.db, input.adminDids);
    if (named.unknown.length > 0) {
      throw taskErrorForReason('notFound', { internalMessage: `no identity for admin ${named.unknown.join(', ')}` });
    }
  }

  async check(input: CeremonyEstablishment): Promise<void> {
    // A ceremony this server already established (a retry after a crash) has nothing left to check.
    if ((await this.findEstablished(input.ceremonyId)) !== null) return;

    const avail = await checkCommunityNameAvailable(this.db, input.name);
    if (!avail.available) throw taskErrorForReason('nameTaken', { internalMessage: avail.message });

    // The parent VTN's own policy governs which child kinds it accepts. Allows when there is no parent or it is not a VTN.
    const parentCheck = await this.guard.validateParentVtnPolicy(input.parentCommunityDid, input.kind);
    if (!parentCheck.allowed) throw taskErrorForReason('policyDenied', { internalMessage: `parent VTN policy denied: ${parentCheck.reason}` });

    const createInput = await this.createInput(input);

    // The crystallization policy (D1.1). The approvals the boundary verified are pre-verified; the rest are verified as signatures.
    const preVerified = new Set(input.approvals.filter((a) => a.verified).map((a) => a.approverDid));
    const decision = await this.guard.validateCrystallization(
      { ...proposalOf(input) },
      input.approvals.map((a, i) => ({ approvalId: `${input.ceremonyId}:${i}`, proposalId: input.ceremonyId, approverDid: a.approverDid, signature: a.signature, receivedAt: 0 })),
      { preVerified },
    );
    if (!decision.allowed) {
      if (decision.indeterminate === true) throw new TaskError({ code: 'indeterminate', retryable: true, internalMessage: `crystallization could not be decided: ${decision.reason ?? 'policy'}` });
      throw taskErrorForReason('policyDenied', { internalMessage: `crystallization denied: ${decision.reason ?? 'policy'}` });
    }

    try {
      await checkCreateVtc(this.db, createInput);
    } catch (err) {
      throw refusalOf(err);
    }
  }

  async apply(input: CeremonyEstablishment): Promise<void> {
    const existing = await this.findEstablished(input.ceremonyId);
    if (existing !== null) {
      await this.fanOut({ ceremonyId: input.ceremonyId, communityUuid: existing, foundingAdmins: await this.foundingAdminsOf(existing), replayed: true });
      return;
    }
    const createInput = await this.createInput(input);
    let result: CreateVtcResult;
    try {
      result = await driveAtomically(this.db, input.ceremonyId, async (tx) => {
        const drive = await driveCeremony(tx, 'vtc-establish', input.ceremonyId, {
          context: {
            db: tx,
            name: createInput.name,
            kind: createInput.kind,
            adminIdentityUuids: createInput.adminIdentityUuids,
            threshold: createInput.threshold,
            parentCommunityUuid: createInput.parentCommunityUuid,
          },
        });
        if (!drive.completed) throw new Error(`ceremony 'vtc-establish' halted at ${drive.haltedAt}${drive.haltReason ? `: ${drive.haltReason}` : ''}`);
        return drive.outputs[VTC_ESTABLISH_TYPE] as CreateVtcResult;
      });
    } catch (err) {
      // A refusal that appeared since the check (a name taken in between) is a refusal; anything else is left to be retried.
      throw refusalOf(err, true);
    }
    await this.fanOut({ ceremonyId: input.ceremonyId, communityUuid: result.identity.uuid, foundingAdmins: result.foundingAdmins, replayed: false });
  }

  // ── internals ────────────────────────────────────────────────────

  private async createInput(input: CeremonyEstablishment): Promise<CreateVtcInput & { name: string; kind: 'vtc' | 'vtn'; threshold: number }> {
    const named = await resolveFoundingAdminUuids(this.db, input.adminDids);
    if (named.unknown.length > 0) throw taskErrorForReason('notFound', { internalMessage: `no identity for admin ${named.unknown.join(', ')}` });
    let parentCommunityUuid: string | undefined;
    if (input.parentCommunityDid !== null) {
      const parent = await identitiesRepo.findByRealDid(this.db, input.parentCommunityDid);
      if (parent === null) throw taskErrorForReason('notFound', { internalMessage: 'the parent community is not hosted here' });
      parentCommunityUuid = parent.uuid;
    }
    return {
      name: input.name,
      kind: input.kind,
      adminIdentityUuids: named.adminUuids,
      threshold: input.threshold,
      ...(parentCommunityUuid === undefined ? {} : { parentCommunityUuid }),
    };
  }

  /** The community this ceremony already established: the completed `vtc-establish` response recorded under its thread, written in the same transaction as the community. */
  private async findEstablished(ceremonyId: string): Promise<string | null> {
    const rows = await trustTasksRepo.listByThread(this.db, ceremonyId);
    for (const row of rows) {
      if (row.type !== VTC_ESTABLISH_TYPE || row.direction !== 'response' || row.status !== 'completed' || row.payload === null) continue;
      try {
        const uuid = (JSON.parse(row.payload) as { result?: { identity?: { uuid?: unknown } } }).result?.identity?.uuid;
        if (typeof uuid === 'string') return uuid;
      } catch { /* an unreadable record is not an establishment */ }
    }
    return null;
  }

  private async foundingAdminsOf(communityUuid: string): Promise<MembershipRow[]> {
    return (await membershipsRepo.list(this.db, { communityIdentityUuid: communityUuid })).filter((m) => m.role === 'founding_admin');
  }

  private async fanOut(community: EstablishedCommunity): Promise<void> {
    if (this.afterEstablished === undefined) return;
    try {
      await this.afterEstablished(community);
    } catch (err) {
      logger.warn(`[founding] fan-out for ceremony ${community.ceremonyId.slice(0, 8)} failed: ${(err as Error)?.message ?? err}`);
    }
  }
}

function proposalOf(input: CeremonyEstablishment) {
  return {
    proposalId: input.ceremonyId,
    proposerDid: input.proposerDid,
    proposerUuid: null,
    vtcDid: input.vtcDid,
    name: input.name,
    kind: input.kind,
    adminDids: input.adminDids,
    adminUuids: [],
    threshold: input.threshold,
    expiresAt: 0,
    status: 'pending' as const,
    proposalHash: input.proposalHash,
    parentCommunityDid: input.parentCommunityDid,
    errorReason: null,
    createdAt: 0,
    crystallizedAt: null,
  };
}

/** `createVtc`'s refusals as the closed reasons; anything else is not a refusal (`rethrowOthers`: pass it on to be retried; at the check it is `indeterminate`). */
function refusalOf(err: unknown, rethrowOthers = false): unknown {
  if (err instanceof TaskError) return err;
  if (err instanceof CreateVtcConflictError) return taskErrorForReason('nameTaken', { internalMessage: err.message });
  if (err instanceof CreateVtcValidationError || err instanceof CreateVtcNotFoundError) return taskErrorForReason('policyDenied', { internalMessage: err.message });
  return rethrowOthers ? err : new TaskError({ code: 'indeterminate', retryable: true, internalMessage: `the establishment could not be checked: ${(err as Error)?.message ?? err}`, cause: err });
}
