// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The `ceremony-doc` handlers (conformance phase P8c, plan 2.1/2.2): begin (`ceremony:propose`),
 * approve (`ceremony:co-sign`), query (`ceremony:status`) and reset (`ceremony:reset`) over the
 * ceremony participant, the ceremony store and the guards. The founding ceremony is the first.
 *
 * Every document arrives through the boundary pipeline: the proof is verified, the recipient is
 * bound, and the ACTOR is the verified signer, which must equal the envelope `issuer` (decision A4;
 * nothing in a payload is an identity claim). Eligibility is the participant's rule, so there is
 * one source of truth: an approver who is not an admin and a ceremony that does not exist are the
 * same refusal.
 *
 * Outcomes are never read from a vote. After the transaction the handler reads the coordinator's
 * outcome (`getOutcome`) and the stored proposal and hands both to `ceremonyVerdict`:
 *   respond        -> `<type>#response` (the effect exists)
 *   next-step      -> `trust-task-next-step`, `continuation: proceed`, quorum in `ext`
 *   error          -> `trust-task-error` (taskFailed with the closed `details.reason`; `deadlineLapsed` for expiry)
 *   indeterminate  -> `indeterminate` (retryable), never guessed
 * Begin and approve answer this way. Query reports the state as data. Reset answers with the
 * ceremony as it now stands (aborted) and is refused after commit (`alreadyCommitted`).
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { TaskError, isReason } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import { CEREMONY_CO_SIGN_SPEC, CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_PROPOSE_SPEC, CEREMONY_PROPOSE_WIRE_TYPE, CEREMONY_RESET_SPEC, CEREMONY_RESET_WIRE_TYPE, CEREMONY_STATUS_SPEC, CEREMONY_STATUS_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-spec.js';
import { ceremonyVerdict } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-outcome.js';
import type { CeremonyVerdict } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-outcome.js';
import type { HandlerContext, PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import type { TxOutcome } from '@p2p-trust-stack/core/services/trust-tasks/boundary/lifecycle.js';
import { consentChallenge, consentPayloadDigest } from '@p2p-trust-stack/core/services/trust-tasks/boundary/task-consent.js';
import { buildNextStep } from '@p2p-trust-stack/core/services/trust-tasks/boundary/next-step.js';
import type { TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { closeIfLapsed, getAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { CeremonyProposal } from '@p2p-trust-stack/core/tx/ceremony-store.js';
import type { Operation, Participant, TransactionResult } from '@p2p-trust-stack/core/tx/types.js';
import { CEREMONY_APPROVE, CEREMONY_BEGIN, CEREMONY_RESET, declaredAdmins } from '../tx/ceremony-doc-participant.js';
import type { CeremonyDocParticipant } from '../tx/ceremony-doc-participant.js';
import { actorOf } from './shared.js';

/** The part of the transaction manager the handlers use. */
export interface CeremonyTransactions {
  run(fn: (tx: { enlist(participant: Participant, operations: Operation[]): void }) => Promise<void>): Promise<TransactionResult>;
  getOutcome(txId: string): Promise<TxOutcome>;
}

export interface CeremonyDocDeps {
  txManager: CeremonyTransactions;
  participant: CeremonyDocParticipant;
  /** Records the transaction id against the duplicate-record claim so a crash can be settled. */
  attachTx?: (documentId: string, txId: string) => Promise<void>;
  /** The application database (unused by the handlers today; reserved for the establishing server). */
  db?: DataSource;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const notFound = (): TaskError => new TaskError({ reason: 'notFoundOrNotPermitted', internalMessage: 'unknown ceremony or not permitted' });

/** The ceremony id is the thread; a begin document without one uses its own id. */
function ceremonyIdOf(doc: TrustTaskDocument<unknown>, allowOwnId: boolean): string {
  if (typeof doc.threadId === 'string' && doc.threadId !== '') return doc.threadId;
  if (allowOwnId && typeof doc.id === 'string' && doc.id !== '') return doc.id;
  throw notFound();
}

/**
 * The outcome to hand the verdict. A finished proposal is judged with the coordinator's outcome as is.
 * A pending one whose transaction committed is simply waiting for more co-signatures (that is the hold,
 * not a committed ceremony), so the committed outcome is not an input there; an aborted, in-flight or
 * unknown transaction still is.
 */
export function effectiveOutcome(status: CeremonyProposal['status'], outcome: TxOutcome): TxOutcome | undefined {
  return status === 'pending' && outcome === 'committed' ? undefined : outcome;
}

/** The challenge, digest and task type a `task-consent/decision` for this ceremony must echo. */
export function consentBinding(p: CeremonyProposal): { challenge: string; payloadDigest: string; taskType: string } {
  const challenge = consentChallenge({ ceremonyId: p.proposalId, proposalHash: p.proposalHash });
  const subject = { name: p.name, kind: p.kind, threshold: p.threshold, adminDids: p.adminDids, parentCommunityDid: p.parentCommunityDid };
  return { challenge, payloadDigest: consentPayloadDigest({ taskType: CEREMONY_PROPOSE_WIRE_TYPE, subject, challenge }), taskType: CEREMONY_PROPOSE_WIRE_TYPE };
}

function statusPayload(p: CeremonyProposal, approvals: number): Record<string, unknown> {
  return {
    ceremonyId: p.proposalId,
    status: p.status,
    approvalCount: approvals,
    required: Math.max(declaredAdmins(p).size, 1),
    threshold: p.threshold,
    expiresAt: new Date(p.expiresAt).toISOString(),
  };
}

/**
 * The shared mechanics of every handler that drives the ceremony participant: run one operation in a
 * transaction, read the coordinator's outcome and the stored ceremony, and answer by the verdict.
 * `task-consent/decision` (P5b) reuses it, so a decision and a co-sign are one code path.
 */
export function createCeremonyDriver(deps: CeremonyDocDeps) {
  const store = deps.participant.store;

  const reply = (doc: TrustTaskDocument<unknown>, ctx: HandlerContext, actor: string, ceremonyId: string, payload: Record<string, unknown>): TrustTaskDocument<unknown> =>
    ({
      id: ctx.newId(),
      threadId: ceremonyId,
      type: `${String(doc.type)}#response`,
      issuer: ctx.myVid ?? (doc.recipient as string),
      recipient: actor,
      issuedAt: ctx.clock(),
      payload,
    }) as unknown as TrustTaskDocument<unknown>;

  /** Run one operation in a transaction, read the outcome and the stored ceremony, and answer by the verdict. */
  async function drive(doc: TrustTaskDocument<unknown>, ctx: HandlerContext, actor: string, ceremonyId: string, op: Operation, onResponded?: (p: CeremonyProposal, approvals: number) => Record<string, unknown>): Promise<TrustTaskDocument<unknown>> {
    const result = await deps.txManager.run(async (tx) => {
      tx.enlist(deps.participant, [op]);
    });
    if (typeof doc.id === 'string') await deps.attachTx?.(doc.id, result.txId).catch(() => undefined);
    const outcome = await deps.txManager.getOutcome(result.txId);
    const stored = await store.getProposal(ceremonyId);
    const abortReason = getAbortReason(result.txId);
    if (stored === null) {
      // Nothing was begun: an aborted transaction says why, anything else cannot be known.
      if (outcome === 'aborted' && abortReason !== undefined) throw new TaskError({ code: abortReason.code, retryable: abortReason.retryable, ...(abortReason.reason === undefined ? {} : { reason: abortReason.reason }), internalMessage: 'the ceremony was refused' });
      throw new TaskError({ code: 'indeterminate', retryable: true, internalMessage: 'no ceremony and no outcome' });
    }
    const proposal = await closeIfLapsed(store, stored, ctx.now);
    const verdict = ceremonyVerdict({
      proposal: { ...proposal, ...(isReason(proposal.errorReason) ? { reason: proposal.errorReason } : {}) },
      outcome: effectiveOutcome(proposal.status, outcome),
      now: ctx.now,
      ...(abortReason === undefined ? {} : { abortReason }),
    });
    const approvals = (await store.getApprovals(ceremonyId)).length;
    switch (verdict.kind) {
      case 'respond':
        return reply(doc, ctx, actor, ceremonyId, (onResponded ?? statusPayload)(proposal, approvals));
      case 'next-step': {
        const required = Math.max(declaredAdmins(proposal).size, 1);
        return buildNextStep(
          { id: doc.id, type: doc.type, threadId: ceremonyId, issuer: doc.issuer, recipient: doc.recipient },
          {
            // The request's own type is never named: a held co-sign is not re-issued by its sender (the other admins co-sign), so
            // naming it would imply `resubmit` (SPEC.md 8.6). A held begin names the co-sign; a held co-sign names only the status task.
            expects: [
              ...(doc.type === CEREMONY_CO_SIGN_WIRE_TYPE ? [] : [{ typeUri: CEREMONY_CO_SIGN_WIRE_TYPE, reason: 'the named admins still need to co-sign' }]),
              { typeUri: CEREMONY_STATUS_WIRE_TYPE, reason: 'read the ceremony state' },
            ],
            continuation: 'proceed',
            message: 'co-signatures outstanding',
            // The `task-consent/decision` binding (P5b): what an approver echoes to approve through that task instead of a co-sign.
            ext: { quorum: { required, received: approvals }, 'p2pts.consent': consentBinding(proposal) },
          },
          { newId: ctx.newId, now: ctx.clock, issuer: ctx.myVid ?? (doc.recipient as string), recipient: actor },
        ) as unknown as TrustTaskDocument<unknown>;
      }
      default:
        throw refusal(verdict);
    }
  }

  /** Run one operation that has no verdict of its own (reset, deny): refused or indeterminate throws, committed returns. */
  async function runOperation(doc: TrustTaskDocument<unknown>, op: Operation, what: string): Promise<void> {
    const result = await deps.txManager.run(async (tx) => {
      tx.enlist(deps.participant, [op]);
    });
    if (typeof doc.id === 'string') await deps.attachTx?.(doc.id, result.txId).catch(() => undefined);
    const outcome = await deps.txManager.getOutcome(result.txId);
    if (outcome === 'aborted') {
      const why = getAbortReason(result.txId);
      if (why === undefined) throw new TaskError({ code: 'taskFailed', retryable: false, internalMessage: `the ${what} was refused` });
      throw new TaskError({ code: why.code, retryable: why.retryable, ...(why.reason === undefined ? {} : { reason: why.reason }), internalMessage: `the ${what} was refused` });
    }
    if (outcome !== 'committed') throw new TaskError({ code: 'indeterminate', retryable: true, internalMessage: `${what} outcome ${outcome}` });
  }

  return { store, reply, drive, runOperation };
}

export function createCeremonyDocHandlers(deps: CeremonyDocDeps): PipelineHandler[] {
  const { store, reply, drive, runOperation } = createCeremonyDriver(deps);

  const begin: PipelineHandler = {
    types: [CEREMONY_PROPOSE_WIRE_TYPE],
    spec: CEREMONY_PROPOSE_SPEC,
    consequential: true,
    handle: async (doc, ctx) => {
      const actor = actorOf(doc, ctx);
      const ceremonyId = ceremonyIdOf(doc, true);
      const p = doc.payload as { name: string; kind: 'vtc' | 'vtn'; threshold: number; adminDids: string[]; parentCommunityDid?: string };
      const proof = (doc as { proof?: unknown }).proof;
      const signature = isObj(proof) && typeof proof.proofValue === 'string' ? proof.proofValue : '';
      return drive(doc, ctx, actor, ceremonyId, {
        op: CEREMONY_BEGIN,
        params: { ceremonyId, proposerDid: actor, name: p.name, kind: p.kind, threshold: p.threshold, adminDids: p.adminDids, parentCommunityDid: p.parentCommunityDid ?? null, signature, nowMs: ctx.now },
      });
    },
  };

  const approve: PipelineHandler = {
    types: [CEREMONY_CO_SIGN_WIRE_TYPE],
    spec: CEREMONY_CO_SIGN_SPEC,
    consequential: true,
    handle: async (doc, ctx) => {
      const actor = actorOf(doc, ctx);
      const ceremonyId = ceremonyIdOf(doc, false);
      const p = doc.payload as { proposalHash?: string };
      const proof = (doc as { proof?: unknown }).proof;
      const signature = isObj(proof) && typeof proof.proofValue === 'string' ? proof.proofValue : '';
      return drive(doc, ctx, actor, ceremonyId, {
        op: CEREMONY_APPROVE,
        params: { ceremonyId, approverDid: actor, signature, ...(p.proposalHash === undefined ? {} : { proposalHash: p.proposalHash }), nowMs: ctx.now },
      });
    },
  };

  const query: PipelineHandler = {
    types: [CEREMONY_STATUS_WIRE_TYPE],
    spec: CEREMONY_STATUS_SPEC,
    consequential: false,
    handle: async (doc, ctx) => {
      const actor = actorOf(doc, ctx);
      const ceremonyId = ceremonyIdOf(doc, false);
      const stored = await store.getProposal(ceremonyId);
      if (stored === null || !declaredAdmins(stored).has(actor)) throw notFound();
      // A read tells the truth about the deadline: a lapsed pending ceremony is stored and reported as expired.
      const proposal = await closeIfLapsed(store, stored, ctx.now);
      return reply(doc, ctx, actor, ceremonyId, statusPayload(proposal, (await store.getApprovals(ceremonyId)).length));
    },
  };

  const reset: PipelineHandler = {
    types: [CEREMONY_RESET_WIRE_TYPE],
    spec: CEREMONY_RESET_SPEC,
    consequential: true,
    handle: async (doc, ctx) => {
      const actor = actorOf(doc, ctx);
      const ceremonyId = ceremonyIdOf(doc, false);
      await runOperation(doc, { op: CEREMONY_RESET, params: { ceremonyId, actorDid: actor, nowMs: ctx.now } }, 'reset');
      const proposal = await store.getProposal(ceremonyId);
      if (proposal === null) throw notFound();
      return reply(doc, ctx, actor, ceremonyId, statusPayload(proposal, (await store.getApprovals(ceremonyId)).length));
    },
  };

  return [begin, approve, query, reset];
}

/** A verdict that is not a response, as the typed refusal the pipeline puts on the wire. */
export function refusal(verdict: CeremonyVerdict): TaskError {
  if (verdict.kind === 'indeterminate') return new TaskError({ code: 'indeterminate', retryable: true, internalMessage: 'the outcome is not known yet' });
  if (verdict.kind === 'error') {
    return new TaskError({ code: verdict.code, retryable: verdict.retryable, ...(verdict.reason === undefined ? {} : { reason: verdict.reason }), internalMessage: 'the ceremony did not complete' });
  }
  throw new TypeError(`not a refusal: ${verdict.kind}`);
}
