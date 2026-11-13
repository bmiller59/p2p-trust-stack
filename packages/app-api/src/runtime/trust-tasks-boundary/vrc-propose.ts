// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `vrc/relationships/propose/0.1` handler (conformance phase P6a, plan 2.2, decision 32).
 *
 * The peer proposes a relationship and names the relationship DID it will use. Order of work:
 * authorise from the verified actor (== issuer); pre-check the proposed DID (a pure function shared
 * with the rest of the system); only then decide, and only an accepted or held proposal is stored
 * (a per-VRC relationship DID is minted for the exchange and the mapping row written before any
 * reply names it). The decision belongs to the human: a policy answers accept, decline or hold, and
 * a hold is answered with a `trust-task-next-step` (continuation `resubmit`, `inResponseTo` filled,
 * same thread) rather than silence or an error. A resubmission on the thread (fresh id) gets a
 * further next-step while held, the acceptance (never a second execution) after the human accepted,
 * and the decline after the human declined. The exchange is keyed by the thread.
 *
 * The decision itself is `decide(exchangeId, accept|decline)`: the agent's UI or API calls it. The
 * personhood ceremony's acknowledge entry points are NOT driven from here (see the P6 report).
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import type { ExchangeDidRow } from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import {
  ExchangeDidLimitError,
  checkProposedRelationshipDid,
  declineExchange,
  mintExchangeRelationshipDid,
} from '@p2p-trust-stack/core/relationship/exchange-dids.js';
import { TaskError, buildErrorDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { HandlerContext, PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { buildNextStep } from '@p2p-trust-stack/core/services/trust-tasks/boundary/next-step.js';
import { VRC_PROPOSE_SPEC } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import type { TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { PROPOSE_DECLINED, PROPOSE_RESPONSE_TYPE, PROPOSE_TYPE, actorOf } from './shared.js';

export type ProposeDecision = 'accept' | 'decline' | 'hold';

export interface ProposalInfo {
  exchangeId: string;
  /** The verified connection DID of the proposer. */
  peer: string;
  /** The relationship DID the proposer named. */
  relationshipDid: string;
  witnessedRequested: boolean;
}

/** What the human (or the agent's configured stand-in) decides about a new proposal. */
export interface ProposeConsentPolicy {
  decide(proposal: ProposalInfo): Promise<ProposeDecision> | ProposeDecision;
  /** Whether a requested witnessed exchange is agreed to. Default: no (a request is never mirrored). */
  witnessed?(proposal: ProposalInfo): Promise<boolean> | boolean;
}

/** Safe default: every proposal waits for the human. */
export const HOLD_EVERYTHING: ProposeConsentPolicy = { decide: () => 'hold' };

export interface VrcProposeDeps {
  /** The application database (the relationship-DID mapping lives here). */
  db: DataSource;
  /** The agent's root identity for its connection DID(s). */
  localIdentityUuid: string;
  /** The agent's key passphrase for the per-exchange relationship key. No default. */
  passphrase: string;
  policy?: ProposeConsentPolicy;
  now?: () => number;
  newId?: () => string;
  /** The serving identifier when a reply is built outside a request (a decision on a held proposal). */
  onHeld?: (row: ExchangeDidRow) => void;
}

/** Make sure a root identity row exists for a counterparty's connection DID (called only for an accepted exchange). */
export async function ensureRemoteIdentity(db: DataSource, did: string): Promise<string> {
  const existing = await identitiesRepo.findByRealDid(db, did);
  if (existing !== null) return existing.uuid;
  const uuid = await identitiesRepo.create(db, { realDid: did, role: 'vta', subjectKind: 'human', custody: 'remote', name: did });
  await didDocumentsRepo.create(db, { identityUuid: uuid, did, method: did.split(':').slice(0, 2).join(':'), documentJson: '{}', isPrimary: true });
  return uuid;
}

const refusal = (reason: string): TaskError => new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: reason });

export class VrcProposeService {
  private readonly deps: VrcProposeDeps;
  private readonly policy: ProposeConsentPolicy;
  private readonly now: () => number;

  constructor(deps: VrcProposeDeps) {
    this.deps = deps;
    this.policy = deps.policy ?? HOLD_EVERYTHING;
    this.now = deps.now ?? Date.now;
  }

  /** The pipeline handler for the propose type. Proof is OPTIONAL in the specification (REQUIRED by the attested profile). */
  handler(): PipelineHandler {
    return {
      types: [PROPOSE_TYPE],
      spec: VRC_PROPOSE_SPEC,
      consequential: false,
      handle: (doc, ctx) => this.handle(doc, ctx),
    };
  }

  async handle(doc: TrustTaskDocument<unknown>, ctx: HandlerContext): Promise<TrustTaskDocument<unknown>> {
    const peer = actorOf(doc, ctx);
    const payload = doc.payload as { relationshipDid?: unknown; witnessed?: unknown };
    const exchangeId = typeof doc.threadId === 'string' && doc.threadId !== '' ? doc.threadId : String(doc.id);
    const local = ctx.myVid;
    if (local === undefined) throw new TaskError({ code: 'wrongRecipient', internalMessage: 'no serving identifier' });

    // A thread belongs to the connection that opened it; to anyone else it is not theirs to use. Checked
    // first so a foreign sender learns nothing else about it.
    const existing = await exchangeDids.findByExchangeId(this.deps.db, exchangeId);
    if (existing !== null && (existing.remoteConnectionDid !== peer || existing.role !== 'acceptor')) {
      throw new TaskError({ code: 'permissionDenied', retryable: false, internalMessage: 'thread belongs to another sender' });
    }

    const check = await checkProposedRelationshipDid(this.deps.db, {
      relationshipDid: payload.relationshipDid,
      senderConnectionDid: peer,
      localConnectionDid: local,
      exchangeId,
    });
    if (!check.ok) throw refusal(`relationshipDid refused: ${check.reason}`);
    const relationshipDid = payload.relationshipDid as string;
    const info: ProposalInfo = { exchangeId, peer, relationshipDid, witnessedRequested: payload.witnessed === true };
    if (existing !== null) return this.reply(existing, doc, ctx, info);

    const decision = await this.policy.decide(info);
    if (decision === 'decline') throw new TaskError({ code: PROPOSE_DECLINED, retryable: false, internalMessage: 'declined by policy' });

    const row = await this.mint(info, local, decision === 'hold' ? 'held' : 'accepted');
    if (decision === 'accept') await this.markAccepted(row);
    else this.deps.onHeld?.(row);
    return this.reply((await exchangeDids.findByExchangeId(this.deps.db, exchangeId))!, doc, ctx, info);
  }

  private async mint(info: ProposalInfo, local: string, state: 'held' | 'accepted'): Promise<ExchangeDidRow> {
    try {
      return await mintExchangeRelationshipDid(this.deps.db, {
        exchangeId: info.exchangeId,
        role: 'acceptor',
        localIdentityUuid: this.deps.localIdentityUuid,
        localConnectionDid: local,
        remoteConnectionDid: info.peer,
        remoteRelationshipDid: info.relationshipDid,
        passphrase: this.deps.passphrase,
        state,
        now: this.now(),
      });
    } catch (err) {
      if (err instanceof ExchangeDidLimitError) throw new TaskError({ code: 'unavailable', retryable: true, internalMessage: err.message });
      // The mapping refuses a reused DID inside its own transaction (a race the pre-check could not see).
      if (err instanceof Error && err.name === 'RelationshipDidReuseError') throw refusal(err.message);
      throw err;
    }
  }

  /** The proposal is accepted: the counterparty becomes a root identity the credentials can reference. */
  private async markAccepted(row: ExchangeDidRow): Promise<void> {
    const uuid = await ensureRemoteIdentity(this.deps.db, row.remoteConnectionDid);
    await exchangeDids.setRemoteIdentityUuid(this.deps.db, row.exchangeId, uuid, this.now());
    if (row.state !== 'accepted') await exchangeDids.setState(this.deps.db, row.exchangeId, 'accepted', this.now());
  }

  /** The answer for the exchange as it stands now: next-step while held, the acceptance, or the decline. */
  private async reply(row: ExchangeDidRow, doc: TrustTaskDocument<unknown>, ctx: HandlerContext, info: ProposalInfo): Promise<TrustTaskDocument<unknown>> {
    switch (row.state) {
      case 'held':
        return buildNextStep(
          { id: doc.id, type: doc.type, threadId: row.exchangeId, issuer: doc.issuer, recipient: doc.recipient },
          {
            expects: [{ typeUri: PROPOSE_TYPE, reason: "the counterparty's decision is pending; resubmit the proposal to learn the outcome" }],
            continuation: 'resubmit',
            message: 'decision pending',
          },
          { newId: ctx.newId, now: ctx.clock, issuer: row.localConnectionDid, recipient: row.remoteConnectionDid },
        ) as unknown as TrustTaskDocument<unknown>;
      case 'declined':
        throw new TaskError({ code: PROPOSE_DECLINED, retryable: false, internalMessage: 'declined' });
      case 'ended':
        throw new TaskError({ reason: 'notFound', internalMessage: 'the exchange has ended' });
      default: {
        const agreed = info.witnessedRequested && (await this.policy.witnessed?.(info)) === true;
        return this.acceptance(row, ctx.newId(), ctx.clock(), agreed);
      }
    }
  }

  private acceptance(row: ExchangeDidRow, id: string, issuedAt: string, witnessed: boolean): TrustTaskDocument<unknown> {
    return {
      id,
      threadId: row.exchangeId,
      type: PROPOSE_RESPONSE_TYPE,
      issuer: row.localConnectionDid,
      recipient: row.remoteConnectionDid,
      issuedAt,
      payload: { accept: true, relationshipDid: row.localRelationshipDid, ...(witnessed ? { witnessed: true } : {}) },
    } as unknown as TrustTaskDocument<unknown>;
  }

  /** Held proposals, oldest first (the agent's UI lists these). */
  async listHeld(): Promise<ExchangeDidRow[]> {
    const rows = await this.deps.db.all<{ exchange_id: string }>(
      "SELECT exchange_id FROM vrc_exchange_relationship_dids WHERE state = 'held' AND role = 'acceptor' ORDER BY created_at, exchange_id",
    );
    const out: ExchangeDidRow[] = [];
    for (const r of rows) out.push((await exchangeDids.findByExchangeId(this.deps.db, r.exchange_id))!);
    return out;
  }

  /**
   * The human's decision on a held proposal. Returns the (unsigned, addressed) document the agent
   * would emit: the acceptance, or the decline error. The carrier has no push channel, so in
   * production the proposer learns it by resubmitting; a test adapter signs and returns it.
   * Deciding twice, or on anything that is not held, is refused.
   */
  async decide(exchangeId: string, decision: 'accept' | 'decline'): Promise<TrustTaskDocument<unknown>> {
    const row = await exchangeDids.findByExchangeId(this.deps.db, exchangeId);
    if (row === null || row.role !== 'acceptor' || row.state !== 'held') throw new TaskError({ reason: 'notFound', internalMessage: 'no held proposal for that exchange' });
    const newId = this.deps.newId ?? (() => crypto.randomUUID());
    const issuedAt = new Date(Math.floor(this.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z');
    if (decision === 'decline') {
      await declineExchange(this.deps.db, exchangeId, this.now());
      return buildErrorDocument(
        { threadId: exchangeId },
        new TaskError({ code: PROPOSE_DECLINED, retryable: false }),
        { newId, now: () => issuedAt, issuer: row.localConnectionDid, recipient: row.remoteConnectionDid },
      ) as unknown as TrustTaskDocument<unknown>;
    }
    await this.markAccepted(row);
    return this.acceptance({ ...row, state: 'accepted' }, newId(), issuedAt, false);
  }
}
