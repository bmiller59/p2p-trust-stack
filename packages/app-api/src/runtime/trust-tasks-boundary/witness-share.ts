// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `vrc/relationships/witness-share/0.1` handler (conformance phase P7; suite-local profile).
 *
 * The peer hands over the Verifiable Witness Credential it earned in a witnessed exchange, as a
 * challenge-bound presentation plus the initiating and terminal documents that evidence the
 * witnessing. In order: authorise from the verified actor (equal to the envelope issuer, the peer's
 * CONNECTION DID); find the accepted exchange the share belongs to (a share on anyone else's thread
 * is indistinguishable from one on no thread); run the receive check (`checkWitnessShare`, the same
 * function the participant runs again before writing); enlist `store_witness_share` and read the
 * outcome as a fact; answer with a receipt over the credential AS STORED, read back from the table.
 *
 * No order against `issue` is enforced (profile 7, open question O7): the share is accepted whenever
 * the checks pass and the exchange is accepted, before, between or after the counterparty's issue.
 * Not trusted: the request's content for anything but evidence; no digest is copied into the receipt.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import * as witnessShares from '@p2p-trust-stack/core/db/repositories/witness-shares-repo.js';
import { checkWitnessShare } from '@p2p-trust-stack/core/relationship/witness-share.js';
import type { WitnessProofVerifier } from '@p2p-trust-stack/core/relationship/witness-share.js';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { HandlerContext, PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { digestMultibaseOf } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/digest.js';
import { ResolutionUnavailable } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import type { TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { WITNESS_SHARE_SPEC } from '@p2p-trust-stack/core/services/trust-tasks/boundary/witness-share-spec.js';
import { getAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { Operation, Participant, TransactionResult } from '@p2p-trust-stack/core/tx/types.js';
import { RECEIVING_STATES, WITNESS_SHARE_NOT_ACCEPTED, WITNESS_SHARE_TYPE, WITNESS_SHARE_URN_TYPE, actorOf } from './shared.js';

/** The part of the transaction manager the handler uses. */
export interface WitnessShareTransactions {
  run(fn: (tx: { enlist(participant: Participant, operations: Operation[]): void }) => Promise<void>): Promise<TransactionResult>;
}

export interface WitnessShareDeps {
  db: DataSource;
  txManager: WitnessShareTransactions;
  /** The witness share participant (`store_witness_share`). */
  participant: Participant;
  /** The boundary's proof verifier. */
  verifier: WitnessProofVerifier;
  /** Records the transaction id against the duplicate-record claim so a crash can be settled. */
  attachTx?: (documentId: string, txId: string) => Promise<void>;
}

const notAccepted = (internal: string, reason: 'notAccepted' | 'outcomeEvidenceInvalid' = 'notAccepted'): TaskError =>
  new TaskError({ code: WITNESS_SHARE_NOT_ACCEPTED, reason, retryable: false, internalMessage: internal });

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function createWitnessShareHandler(deps: WitnessShareDeps): PipelineHandler {
  return {
    // The registry-style URI the profile names, and the boundary's URN codec form of the same task.
    types: [WITNESS_SHARE_TYPE, WITNESS_SHARE_URN_TYPE],
    spec: WITNESS_SHARE_SPEC,
    consequential: true,
    handle: (doc, ctx) => handleShare(deps, doc, ctx),
  };
}

async function handleShare(deps: WitnessShareDeps, doc: TrustTaskDocument<unknown>, ctx: HandlerContext): Promise<TrustTaskDocument<unknown>> {
  const actor = actorOf(doc, ctx);
  // The exchange id is the share's thread: it is also the presentation's challenge.
  const exchangeId = typeof doc.threadId === 'string' && doc.threadId !== '' ? doc.threadId : String(doc.id);

  // One answer for "no such exchange", "somebody else's", "not decided yet", "ended" and "not yours" (profile 6.1).
  const exchange = await exchangeDids.findByExchangeId(deps.db, exchangeId);
  if (exchange === null || exchange.remoteConnectionDid !== actor || !RECEIVING_STATES.has(exchange.state) || exchange.remoteRelationshipDid === null) {
    throw notAccepted('no accepted exchange for this share');
  }

  const payload = doc.payload as { presentation?: unknown; outcomeEvidence?: { initiating?: unknown; terminal?: unknown } };
  const presentation = payload.presentation;
  const initiating = payload.outcomeEvidence?.initiating;
  const terminal = payload.outcomeEvidence?.terminal;
  if (!isObj(presentation) || !isObj(initiating) || !isObj(terminal)) throw new TaskError({ code: 'malformedRequest', retryable: false });

  let check;
  try {
    check = await checkWitnessShare({ presentation, initiating, terminal }, exchange, { verifier: deps.verifier, nowMs: ctx.now, challenge: exchangeId });
  } catch (err) {
    if (err instanceof ResolutionUnavailable) throw new TaskError({ code: 'unavailable', retryable: true, internalMessage: err.message });
    throw err;
  }
  if (!check.ok) throw notAccepted(`bundle refused: ${check.reason}`, 'outcomeEvidenceInvalid');

  const result = await deps.txManager.run(async (tx) => {
    tx.enlist(deps.participant, [
      {
        op: 'store_witness_share',
        params: {
          exchangeId,
          presentationJson: JSON.stringify(presentation),
          initiatingJson: JSON.stringify(initiating),
          terminalJson: JSON.stringify(terminal),
          shareDocumentId: typeof doc.id === 'string' ? doc.id : undefined,
          senderConnectionDid: actor,
        },
      },
    ]);
  });
  if (typeof doc.id === 'string') await deps.attachTx?.(doc.id, result.txId).catch(() => undefined);
  if (result.outcome !== 'committed') throw refusalFor(result.txId);

  // The receipt comes from what is in the table, not from what was sent.
  const row = await witnessShares.findByExchange(deps.db, exchangeId);
  if (row === null) throw new TaskError({ reason: 'storeFailed', internalMessage: 'committed but the credential is not in the table' });
  if (row.id !== check.digest) throw notAccepted('the stored credential is not the shared one');
  return {
    id: ctx.newId(),
    threadId: exchangeId,
    type: `${String(doc.type)}#response`,
    issuer: exchange.localConnectionDid,
    recipient: exchange.remoteConnectionDid,
    issuedAt: ctx.clock(),
    payload: { vwcDigestMultibase: digestMultibaseOf(JSON.parse(row.w3cVcJson)) },
  } as unknown as TrustTaskDocument<unknown>;
}

/** What the participant recorded when it voted no, as a wire refusal (closed `details.reason` vocabulary). */
function refusalFor(txId: string): TaskError {
  const why = getAbortReason(txId);
  if (why === undefined) return new TaskError({ code: 'taskFailed', retryable: false, internalMessage: 'the transaction aborted' });
  return new TaskError({ code: why.code, retryable: why.retryable, ...(why.reason === undefined ? {} : { reason: why.reason }), internalMessage: 'the transaction aborted' });
}
