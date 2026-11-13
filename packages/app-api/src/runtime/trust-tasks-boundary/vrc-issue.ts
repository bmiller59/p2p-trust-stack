// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `vrc/relationships/issue/0.1` handler (conformance phase P6b, plan 2.2).
 *
 * The peer delivers the VRC it issued for an accepted exchange. In order: authorise from the verified
 * actor (equal to the envelope issuer, which is the peer's CONNECTION DID; the relationship DID never
 * appears in the envelope); find the exchange the delivery belongs to (a delivery on anyone else's
 * thread is indistinguishable from one on no thread); check the credential against the exchange
 * RECORD, never against what the document claims, and refuse before anything is stored; enlist
 * `store_remote_vrc` on the existing VRC receive participant (the same participant the TSP ceremony
 * uses; this is a second front door onto it) and read the outcome as a fact; only after `committed`,
 * and only if the credential is actually in the table, answer with a receipt computed over the
 * credential AS STORED.
 *
 * Not passed on: the remote-supplied `issuerIdentity` (there is none on this path), and the
 * request's `vrcDigestMultibase` (it is never copied into the receipt).
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import type { ExchangeDidRow } from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { checkIncomingVrc, findExchangeVrc } from '@p2p-trust-stack/core/relationship/exchange-vrc.js';
import type { InnerProofVerifier } from '@p2p-trust-stack/core/relationship/exchange-vrc.js';
import { sha256 } from '@p2p-trust-stack/core/crypto/primitives.js';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { HandlerContext, PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { digestMultibaseOf } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/digest.js';
import { ResolutionUnavailable } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { VRC_ISSUE_SPEC, canonicalJson } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import type { TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { getAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { Operation, Participant, TransactionResult } from '@p2p-trust-stack/core/tx/types.js';
import { ISSUE_ALREADY_ISSUED, ISSUE_NOT_ACCEPTED, ISSUE_RESPONSE_TYPE, ISSUE_TYPE, actorOf } from './shared.js';

/** The part of the transaction manager the handler uses. */
export interface IssueTransactions {
  run(fn: (tx: { enlist(participant: Participant, operations: Operation[]): void }) => Promise<void>): Promise<TransactionResult>;
}

export interface VrcIssueDeps {
  db: DataSource;
  txManager: IssueTransactions;
  /** The VRC receive participant (`store_remote_vrc`). */
  participant: Participant;
  /** The boundary's proof verifier: did:key and did:peer:4 relationship DIDs resolve offline. */
  verifier: InnerProofVerifier;
  /** Records the transaction id against the duplicate-record claim so a crash can be settled (accepted-store `attachTx`). */
  attachTx?: (documentId: string, txId: string) => Promise<void>;
}

/** States of an exchange in which the counterparty's credential may be received. */
const RECEIVING = new Set(['accepted', 'received', 'issued-by-me']);

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const notAccepted = (internal: string, reason: 'notAccepted' | 'vcInvalid' = 'notAccepted'): TaskError =>
  new TaskError({ code: ISSUE_NOT_ACCEPTED, reason, retryable: false, internalMessage: internal });

export function createVrcIssueHandler(deps: VrcIssueDeps): PipelineHandler {
  return {
    types: [ISSUE_TYPE],
    spec: VRC_ISSUE_SPEC,
    consequential: true,
    handle: (doc, ctx) => handleIssue(deps, doc, ctx),
  };
}

async function handleIssue(deps: VrcIssueDeps, doc: TrustTaskDocument<unknown>, ctx: HandlerContext): Promise<TrustTaskDocument<unknown>> {
  const actor = actorOf(doc, ctx);
  const exchangeId = typeof doc.threadId === 'string' && doc.threadId !== '' ? doc.threadId : String(doc.id);

  // One answer for "no such exchange", "somebody else's exchange", "not decided yet" and "not yours".
  const exchange = await exchangeDids.findByExchangeId(deps.db, exchangeId);
  if (
    exchange === null ||
    exchange.remoteConnectionDid !== actor ||
    !RECEIVING.has(exchange.state) ||
    exchange.remoteRelationshipDid === null ||
    exchange.localIdentityUuid === null ||
    exchange.remoteIdentityUuid === null
  ) {
    throw notAccepted('no accepted exchange for this delivery');
  }

  const vrc = (doc.payload as { vrc?: unknown }).vrc;
  if (vrc === null || typeof vrc !== 'object' || Array.isArray(vrc)) throw new TaskError({ code: 'malformedRequest', retryable: false });

  // Stored in the canonical (RFC 8785) serialisation: the credential's proof is over that form, so it
  // verifies identically, and the same credential always has the same stored text and digest.
  const w3cVcJson = canonicalJson(vrc);
  let check;
  try {
    check = await checkIncomingVrc(w3cVcJson, exchange, { verifier: deps.verifier, nowMs: ctx.now });
  } catch (err) {
    if (err instanceof ResolutionUnavailable) throw new TaskError({ code: 'unavailable', retryable: true, internalMessage: err.message });
    throw err;
  }
  if (!check.ok) throw notAccepted(`credential refused: ${check.reason}`, 'vcInvalid');

  // Per exchange, never per pair: a different credential for this exchange is `alreadyIssued`; the same one again is a receipt again.
  const storedDigest = hex(sha256(new TextEncoder().encode(w3cVcJson)));
  const held = await findExchangeVrc(deps.db, exchange, 'received');
  if (held !== null && held.digest !== storedDigest) {
    throw new TaskError({ code: ISSUE_ALREADY_ISSUED, retryable: false, internalMessage: 'the exchange already holds a different credential' });
  }

  const subject = (vrc as { credentialSubject: { id: string } }).credentialSubject.id;
  const result = await deps.txManager.run(async (tx) => {
    tx.enlist(deps.participant, [
      // No `issuerIdentity`: what the sender says about itself is never an input here.
      { op: 'store_remote_vrc', params: { w3cVcJson, issuerDid: exchange.remoteRelationshipDid, subjectDid: subject, exchangeId } },
    ]);
  });
  if (typeof doc.id === 'string') await deps.attachTx?.(doc.id, result.txId).catch(() => undefined);
  if (result.outcome !== 'committed') throw refusalFor(result.txId);

  // The receipt comes from what is in the table, not from what was sent.
  const row = await findExchangeVrc(deps.db, (await exchangeDids.findByExchangeId(deps.db, exchangeId)) ?? exchange, 'received');
  if (row === null) throw new TaskError({ reason: 'storeFailed', internalMessage: 'committed but the credential is not in the table' });
  if (row.digest !== storedDigest) {
    throw new TaskError({ code: ISSUE_ALREADY_ISSUED, retryable: false, internalMessage: 'the stored credential is not the delivered one' });
  }
  return {
    id: ctx.newId(),
    threadId: exchangeId,
    type: ISSUE_RESPONSE_TYPE,
    issuer: exchange.localConnectionDid,
    recipient: exchange.remoteConnectionDid,
    issuedAt: ctx.clock(),
    payload: { vrcDigestMultibase: digestMultibaseOf(JSON.parse(row.w3cVcJson)) },
  } as unknown as TrustTaskDocument<unknown>;
}

/** What the participant recorded when it voted no, as a wire refusal (closed `details.reason` vocabulary). */
function refusalFor(txId: string): TaskError {
  const why = getAbortReason(txId);
  if (why === undefined) return new TaskError({ code: 'taskFailed', retryable: false, internalMessage: 'the transaction aborted' });
  if (why.reason === 'notAccepted' || why.reason === 'vcInvalid') {
    return notAccepted(`aborted: ${why.reason}`, why.reason);
  }
  return new TaskError({ code: why.code, retryable: why.retryable, ...(why.reason === undefined ? {} : { reason: why.reason }), internalMessage: 'the transaction aborted' });
}

export type { ExchangeDidRow };
