// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * WitnessShareParticipant: agent-side participant that stores a witnessed credential (kind `vwc`)
 * together with the evidence that earned it (conformance phase P7). Operation `store_witness_share`.
 *
 * The boundary handler has already run the receive check, but this participant runs it AGAIN with
 * the same pure function before it writes anything, exactly as the VRC participant does: the
 * coordinator can be reached by other callers, and "earned by verification, never granted on
 * receipt" must hold at the point of storage, not only at the front door.
 *
 * Idempotent by credential digest: the same credential again is a yes with no second row. A
 * DIFFERENT credential for an exchange that already holds one is refused (one share per party per
 * exchange; profile choice). The row is written at COMMIT from the intent recorded in `pending_ops` at prepare, so an
 * abort (or a crash and restart) leaves nothing to undo and no in-memory state is relied on.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import * as witnessShares from '@p2p-trust-stack/core/db/repositories/witness-shares-repo.js';
import { checkWitnessShare } from '@p2p-trust-stack/core/relationship/witness-share.js';
import type { WitnessProofVerifier } from '@p2p-trust-stack/core/relationship/witness-share.js';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import { WITNESS_SHARE_NOT_ACCEPTED } from '@p2p-trust-stack/core/services/trust-tasks/boundary/witness-share-spec.js';
import { recordAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { Operation, Outcome, Participant, Vote } from '@p2p-trust-stack/core/tx/types.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';
import { RECEIVING_STATES } from '../trust-tasks-boundary/shared.js';

type WitnessInsert = Parameters<typeof witnessShares.insert>[1];

export const STORE_WITNESS_SHARE = 'store_witness_share';

export interface StoreWitnessShareParams {
  exchangeId: string;
  /** The three documents exactly as received, as JSON text. */
  presentationJson: string;
  initiatingJson: string;
  terminalJson: string;
  /** The id of the share document that carried them. */
  shareDocumentId?: string;
  /** The connection DID the share came from (the verified actor). */
  senderConnectionDid: string;
}

const refuse = (internal: string, reason: 'notAccepted' | 'outcomeEvidenceInvalid' = 'outcomeEvidenceInvalid'): TaskError =>
  new TaskError({ code: WITNESS_SHARE_NOT_ACCEPTED, reason, retryable: false, internalMessage: internal });

function parseObject(text: unknown): Record<string, unknown> {
  if (typeof text !== 'string') throw refuse('evidence is not text');
  const v: unknown = JSON.parse(text);
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw refuse('evidence is not an object');
  return v as Record<string, unknown>;
}

export class WitnessShareParticipant implements Participant {
  readonly pid: string;
  private verifier: { verifier: WitnessProofVerifier; now: () => number } | undefined;

  private readonly appDb: DataSource;
  private readonly txDb: DataSource;

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
  }

  /** The boundary's proof verifier and clock. Without one the participant votes no. */
  setVerifier(verifier: WitnessProofVerifier, now: () => number = Date.now): void {
    this.verifier = { verifier, now };
  }

  handlesOperation(op: Operation): boolean {
    return op.op === STORE_WITNESS_SHARE;
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    const pending: WitnessInsert[] = [];
    for (const op of operations) {
      if (op.op !== STORE_WITNESS_SHARE) continue;
      try {
        const row = await this.check(op.params as unknown as StoreWitnessShareParams);
        if (row !== null) pending.push(row);
      } catch (err) {
        logger.error(`[witness-share] refused for tx ${txId}:`, (err as Error)?.message);
        recordAbortReason(txId, err);
        return 'no';
      }
    }
    await this.txDb.run(
      "INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome, pending_ops) VALUES (?, ?, 'prepared', ?)",
      txId, this.pid, pending.length === 0 ? null : JSON.stringify(pending),
    );
    return 'yes';
  }

  /** Phase 1: every check, no write. Returns the row to insert at commit, or null when this exact credential is already held. */
  private async check(p: StoreWitnessShareParams): Promise<WitnessInsert | null> {
    if (this.verifier === undefined) throw new TaskError({ code: 'unavailable', retryable: true, internalMessage: 'no proof verifier is installed' });
    const exchange = await exchangeDids.findByExchangeId(this.appDb, p.exchangeId);
    if (exchange === null || exchange.remoteConnectionDid !== p.senderConnectionDid || !RECEIVING_STATES.has(exchange.state) || exchange.remoteRelationshipDid === null) {
      throw refuse('no accepted exchange for this share', 'notAccepted');
    }
    let documents;
    try {
      documents = { presentation: parseObject(p.presentationJson), initiating: parseObject(p.initiatingJson), terminal: parseObject(p.terminalJson) };
    } catch (err) {
      if (err instanceof TaskError) throw err;
      throw refuse('evidence is not JSON');
    }
    const check = await checkWitnessShare(documents, exchange, { verifier: this.verifier.verifier, nowMs: this.verifier.now(), challenge: p.exchangeId });
    if (!check.ok) throw refuse(`bundle refused: ${check.reason}${check.detail === undefined ? '' : ` (${check.detail})`}`);

    const same = await witnessShares.findByDigest(this.appDb, check.digest);
    if (same !== null) {
      // The same credential again: nothing is stored twice. Another exchange cannot hold it (its subject is bound to this exchange's DID).
      if (same.exchangeId !== p.exchangeId) throw refuse('the credential is held for another exchange', 'notAccepted');
      return null;
    }
    if ((await witnessShares.findByExchange(this.appDb, p.exchangeId)) !== null) {
      throw refuse('the exchange already holds a different shared credential', 'notAccepted');
    }
    return {
      id: check.digest,
      exchangeId: p.exchangeId,
      subjectDid: check.subjectDid,
      witnessDid: check.witnessDid,
      senderConnectionDid: p.senderConnectionDid,
      w3cVcJson: check.vwcJson,
      shareDocumentId: p.shareDocumentId,
      // Evidence exactly as received (member order preserved).
      presentationJson: JSON.stringify(documents.presentation),
      initiatingJson: JSON.stringify(documents.initiating),
      terminalJson: JSON.stringify(documents.terminal),
      now: this.verifier.now(),
    };
  }

  /** Phase 2: write the recorded rows. Idempotent by credential digest, so a repeated or replayed commit adds nothing. */
  async commit(txId: string): Promise<void> {
    const row = await this.txDb.get<{ outcome: string; pending_ops: string | null }>('SELECT outcome, pending_ops FROM tx_participant_state WHERE tx_id = ? AND pid = ?', txId, this.pid);
    if (row?.outcome === 'prepared' && row.pending_ops) {
      for (const insert of JSON.parse(row.pending_ops) as WitnessInsert[]) {
        if ((await witnessShares.findByDigest(this.appDb, insert.id)) === null) await witnessShares.insert(this.appDb, insert);
      }
    }
    await this.txDb.run("UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?", txId, this.pid);
  }

  async abort(txId: string): Promise<void> {
    // Nothing was written before commit: dropping the recorded intent is the whole rollback.
    await this.txDb.run("UPDATE tx_participant_state SET outcome = 'aborted', pending_ops = NULL WHERE tx_id = ? AND pid = ?", txId, this.pid);
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>('SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?', txId, this.pid);
    return (row?.outcome as Outcome) ?? 'unknown';
  }
}
