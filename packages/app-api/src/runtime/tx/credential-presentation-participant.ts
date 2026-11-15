// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * CredentialPresentationParticipant: agent-side participant that stores a presentation received as the
 * verifier (conformance phase P5b, `credential-exchange/present`). Operation `store_presentation`; migration 0023.
 *
 * The boundary handler has already run `checkPresentation`; this participant runs it AGAIN with the same pure
 * function before writing, so "verified before stored" holds at the point of storage. Idempotent by digest (the
 * same presentation again is a yes with no second row); a DIFFERENT presentation on a thread that already holds one
 * is refused `staleNonce` (a nonce is single use). The row is written at COMMIT from the intent recorded in `pending_ops` at prepare, so an abort
 * (or a crash and restart) leaves nothing to undo and no in-memory state is relied on.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as presentations from '@p2p-trust-stack/core/db/repositories/credential-presentations-repo.js';
import { PRESENT_STALE_NONCE, checkPresentation, presentRefusal } from '@p2p-trust-stack/core/services/trust-tasks/boundary/credential-exchange.js';
import type { CredentialProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/credential-exchange.js';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import { recordAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { Operation, Outcome, Participant, Vote } from '@p2p-trust-stack/core/tx/types.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';

type PresentationInsert = Parameters<typeof presentations.insert>[1];

export const STORE_PRESENTATION = 'store_presentation';

export interface StorePresentationParams {
  /** The `vp_token` as JSON text. */
  vpJson: string;
  /** The verified sender: the holder. */
  holderDid: string;
  /** Our identifier: the audience the presentation was bound to. */
  audience: string;
  /** The verifier's nonce: the thread. */
  threadId: string;
  documentId?: string;
}

export class CredentialPresentationParticipant implements Participant {
  readonly pid: string;
  private verifier: { verifier: CredentialProofVerifier; now: () => number } | undefined;

  private readonly appDb: DataSource;
  private readonly txDb: DataSource;

  constructor(pid: string, appDb: DataSource, txDb: DataSource) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
  }

  setVerifier(verifier: CredentialProofVerifier, now: () => number = Date.now): void {
    this.verifier = { verifier, now };
  }

  handlesOperation(op: Operation): boolean {
    return op.op === STORE_PRESENTATION;
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    const pending: PresentationInsert[] = [];
    for (const op of operations) {
      if (op.op !== STORE_PRESENTATION) continue;
      try {
        const row = await this.check(op.params as unknown as StorePresentationParams);
        if (row !== null) pending.push(row);
      } catch (err) {
        logger.error(`[credential-presentation] refused for tx ${txId}:`, (err as Error)?.message);
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

  /** Phase 1: every check, no write. Returns the row to insert at commit, or null when this exact presentation is already held. */
  private async check(p: StorePresentationParams): Promise<PresentationInsert | null> {
    if (this.verifier === undefined) throw new TaskError({ code: 'unavailable', retryable: true, internalMessage: 'no proof verifier is installed' });
    let token: unknown;
    try {
      token = JSON.parse(p.vpJson);
    } catch {
      throw presentRefusal('malformed', 'the presentation is not JSON');
    }
    const check = await checkPresentation(token, { holder: p.holderDid, audience: p.audience, nonce: p.threadId }, { verifier: this.verifier.verifier, nowMs: this.verifier.now() });
    if (!check.ok) throw presentRefusal(check.reason, `presentation refused: ${check.reason}${check.detail === undefined ? '' : ` (${check.detail})`}`);

    const same = await presentations.findByDigest(this.appDb, check.digest);
    if (same !== null) {
      if (same.threadId !== p.threadId || same.holderDid !== p.holderDid) throw new TaskError({ code: PRESENT_STALE_NONCE, retryable: false, internalMessage: 'the presentation is held for another thread' });
      return null;
    }
    if ((await presentations.findByThread(this.appDb, p.threadId)) !== null) {
      throw new TaskError({ code: PRESENT_STALE_NONCE, retryable: false, internalMessage: 'the nonce was already used by another presentation' });
    }
    return {
      id: check.digest,
      threadId: p.threadId,
      holderDid: p.holderDid,
      verifierDid: p.audience,
      vpJson: check.text,
      issuers: check.issuers,
      credentialCount: check.credentialCount,
      documentId: p.documentId,
      now: this.verifier.now(),
    };
  }

  /** Phase 2: write the recorded rows. Idempotent by digest, so a repeated or replayed commit adds nothing. */
  async commit(txId: string): Promise<void> {
    const row = await this.txDb.get<{ outcome: string; pending_ops: string | null }>('SELECT outcome, pending_ops FROM tx_participant_state WHERE tx_id = ? AND pid = ?', txId, this.pid);
    if (row?.outcome === 'prepared' && row.pending_ops) {
      for (const insert of JSON.parse(row.pending_ops) as PresentationInsert[]) {
        if ((await presentations.findByDigest(this.appDb, insert.id)) === null) await presentations.insert(this.appDb, insert);
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
