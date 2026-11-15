// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * VrcReceiveParticipant — agent-side participant that receives a peer's VRC
 * (the "reflection" direction of the VRC ceremony) and persists it to the
 * agent's local SQLite credentials table.
 *
 * Handles:
 *   - 'store_remote_vrc' — stores the W3C VC JSON received from the remote peer
 *
 * This mirrors VtcReceiveParticipant but for VRC replication instead of
 * VTC community data. It is registered with the agent's transaction coordinator
 * so that inbound tx_prepare messages carrying this operation are routed here.
 *
 * pid: 'peer:{agentDid}' — identifies this agent as a participant.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from '@p2p-trust-stack/core/tx/types.js';
import type { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import type { VtcStore } from '@p2p-trust-stack/core/vtc/store.js';
import { VrcCeremonyStore } from '@p2p-trust-stack/core/tx/vrc-ceremony-store.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { checkIncomingVrc, findExchangeVrc } from '@p2p-trust-stack/core/relationship/exchange-vrc.js';
import type { InnerProofVerifier } from '@p2p-trust-stack/core/relationship/exchange-vrc.js';
import type { ExchangeDidRow } from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { recordAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import { sha256 } from '@p2p-trust-stack/core/crypto/primitives.js';

export interface StoreRemoteVrcParams {
  w3cVcJson: string;
  issuerDid: string;
  subjectDid: string;
  /** Sender's VID, used to key the mirrored ceremony session consistently. */
  issuerVid?: string;
  /**
   * The sender's full identity record, shared so the receiver can populate its
   * local `identities` table (login name, role, subject kind, public keys, …).
   * The receiver re-derives the row key (deterministic UUIDv5 of the real DID)
   * and stores the record with custody='remote'.
   */
  issuerIdentity?: Record<string, unknown>;
  /**
   * Boundary path only (conformance P5c): the `propose` document id of the exchange this credential
   * belongs to. When set, issuer and subject must be the exchange's relationship DIDs, the inner
   * proof must verify, the credential is stored against the exchange's root identities, and
   * `issuerIdentity` and the internal ceremony session are NOT used.
   */
  exchangeId?: string;
}

export class VrcReceiveParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;
  private readonly txDb: DataSource;
  private readonly vtcStore: VtcStore;
  private readonly ceremonyStore: VrcCeremonyStore;
  private innerProof: { verifier: InnerProofVerifier; now: () => number } | undefined;

  constructor(
    pid: string,
    appDb: DataSource,
    txDb: DataSource,
    vtcStore: VtcStore,
    _resolver: IdentityResolver,
  ) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
    this.vtcStore = vtcStore;
    // The ceremony saga lives in the same tx-coordinator db as participant state.
    this.ceremonyStore = new VrcCeremonyStore(txDb);
  }

  /**
   * Boundary path: verify the inner proof with the boundary's verifier (so `did:key` as well as
   * `did:peer:4` relationship DIDs verify) on the same clock the pipeline uses. Without it the
   * offline `did:peer:4` check applies.
   */
  setInnerProofVerifier(verifier: InnerProofVerifier, now: () => number = Date.now): void {
    this.innerProof = { verifier, now };
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'store_remote_vrc';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    // Both paths apply their effect at COMMIT: prepare only checks and records what to apply (in `pending_ops`),
    // so a credential is never visible while the transaction is undecided, an abort leaves nothing to undo, and a
    // restart between prepare and commit loses nothing.
    const pending: StoreRemoteVrcParams[] = [];
    for (const op of operations) {
      if (op.op !== 'store_remote_vrc') continue;

      const params = op.params as unknown as StoreRemoteVrcParams;
      if (!params?.w3cVcJson) return 'no';

      if (params.exchangeId !== undefined) {
        try {
          await this.checkExchangeVrc(params);
          pending.push(params);
        } catch (err) {
          logger.error(`[vrc-receive] exchange VRC refused for tx ${txId}:`, (err as Error)?.message);
          recordAbortReason(txId, err);
          return 'no';
        }
        continue;
      }

      // Legacy path: nothing to check beyond the shape above. The store and the ceremony leg are applied at commit
      // (both idempotent: digest dedup, flag set), so an undecided or aborted transaction leaves nothing behind.
      pending.push(params);
    }

    // Durably record 'prepared' BEFORE voting yes.
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome, pending_ops)
       VALUES (?, ?, 'prepared', ?)`,
      txId, this.pid, pending.length === 0 ? null : JSON.stringify(pending),
    );

    return 'yes';
  }

  /**
   * Conformant path, phase 1. Checks come from the exchange record, never from the sender's say-so, and run
   * before anything is stored. A different credential from the same counterparty relationship DID in
   * the same exchange is `alreadyIssued`; the same bytes again are an idempotent success.
   */
  private async checkExchangeVrc(params: StoreRemoteVrcParams): Promise<ExchangeDidRow> {
    const exchange = await exchangeDids.findByExchangeId(this.appDb, params.exchangeId as string);
    if (exchange === null || exchange.state === 'ended' || exchange.remoteRelationshipDid === null) {
      throw new TaskError({ reason: 'notAccepted', internalMessage: 'no accepted exchange for this VRC' });
    }
    if (exchange.localIdentityUuid === null || exchange.remoteIdentityUuid === null) {
      throw new TaskError({ reason: 'notAccepted', internalMessage: 'exchange identities are not mapped' });
    }
    const check = await checkIncomingVrc(
      params.w3cVcJson,
      exchange,
      this.innerProof === undefined ? undefined : { verifier: this.innerProof.verifier, nowMs: this.innerProof.now() },
    );
    if (!check.ok) {
      throw new TaskError({ reason: 'vcInvalid', internalMessage: `exchange VRC refused: ${check.reason}` });
    }
    const held = await findExchangeVrc(this.appDb, exchange, 'received');
    const digest = Array.from(sha256(new TextEncoder().encode(params.w3cVcJson)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    if (held !== null && held.digest !== digest) {
      throw new TaskError({
        code: 'vrc/relationships/issue:alreadyIssued',
        retryable: false,
        internalMessage: 'the exchange already holds a different credential',
      });
    }
    return exchange;
  }

  /** Conformant path, phase 2: store the credential against the exchange's root identities. Idempotent (digest dedup, state only moves forward). */
  private async applyExchangeVrc(params: StoreRemoteVrcParams): Promise<void> {
    const exchange = await this.checkExchangeVrc(params);
    this.vtcStore.storeReceivedDtgVrc(params.w3cVcJson, params.issuerDid, params.subjectDid, undefined, {
      issuerIdentityUuid: exchange.remoteIdentityUuid as string,
      subjectIdentityUuid: exchange.localIdentityUuid as string,
    });
    if (exchange.state === 'accepted') await exchangeDids.setState(this.appDb, exchange.exchangeId, 'received');
  }

  /** Legacy path, commit: store the remote peer's VRC and advance the mirrored ceremony session. Idempotent. */
  private async applyLegacyVrc(params: StoreRemoteVrcParams): Promise<void> {
    this.vtcStore.storeReceivedDtgVrc(params.w3cVcJson, params.issuerDid, params.subjectDid, params.issuerIdentity);
    // Ceremony sessions are keyed by real DIDs (local_did = subjectDid, remote_did = issuerDid), so both mirrors
    // reference the same (local,remote) DID pair and peer_vrc_received lands on the session the driver is advancing.
    if (params.subjectDid && params.issuerDid) {
      const session = await this.ceremonyStore.ensureSession(params.subjectDid, params.issuerDid);
      await this.ceremonyStore.setLeg(session.sessionId, { peerVrcReceived: true });
    }
    logger.info(`[vrc-receive] stored remote VRC from ${params.issuerDid.slice(0, 12)}...`);
  }

  async commit(txId: string): Promise<void> {
    const row = await this.txDb.get<{ outcome: string; pending_ops: string | null }>(
      'SELECT outcome, pending_ops FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId, this.pid,
    );
    if (row?.outcome === 'prepared' && row.pending_ops) {
      for (const params of JSON.parse(row.pending_ops) as StoreRemoteVrcParams[]) {
        if (params.exchangeId !== undefined) await this.applyExchangeVrc(params);
        else await this.applyLegacyVrc(params);
      }
    }
    await this.txDb.run(
      "UPDATE tx_participant_state SET outcome = 'committed' WHERE tx_id = ? AND pid = ?",
      txId, this.pid,
    );
    logger.info(`[vrc-receive] ${txId.slice(0, 8)} committed`);
  }

  async abort(txId: string): Promise<void> {
    // Neither path has stored anything before commit: dropping the recorded intent is the whole rollback.
    await this.txDb.run(
      "UPDATE tx_participant_state SET outcome = 'aborted', pending_ops = NULL WHERE tx_id = ? AND pid = ?",
      txId, this.pid,
    );
    logger.info(`[vrc-receive] ${txId.slice(0, 8)} aborted`);
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId, this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }
}
