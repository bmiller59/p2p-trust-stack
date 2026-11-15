// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Wires the agent's Trust Task boundary (conformance phase P6c): the propose and issue handlers over
 * the agent's own stores, the durable duplicate record, proof-only authentication with the agent's
 * proof verifier, the signer the process installed at start, and the config-gated listener. Built
 * only when the listener is switched on; an agent that does not opt in runs none of this.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { AcceptedIdStore } from '@p2p-trust-stack/core/services/trust-tasks/boundary/accepted-store.js';
import { Pipeline } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pipeline.js';
import type { DidProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/verify.js';
import { getBoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { TrustTaskRecorder } from '@p2p-trust-stack/core/services/trust-tasks/boundary/recorder.js';
import type { TransactionManager } from '@p2p-trust-stack/core/tx/manager.js';
import { logger } from '@p2p-trust-stack/core/util/logger.js';
import type { VrcReceiveParticipant } from '../tx/vrc-receive-participant.js';
import type { WitnessShareParticipant } from '../tx/witness-share-participant.js';
import type { CredentialReceiveParticipant } from '../tx/credential-receive-participant.js';
import type { CredentialPresentationParticipant } from '../tx/credential-presentation-participant.js';
import { startBoundaryListener } from './listener.js';
import type { BoundaryListener, BoundaryListenerConfig } from './listener.js';
import { settleAcceptedClaims } from './settle.js';
import { HOLD_EVERYTHING, VrcProposeService } from './vrc-propose.js';
import type { ProposeConsentPolicy } from './vrc-propose.js';
import { createVrcIssueHandler } from './vrc-issue.js';
import { createWitnessShareHandler } from './witness-share.js';
import { createCredentialIssueHandler, createCredentialPresentHandler } from './credential-exchange.js';
import { createTaskConsentRequestHandler } from './task-consent.js';
import type { TaskConsentRequestDeps } from './task-consent.js';

export interface AgentBoundaryDeps {
  ds: DataSource;
  /** The agent's connection DID: the identifier the listener answers as. */
  did: string;
  /** The agent's key passphrase (custody of the per-exchange relationship keys). */
  passphrase: string;
  txManager: TransactionManager;
  receive: VrcReceiveParticipant;
  /** The witness share participant (`store_witness_share`). */
  witnessShare: WitnessShareParticipant;
  verifier: DidProofVerifier;
  /**
   * Layer 3b-DTG adapters (conformance P5b). Each is served only when its dependency is given: `credential-exchange/issue`
   * over the credential receive participant, `credential-exchange/present` over the presentation participant, and
   * `task-consent/request` (this device as the approver) when a consent policy is given. `task-consent/decision` is the
   * ceremony HOST's task and rides with the ceremony document handlers, which the agent listener does not serve.
   */
  credentialReceive?: CredentialReceiveParticipant;
  presentation?: CredentialPresentationParticipant;
  consent?: TaskConsentRequestDeps;
  config: BoundaryListenerConfig;
  /** Called when a proposal starts waiting for the human. */
  onHeld?: (exchangeId: string) => void;
}

export interface AgentBoundary {
  readonly propose: VrcProposeService;
  readonly listener: BoundaryListener;
  stop(): Promise<void>;
}

const DECLINE_ALL: ProposeConsentPolicy = { decide: () => 'decline' };
const SWEEP_MS = 60_000;

export async function startAgentBoundary(deps: AgentBoundaryDeps): Promise<AgentBoundary> {
  const identity = await identitiesRepo.findByRealDid(deps.ds, deps.did);
  if (identity === null) throw new Error('Trust Task listener: the agent has no identity row for its connection DID');
  if (getBoundarySigner()?.did !== deps.did) {
    throw new Error('Trust Task listener: no boundary signer is installed for the connection DID, so replies could not be signed');
  }

  const guard = new AcceptedIdStore(deps.ds);
  const propose = new VrcProposeService({
    db: deps.ds,
    localIdentityUuid: identity.uuid,
    passphrase: deps.passphrase,
    policy: deps.config.proposePolicy === 'decline' ? DECLINE_ALL : HOLD_EVERYTHING,
    ...(deps.onHeld === undefined ? {} : { onHeld: (row) => deps.onHeld!(row.exchangeId) }),
  });
  deps.receive.setInnerProofVerifier(deps.verifier);
  deps.witnessShare.setVerifier(deps.verifier);
  deps.presentation?.setVerifier(deps.verifier);
  const recorder = new TrustTaskRecorder(deps.ds, { node: 'agent', onError: (err) => logger.error('[trust-tasks] recording a document failed:', (err as Error)?.message) });
  const pipeline = new Pipeline({
    handlers: [
      propose.handler(),
      createVrcIssueHandler({
        db: deps.ds,
        txManager: deps.txManager,
        participant: deps.receive,
        verifier: deps.verifier,
        attachTx: (id, txId) => guard.attachTx(id, txId),
      }),
      createWitnessShareHandler({
        db: deps.ds,
        txManager: deps.txManager,
        participant: deps.witnessShare,
        verifier: deps.verifier,
        attachTx: (id, txId) => guard.attachTx(id, txId),
      }),
      ...(deps.credentialReceive === undefined ? [] : [createCredentialIssueHandler({ db: deps.ds, txManager: deps.txManager, participant: deps.credentialReceive, verifier: deps.verifier, attachTx: (id, txId) => guard.attachTx(id, txId) })]),
      ...(deps.presentation === undefined ? [] : [createCredentialPresentHandler({ txManager: deps.txManager, participant: deps.presentation, verifier: deps.verifier, attachTx: (id, txId) => guard.attachTx(id, txId) })]),
      ...(deps.consent === undefined ? [] : [createTaskConsentRequestHandler(deps.consent)]),
    ],
    servedVids: [deps.did],
    guard,
    proof: { verifier: deps.verifier, tier: deps.config.tier },
    signer: () => getBoundarySigner(),
    record: (result) => recorder.record(result),
    onUnexpected: (err) => logger.error('[trust-tasks] unexpected failure:', (err as Error)?.message),
  });

  const sweep = async (): Promise<void> => {
    try {
      await settleAcceptedClaims(guard, deps.txManager);
      await guard.pruneExpired();
      await propose.expireLapsed();
    } catch (err) {
      logger.error('[trust-tasks] settle sweep failed:', (err as Error)?.message);
    }
  };
  await sweep();
  const timer = setInterval(() => void sweep(), SWEEP_MS);
  timer.unref();

  const listener = await startBoundaryListener({
    host: deps.config.host,
    port: deps.config.port,
    process: (input) => pipeline.process(input),
    onError: (err) => logger.error('[trust-tasks] listener error:', (err as Error)?.message),
  });
  logger.info(`[trust-tasks] listener on ${listener.host}:${listener.port} (tier ${deps.config.tier}, proposals: ${deps.config.proposePolicy})`);
  return {
    propose,
    listener,
    stop: async () => {
      clearInterval(timer);
      await listener.close();
    },
  };
}
