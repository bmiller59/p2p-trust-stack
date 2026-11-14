// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `credential-exchange/issue` and `credential-exchange/present` handlers (conformance phase P5b, layer 3b-DTG).
 * Policy and the pure checks are in core (`boundary/credential-exchange.ts`); the rules are stated there.
 *
 * ISSUE (we are the holder) rides the EXISTING credential delivery: the credential is enlisted as an
 * `exchange:credential` operation on the credential receive participant, the same participant the server's queue
 * fan-out feeds, so there is one place that stores a delivered credential. The adapter verifies first (the
 * participant's own verify and binding policies default to `warn`, which stores anyway). Idempotent by digest:
 * the credential id is derived from the digest of its canonical text, and the participant skips a uuid it holds.
 * The task has no response document: an accepted delivery is answered 204.
 *
 * PRESENT (we are the verifier) is new: there is no existing operation. `store_presentation` on
 * `CredentialPresentationParticipant` keeps the presentation as evidence (migration 0023). The nonce is the
 * thread; it is single use. No response document, so an accepted presentation is answered 204.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as credentialsRepo from '@p2p-trust-stack/core/db/repositories/credentials-repo.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import {
  CREDENTIAL_ISSUE_TYPE,
  CREDENTIAL_PRESENT_TYPE,
  checkIssuedCredential,
  checkPresentation,
  issueRefusal,
  parseIssuePayload,
  presentRefusal,
} from '@p2p-trust-stack/core/services/trust-tasks/boundary/credential-exchange.js';
import type { CredentialProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/credential-exchange.js';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { HandlerContext, PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { CREDENTIAL_ISSUE_SPEC, CREDENTIAL_PRESENT_SPEC, canonicalJson } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import type { TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { getAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { Operation, Participant, TransactionResult } from '@p2p-trust-stack/core/tx/types.js';
import { STORE_PRESENTATION } from '../tx/credential-presentation-participant.js';
import type { CredentialPushData } from '../tx/credential-receive-participant.js';
import { actorOf } from './shared.js';

export interface CredentialExchangeTransactions {
  run(fn: (tx: { enlist(participant: Participant, operations: Operation[]): void }) => Promise<void>): Promise<TransactionResult>;
}

export interface CredentialIssueDeps {
  db: DataSource;
  txManager: CredentialExchangeTransactions;
  /** The credential receive participant (`exchange:credential`). */
  participant: Participant;
  verifier: CredentialProofVerifier;
  attachTx?: (documentId: string, txId: string) => Promise<void>;
}

export interface CredentialPresentDeps {
  txManager: CredentialExchangeTransactions;
  /** The presentation participant (`store_presentation`). */
  participant: Participant;
  verifier: CredentialProofVerifier;
  attachTx?: (documentId: string, txId: string) => Promise<void>;
}

const storeFailed = (internal: string): TaskError => new TaskError({ reason: 'storeFailed', internalMessage: internal });

export function createCredentialIssueHandler(deps: CredentialIssueDeps): PipelineHandler {
  return {
    types: [CREDENTIAL_ISSUE_TYPE],
    spec: CREDENTIAL_ISSUE_SPEC,
    consequential: true,
    handle: async (doc: TrustTaskDocument<unknown>, ctx: HandlerContext) => {
      const actor = actorOf(doc, ctx);
      const holder = ctx.myVid ?? (doc.recipient as string);
      const shape = parseIssuePayload(doc.payload);
      if (!shape.ok) throw issueRefusal(shape.reason, `issue payload: ${shape.reason}`);
      const check = await checkIssuedCredential(shape.credential, { sender: actor, holder }, { verifier: deps.verifier, nowMs: ctx.now });
      if (!check.ok) throw issueRefusal(check.reason, `credential refused: ${check.reason}${check.detail === undefined ? '' : ` (${check.detail})`}`);

      const self = await identitiesRepo.findByRealDid(deps.db, holder);
      if (self === null) throw storeFailed('the holder has no identity row');
      const issuerIdentityUuid = (await identitiesRepo.findByRealDid(deps.db, check.issuerDid))?.uuid ?? didToUuid(check.issuerDid);
      const nowSec = Math.floor(ctx.now / 1000);
      const push: CredentialPushData = {
        credentialUuid: check.credentialUuid,
        vcType: check.vcType,
        issuerIdentityUuid,
        subjectIdentityUuid: self.uuid,
        w3cVcJson: check.text,
        claim: canonicalJson((shape.credential as { credentialSubject?: unknown }).credentialSubject ?? {}),
        status: 'issued',
        validFrom: check.validFromSec ?? nowSec,
        validUntil: check.validUntilSec,
        credentialDigest: check.digestHex,
        createdAt: nowSec,
        issuerDid: check.issuerDid,
        subjectDid: check.subjectDid,
      };
      const result = await deps.txManager.run(async (tx) => {
        tx.enlist(deps.participant, [{ op: 'exchange:credential', params: push as unknown as Record<string, unknown> }]);
      });
      if (typeof doc.id === 'string') await deps.attachTx?.(doc.id, result.txId).catch(() => undefined);
      if (result.outcome !== 'committed') throw storeFailed('the credential receive participant refused the delivery');
      // Only what is in the table counts: a committed transaction whose row is absent is not an acceptance.
      const row = await credentialsRepo.findByUuid(deps.db, check.credentialUuid);
      if (row === null) throw storeFailed('committed but the credential is not in the table');
      return undefined;
    },
  };
}

export function createCredentialPresentHandler(deps: CredentialPresentDeps): PipelineHandler {
  return {
    types: [CREDENTIAL_PRESENT_TYPE],
    spec: CREDENTIAL_PRESENT_SPEC,
    consequential: true,
    handle: async (doc: TrustTaskDocument<unknown>, ctx: HandlerContext) => {
      const actor = actorOf(doc, ctx);
      const audience = ctx.myVid ?? (doc.recipient as string);
      const token = (doc.payload as { vp_token?: unknown }).vp_token;
      if (token === undefined) throw new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: 'no vp_token' });
      // The nonce is the exchange thread the verifier opened; a document with no thread has none.
      const threadId = typeof doc.threadId === 'string' && doc.threadId !== '' ? doc.threadId : undefined;
      if (threadId === undefined) throw presentRefusal('staleNonce', 'no thread to hold a nonce');
      // The cheap, pure verdict first, so a bad presentation is refused with its own reason before anything is enlisted.
      const check = await checkPresentation(token, { holder: actor, audience, nonce: threadId }, { verifier: deps.verifier, nowMs: ctx.now });
      if (!check.ok) throw presentRefusal(check.reason, `presentation refused: ${check.reason}${check.detail === undefined ? '' : ` (${check.detail})`}`);
      const result = await deps.txManager.run(async (tx) => {
        tx.enlist(deps.participant, [{ op: STORE_PRESENTATION, params: { vpJson: canonicalJson(token), holderDid: actor, audience, threadId, documentId: String(doc.id) } }]);
      });
      if (typeof doc.id === 'string') await deps.attachTx?.(doc.id, result.txId).catch(() => undefined);
      if (result.outcome !== 'committed') {
        const why = getAbortReason(result.txId);
        if (why === undefined) throw storeFailed('the presentation was refused');
        throw new TaskError({ code: why.code, retryable: why.retryable, ...(why.reason === undefined ? {} : { reason: why.reason }), internalMessage: 'the presentation was refused' });
      }
      return undefined;
    },
  };
}
