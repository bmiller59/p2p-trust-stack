// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `task-consent/decision` 0.2 and `task-consent/request` 0.1 handlers (conformance phase P5b, layer 3b-DTG).
 *
 * DECISION (we are the executor that holds a pending ceremony). The decision is an approval (or a refusal) of the
 * existing ceremony hold, through the same participant and the same driver as a `ceremony:co-sign`:
 *   - the document proof is `assertionMethod` (the identity-key slot; the purpose pin is `ATTESTATION_SLUGS`) and the
 *     approver is the verified signer, equal to the envelope issuer (decision A4; nothing in the payload names anyone);
 *   - a ceremony the digest does not name is `noPending`; a signer outside the approver set is `notAnApprover` (consumer 5, after the binding checks);
 *   - `payloadDigest` and `challenge` are derived from the stored proposal (`core .../task-consent.ts`); a mismatch is
 *     `task-consent/decision:noPending` (digest) or `:challengeMismatch`; `actionId`, when present, must be the ceremony id;
 *   - `evidence` (WebAuthn, approver-signed statement) cannot be verified by this stack and is refused `:evidenceInvalid`;
 *     the policy never requires it, so `evidenceRequired` is never raised;
 *   - approve: recorded through `ceremony_approve` (the approval keeps its stored signature, the proof value of this
 *     document). The quorum met answers `#response {status: granted}`. A ceremony still waiting is answered with
 *     `trust-task-next-step` (decision 32: holds follow the framework), NOT with the specification's own `pending` status,
 *     which is therefore never emitted. A repeat by the same approver is a success again (double approve);
 *   - deny: closes the ceremony for every approver (`ceremony_deny`) and answers `#response {status: denied}`; a lapsed
 *     ceremony is `deadlineLapsed`, a committed one `alreadyCommitted`.
 *
 * REQUEST (we are the approver device). The request is verified (the executor must be one this device is enrolled
 * with, the device must not be the requester when `excludeRequester` is set, the request must not have lapsed) and a
 * prompt is raised for the human; the answer is the specification's own `prompted` acknowledgement (a human is in the loop,
 * so the decision arrives separately and is not a reply). The request document is retained verbatim by the recorder and
 * is the durable record of the hold; no table is added. Membership of the named `approverSet` is not evaluated (the set
 * is the executor's policy and the device has no such directory).
 */
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { HandlerContext, PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import type { TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { TASK_CONSENT_DECISION_SPEC, TASK_CONSENT_REQUEST_SPEC } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import {
  CONSENT_NOT_ELIGIBLE,
  CONSENT_NO_SURFACE,
  CONSENT_UNTRUSTED_ISSUER,
  DECISION_ACTION_MISMATCH,
  DECISION_CHALLENGE_MISMATCH,
  DECISION_EVIDENCE_INVALID,
  DECISION_NOT_AN_APPROVER,
  DECISION_NO_PENDING,
  TASK_CONSENT_DECISION_RESPONSE_TYPE,
  TASK_CONSENT_DECISION_TYPE,
  TASK_CONSENT_REQUEST_RESPONSE_TYPE,
  TASK_CONSENT_REQUEST_TYPE,
  parseConsentRequestPayload,
  parseDecisionPayload,
} from '@p2p-trust-stack/core/services/trust-tasks/boundary/task-consent.js';
import type { ConsentRequestPayload } from '@p2p-trust-stack/core/services/trust-tasks/boundary/task-consent.js';
import { CEREMONY_APPROVE, CEREMONY_DENY, declaredAdmins } from '../tx/ceremony-doc-participant.js';
import { actorOf } from './shared.js';
import { consentBinding, createCeremonyDriver } from './ceremony-doc.js';
import type { CeremonyDocDeps } from './ceremony-doc.js';

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function createTaskConsentDecisionHandler(deps: CeremonyDocDeps): PipelineHandler {
  const { store, reply, drive, runOperation } = createCeremonyDriver(deps);
  return {
    types: [TASK_CONSENT_DECISION_TYPE],
    spec: TASK_CONSENT_DECISION_SPEC,
    consequential: true,
    handle: async (doc, ctx) => {
      const actor = actorOf(doc, ctx);
      // Consumer 1: refuse any proof purpose but assertionMethod, at every tier (the pipeline pins it at Tier 2 only).
      const proof = (doc as { proof?: unknown }).proof;
      if (isObj(proof) && proof.proofPurpose !== 'assertionMethod') throw new TaskError({ code: 'proofInvalid', retryable: false, internalMessage: 'a consent decision must be proven under assertionMethod' });
      const decision = parseDecisionPayload(doc.payload);
      // Consumer 2: the pending request is found by `payloadDigest` (the thread names it too when the producer set one; a
      // decision need not carry a thread). Absent, or one whose digest this is not: `noPending`.
      const threadId = typeof doc.threadId === 'string' && doc.threadId !== '' ? doc.threadId : undefined;
      const byThread = threadId === undefined ? null : await store.getProposal(threadId);
      const stored = byThread ?? (await store.listPending()).find((p) => consentBinding(p).payloadDigest === decision.payloadDigest) ?? null;
      const binding = stored === null ? undefined : consentBinding(stored);
      if (stored === null || binding === undefined || decision.payloadDigest !== binding.payloadDigest) throw new TaskError({ code: DECISION_NO_PENDING, retryable: false, internalMessage: 'no pending consent for this digest' });
      const ceremonyId = stored.proposalId;
      // Consumers 3 to 5, in the specification's order, then 7 (evidence).
      if (decision.challenge !== binding.challenge) throw new TaskError({ code: DECISION_CHALLENGE_MISMATCH, retryable: false, internalMessage: 'challenge does not match' });
      if (decision.actionId !== undefined && decision.actionId !== ceremonyId) throw new TaskError({ code: DECISION_ACTION_MISMATCH, retryable: false, internalMessage: 'actionId names another action' });
      if (!declaredAdmins(stored).has(actor)) throw new TaskError({ code: DECISION_NOT_AN_APPROVER, retryable: false, internalMessage: 'the proven signer is not in the approver set' });
      if (decision.hasEvidence) throw new TaskError({ code: DECISION_EVIDENCE_INVALID, retryable: false, internalMessage: 'evidence cannot be verified by this stack' });

      if (decision.decision === 'deny') {
        await runOperation(doc, { op: CEREMONY_DENY, params: { ceremonyId, approverDid: actor, nowMs: ctx.now } }, 'denial');
        return reply(doc, ctx, actor, ceremonyId, { status: 'denied', payloadDigest: binding.payloadDigest });
      }
      const signature = isObj(proof) && typeof proof.proofValue === 'string' ? proof.proofValue : '';
      return drive(
        doc,
        ctx,
        actor,
        ceremonyId,
        { op: CEREMONY_APPROVE, params: { ceremonyId, approverDid: actor, signature, verified: true, nowMs: ctx.now } },
        (_p, approvals) => ({ status: 'granted', payloadDigest: binding.payloadDigest, approvals }),
      );
    },
  };
}

/** What the device shows its human when a consent request arrives. */
export interface ConsentPrompt {
  requestId: string;
  threadId: string;
  /** The executor that asked (the verified sender). */
  executor: string;
  request: ConsentRequestPayload;
  note?: string;
}

export interface TaskConsentRequestDeps {
  /** Whether `did` is an executor this device is enrolled with. A request from anyone else never prompts. */
  isEnrolledExecutor: (did: string) => Promise<boolean> | boolean;
  /** Raise the prompt. Absent means the device has no consent surface (`noSurface`, retryable). */
  prompt?: (prompt: ConsentPrompt) => Promise<void> | void;
}

export function createTaskConsentRequestHandler(deps: TaskConsentRequestDeps): PipelineHandler {
  return {
    types: [TASK_CONSENT_REQUEST_TYPE],
    spec: TASK_CONSENT_REQUEST_SPEC,
    consequential: true,
    handle: async (doc: TrustTaskDocument<unknown>, ctx: HandlerContext) => {
      const actor = actorOf(doc, ctx);
      const request = parseConsentRequestPayload(doc.payload);
      if (!(await deps.isEnrolledExecutor(actor))) throw new TaskError({ code: CONSENT_UNTRUSTED_ISSUER, retryable: false, internalMessage: 'the executor is not enrolled with this device' });
      const me = ctx.myVid ?? (doc.recipient as string);
      if (request.excludeRequester && request.requester === me) throw new TaskError({ code: CONSENT_NOT_ELIGIBLE, retryable: false, internalMessage: 'this device is the requester and the requester is excluded' });
      if (request.expiresAtMs <= ctx.now) throw new TaskError({ reason: 'deadlineLapsed', internalMessage: 'the consent request has lapsed' });
      if (deps.prompt === undefined) throw new TaskError({ code: CONSENT_NO_SURFACE, retryable: true, internalMessage: 'no consent surface is available' });
      const threadId = typeof doc.threadId === 'string' && doc.threadId !== '' ? doc.threadId : String(doc.id);
      const note = isObj(doc.payload) && typeof doc.payload.note === 'string' ? doc.payload.note : undefined;
      await deps.prompt({ requestId: String(doc.id), threadId, executor: actor, request, ...(note === undefined ? {} : { note }) });
      return {
        id: ctx.newId(),
        threadId,
        type: TASK_CONSENT_REQUEST_RESPONSE_TYPE,
        issuer: me,
        recipient: actor,
        issuedAt: ctx.clock(),
        payload: { status: 'prompted' },
      } as unknown as TrustTaskDocument<unknown>;
    },
  };
}

export { TASK_CONSENT_DECISION_RESPONSE_TYPE };
