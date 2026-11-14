// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `task-consent/{request,decision}` (conformance phase P5b, layer 3b-DTG): the pure parts.
 *
 * VERSION CHOICE (recorded; the registry text decides). `task-consent/decision` has 0.1 and 0.2 in the
 * pinned library. 0.1 declares `superseded by task-consent/decision/0.2` and targets framework 0.5.0;
 * 0.2 is additive over it (optional `evidence` and `actionId`, the proof "always by the approver's own DID")
 * and targets 0.6.0, the framework pin of this stack. This stack serves **0.2 only**. A 0.1 document gets
 * `unsupportedVersion` with `servedVersions: ["0.2"]` from the pipeline. `task-consent/request` has only 0.1.
 *
 * What the stack maps onto. The existing ceremony hold (a pending ceremony awaiting its admins) is the
 * "pending privileged task"; an approval is a recorded `ceremony_approvals` row whose signature is the
 * approver's proof value over the proposal binding (unchanged). The spec's per-request `challenge` and
 * `payloadDigest` are derived from the stored proposal (below), so no new column is needed.
 *
 * Specification-silent choices, each tested:
 *  - challenge = multibase multihash of the canonical `{ceremonyId, proposalHash, purpose}`. The spec asks for a nonce
 *    of at least 128 bits; this is 256 bits and unique per ceremony, but it is derived, not secret.
 *  - payloadDigest = multibase multihash of the canonical `{challenge, payload, taskType}` where the payload is the
 *    ceremony's proposal content (name, kind, threshold, sorted adminDids, parentCommunityDid or null) and the
 *    task type is the ceremony begin type. The spec fixes the inputs but not the composition.
 */
import { TaskError } from './errors.js';
import { digestMultibaseOf } from './proof/digest.js';

export const TASK_CONSENT_REQUEST_TYPE = 'https://trusttasks.org/spec/task-consent/request/0.1';
export const TASK_CONSENT_REQUEST_RESPONSE_TYPE = `${TASK_CONSENT_REQUEST_TYPE}#response`;
export const TASK_CONSENT_DECISION_TYPE = 'https://trusttasks.org/spec/task-consent/decision/0.2';
export const TASK_CONSENT_DECISION_RESPONSE_TYPE = `${TASK_CONSENT_DECISION_TYPE}#response`;
/** The decision versions served, for the record and the test. */
export const TASK_CONSENT_DECISION_SERVED_VERSIONS: readonly string[] = ['0.2'];

export const CONSENT_UNTRUSTED_ISSUER = 'task-consent/request:untrustedIssuer';
export const CONSENT_NOT_ELIGIBLE = 'task-consent/request:notEligible';
export const CONSENT_NO_SURFACE = 'task-consent/request:noSurface';
export const DECISION_NO_PENDING = 'task-consent/decision:noPending';
export const DECISION_CHALLENGE_MISMATCH = 'task-consent/decision:challengeMismatch';
export const DECISION_ACTION_MISMATCH = 'task-consent/decision:actionMismatch';
export const DECISION_EVIDENCE_INVALID = 'task-consent/decision:evidenceInvalid';

const DIGEST = /^(z[1-9A-HJ-NP-Za-km-z]+|u[A-Za-z0-9_-]+)$/;
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const malformed = (why: string): TaskError => new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: why });

export const isDigestMultibase = (v: unknown): v is string => typeof v === 'string' && v.length >= 16 && DIGEST.test(v);

/** The proposal content a consent decision binds (a ceremony begin payload, normalised). */
export interface ConsentSubject {
  name: string;
  kind: string;
  threshold: number;
  adminDids: readonly string[];
  parentCommunityDid: string | null;
}

export function consentChallenge(input: { ceremonyId: string; proposalHash: string }): string {
  return digestMultibaseOf({ purpose: 'p2pts/task-consent/challenge/0.1', ceremonyId: input.ceremonyId, proposalHash: input.proposalHash });
}

export function consentPayloadDigest(input: { taskType: string; subject: ConsentSubject; challenge: string }): string {
  const payload = {
    name: input.subject.name,
    kind: input.subject.kind,
    threshold: input.subject.threshold,
    adminDids: [...new Set(input.subject.adminDids)].sort(),
    parentCommunityDid: input.subject.parentCommunityDid,
  };
  return digestMultibaseOf({ challenge: input.challenge, payload, taskType: input.taskType });
}

export interface DecisionPayload {
  challenge: string;
  payloadDigest: string;
  decision: 'approve' | 'deny';
  reason?: string;
  actionId?: string;
  /** True when the decision carries an `evidence` member (which this stack cannot verify). */
  hasEvidence: boolean;
}

/** The payload rules the small schema reader does not enforce (lengths, enum, digest form). Throws `malformedRequest`. */
export function parseDecisionPayload(payload: unknown): DecisionPayload {
  if (!isObj(payload)) throw malformed('the decision payload is not an object');
  const { challenge, payloadDigest, decision, reason, actionId, evidence } = payload;
  if (typeof challenge !== 'string' || challenge.length < 16) throw malformed('challenge');
  if (!isDigestMultibase(payloadDigest)) throw malformed('payloadDigest');
  if (decision !== 'approve' && decision !== 'deny') throw malformed('decision');
  if (reason !== undefined && (typeof reason !== 'string' || reason.length > 500)) throw malformed('reason');
  if (actionId !== undefined && (typeof actionId !== 'string' || actionId.length < 1 || actionId.length > 128)) throw malformed('actionId');
  if (evidence !== undefined && !isObj(evidence)) throw malformed('evidence');
  return {
    challenge,
    payloadDigest,
    decision,
    ...(reason === undefined ? {} : { reason }),
    ...(actionId === undefined ? {} : { actionId }),
    hasEvidence: evidence !== undefined,
  };
}

export interface ConsentRequestPayload {
  challenge: string;
  taskType: string;
  payloadDigest: string;
  requester: string;
  approverSet: string;
  minApprovals: number;
  excludeRequester: boolean;
  /** Epoch ms. */
  expiresAtMs: number;
}

/** The payload rules of a consent request beyond the small schema reader. Throws `malformedRequest`. */
export function parseConsentRequestPayload(payload: unknown): ConsentRequestPayload {
  if (!isObj(payload)) throw malformed('the request payload is not an object');
  const p = payload;
  if (typeof p.challenge !== 'string' || p.challenge.length < 16) throw malformed('challenge');
  if (typeof p.taskType !== 'string' || !/^[A-Za-z][A-Za-z0-9+.-]*:/.test(p.taskType)) throw malformed('taskType');
  if (!isDigestMultibase(p.payloadDigest)) throw malformed('payloadDigest');
  if (!['none', 'mutating', 'destructive'].includes(String(p.sideEffects))) throw malformed('sideEffects');
  if (!isObj(p.exposure) || typeof p.exposure.actsAsSubject !== 'boolean' || !['none', 'metadata', 'secret'].includes(String(p.exposure.discloses))) throw malformed('exposure');
  if (!Array.isArray(p.effects)) throw malformed('effects');
  if (typeof p.requester !== 'string' || p.requester === '') throw malformed('requester');
  if (typeof p.approverSet !== 'string' || p.approverSet === '') throw malformed('approverSet');
  if (typeof p.minApprovals !== 'number' || !Number.isInteger(p.minApprovals) || p.minApprovals < 1) throw malformed('minApprovals');
  if (typeof p.excludeRequester !== 'boolean') throw malformed('excludeRequester');
  if (typeof p.expiresAt !== 'string') throw malformed('expiresAt');
  const expiresAtMs = Date.parse(p.expiresAt);
  if (!Number.isFinite(expiresAtMs)) throw malformed('expiresAt');
  if (p.note !== undefined && (typeof p.note !== 'string' || p.note.length < 1 || p.note.length > 500)) throw malformed('note');
  return {
    challenge: p.challenge,
    taskType: p.taskType,
    payloadDigest: p.payloadDigest,
    requester: p.requester,
    approverSet: p.approverSet,
    minApprovals: p.minApprovals,
    excludeRequester: p.excludeRequester,
    expiresAtMs,
  };
}
