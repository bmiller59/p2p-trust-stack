// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The legacy `policy/evaluate` handler (conformance plan P2): the one task the HTTPS bridge has
 * served since P5.5, moved onto the pipeline unchanged in behaviour. The pipeline now does the
 * envelope, type, freshness, recipient and sender work that used to be spread over the route; what
 * remains here is the business logic: resolve the community the `recipient` names, run the policy
 * gate with real facts, wrap the decision.
 *
 * Served under the internal name (`task:p2pts:policy:evaluate:0.1`, kept for one release so existing
 * clients keep working) and under its valid wire form (`urn:p2pts:tasks:spec:policy:evaluate:0.1`,
 * urn-codec.ts).
 *
 * Actor (conformance P5, decision C5, AUTHZ-001): the policy actor is the VERIFIED sender, never the
 * in-band `issuer` on its own. The sender is the transport-authenticated identity (the session
 * cookie), else the signer of a verified proof. With neither, the caller is unauthenticated and the
 * answer is `permissionDenied` (behaviour change from P2, which fell back to the in-band issuer or
 * the community's own DID and so evaluated as the community itself).
 */
import type { DataSource } from '../../../db/data-source.js';
import * as identitiesRepo from '../../../db/repositories/identities-repo.js';
import { POLICY_ACTIONS } from '../../policy-engine.js';
import type { PolicyQuery } from '../../policy-engine.js';
import { gatePolicy } from '../../policy-gate.js';
import { buildResponse } from '../envelope.js';
import { POLICY_EVALUATE_TYPE } from '../type-uris.js';
import { TaskError } from './errors.js';
import type { PipelineHandler } from './handlers.js';
import type { TrustTaskDocument } from './runtime.js';
import { toWireTypeUri } from './urn-codec.js';

/** The wire form of the evaluate type (derived, never typed by hand). */
export const POLICY_EVALUATE_WIRE_TYPE = toWireTypeUri(POLICY_EVALUATE_TYPE)!;

export const LEGACY_EVALUATE_SCHEMA = {
  type: 'object',
  required: ['action'],
  properties: {
    action: { type: 'string' },
    kind: { type: 'string' },
    subjectDid: { type: 'string' },
    facts: { type: 'object' },
  },
} as const;

/** Whether `recipient` is a community this server hosts (the pipeline's "is this ours?"). */
export async function isHostedCommunity(db: DataSource, recipient: string): Promise<boolean> {
  const identity = await identitiesRepo.findByRealDid(db, recipient);
  return identity !== undefined && identity !== null && !!identity.did;
}

export function createLegacyEvaluateHandler(db: DataSource): PipelineHandler {
  return {
    types: [POLICY_EVALUATE_WIRE_TYPE, POLICY_EVALUATE_TYPE],
    spec: {
      typeUri: POLICY_EVALUATE_WIRE_TYPE,
      isBearer: false,
      isProofRequired: false,
      isRecipientRequired: true,
      isIssuedAtRequired: false,
      payloadSchema: LEGACY_EVALUATE_SCHEMA,
    },
    consequential: false,
    async handle(doc: TrustTaskDocument<unknown>, ctx) {
      // The verified sender is the actor; no verified sender is not an actor at all. Checked first, so an
      // unauthenticated caller cannot tell a hosted community from an unknown one.
      const actor = ctx.sender ?? ctx.verifiedSigner;
      if (typeof actor !== 'string' || actor.length === 0) {
        throw new TaskError({ code: 'permissionDenied', retryable: false, internalMessage: 'evaluate requires an authenticated sender' });
      }
      const identity = await identitiesRepo.findByRealDid(db, String(doc.recipient ?? ''));
      if (!identity || !identity.did) {
        throw new TaskError({ code: 'wrongRecipient', internalMessage: `community ${String(doc.recipient)} not found` });
      }
      const p = (doc.payload ?? {}) as Record<string, unknown>;
      const action = p.action;
      if (typeof action !== 'string' || !action) {
        throw new TaskError({ code: 'malformedRequest', internalMessage: 'payload.action is required' });
      }
      if (!(POLICY_ACTIONS as readonly string[]).includes(action)) {
        throw new TaskError({ code: 'malformedRequest', internalMessage: `unknown action '${action}'` });
      }
      const params: Record<string, unknown> = {};
      if (p.kind !== undefined) params.kind = p.kind;
      if (p.subjectDid !== undefined) params.subjectDid = p.subjectDid;
      const query: PolicyQuery = {
        action: action as PolicyQuery['action'],
        communityDid: identity.did,
        actorDid: actor,
        params,
      };
      const facts = p.facts && typeof p.facts === 'object' ? (p.facts as Record<string, unknown>) : undefined;
      const result = await gatePolicy(db, query, facts);
      return buildResponse(
        doc as unknown as Parameters<typeof buildResponse>[0],
        { communityUuid: identity.uuid, communityDid: identity.did, query, result },
        { newId: ctx.newId, now: ctx.clock },
      ) as unknown as TrustTaskDocument<unknown>;
    },
  };
}
