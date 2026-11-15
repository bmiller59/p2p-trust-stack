// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Shared pieces of the agent-side Trust Task boundary handlers (conformance phase P6): the wire type
 * URIs, the extended error codes and the authorisation rule every handler applies.
 */
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { HandlerContext } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';

export const PROPOSE_TYPE = 'https://trusttasks.org/spec/vrc/relationships/propose/0.1';
export const PROPOSE_RESPONSE_TYPE = `${PROPOSE_TYPE}#response`;
export const ISSUE_TYPE = 'https://trusttasks.org/spec/vrc/relationships/issue/0.1';
export const ISSUE_RESPONSE_TYPE = `${ISSUE_TYPE}#response`;

export {
  WITNESS_SHARE_NOT_ACCEPTED,
  WITNESS_SHARE_RESPONSE_TYPE,
  WITNESS_SHARE_TYPE,
  WITNESS_SHARE_URN_TYPE,
} from '@p2p-trust-stack/core/services/trust-tasks/boundary/witness-share-spec.js';

/** States of an exchange in which the counterparty's credential or witness share may be received. */
export const RECEIVING_STATES: ReadonlySet<string> = new Set(['accepted', 'received', 'issued-by-me']);

export const PROPOSE_DECLINED = 'vrc/relationships/propose:declined';
export const ISSUE_NOT_ACCEPTED = 'vrc/relationships/issue:notAccepted';
export const ISSUE_ALREADY_ISSUED = 'vrc/relationships/issue:alreadyIssued';

/**
 * The ACTOR of a document: the identity the carrier authenticated, or the signer of a proof the
 * pipeline verified (conformance AUTHZ-001). Proof is not authorisation: the actor must also be the
 * in-band `issuer`, and every handler authorises from this value, never from document claims.
 * Nothing here consults a claim inside the payload.
 */
export function actorOf(doc: { issuer?: unknown }, ctx: HandlerContext): string {
  const actor = ctx.sender ?? ctx.verifiedSigner;
  if (typeof actor !== 'string' || actor.length === 0 || typeof doc.issuer !== 'string' || doc.issuer !== actor) {
    throw new TaskError({ code: 'permissionDenied', retryable: false, internalMessage: 'no verified actor equal to the issuer' });
  }
  return actor;
}
