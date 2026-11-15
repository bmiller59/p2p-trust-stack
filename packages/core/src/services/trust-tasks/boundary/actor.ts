// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { TaskError } from './errors.js';
import type { HandlerContext } from './handlers.js';

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
