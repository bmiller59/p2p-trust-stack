// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Policy for the private ceremony document types (conformance phase P8c, plan 2.1 `ceremony-doc`).
 *
 * Four documents drive the founding ceremony:
 *   - `ceremony:propose`  begin: the proposer names the community, its admins and the threshold;
 *   - `ceremony:co-sign`  approve: an admin accepts the named role;
 *   - `ceremony:status`   query: the ceremony's state (read only);
 *   - `ceremony:reset`    reset: abandon a failed or expired ceremony so it can be begun again.
 *
 * The ceremony id is the document's thread (`threadId`, else the begin document's `id`). Each type is
 * served under its boundary URN (the codec form of the internal name). All four need `recipient`;
 * the mutating ones need a proof and `issuedAt`. The payloads are closed.
 */
import { CEREMONY_CO_SIGN_TYPE, CEREMONY_PROPOSE_TYPE } from '../type-uris.js';
import { toWireTypeUri } from './urn-codec.js';
import type { SpecPolicy } from './runtime.js';

export const CEREMONY_STATUS_INTERNAL_NAME = 'task:p2pts:ceremony:status:0.1';
export const CEREMONY_RESET_INTERNAL_NAME = 'task:p2pts:ceremony:reset:0.1';

/** `urn:p2pts:tasks:spec:ceremony:propose:0.1` */
export const CEREMONY_PROPOSE_WIRE_TYPE = toWireTypeUri(CEREMONY_PROPOSE_TYPE) as string;
/** `urn:p2pts:tasks:spec:ceremony:co-sign:0.1` */
export const CEREMONY_CO_SIGN_WIRE_TYPE = toWireTypeUri(CEREMONY_CO_SIGN_TYPE) as string;
/** `urn:p2pts:tasks:spec:ceremony:status:0.1` */
export const CEREMONY_STATUS_WIRE_TYPE = toWireTypeUri(CEREMONY_STATUS_INTERNAL_NAME) as string;
/** `urn:p2pts:tasks:spec:ceremony:reset:0.1` */
export const CEREMONY_RESET_WIRE_TYPE = toWireTypeUri(CEREMONY_RESET_INTERNAL_NAME) as string;

export const CEREMONY_WIRE_TYPES = Object.freeze([
  CEREMONY_PROPOSE_WIRE_TYPE,
  CEREMONY_CO_SIGN_WIRE_TYPE,
  CEREMONY_STATUS_WIRE_TYPE,
  CEREMONY_RESET_WIRE_TYPE,
]);

const EXT = { type: 'object', minProperties: 1, additionalProperties: true } as const;
const NONEMPTY = { type: 'string', minLength: 1, maxLength: 2048 } as const;

export const CEREMONY_PROPOSE_PAYLOAD_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['name', 'kind', 'threshold', 'adminDids'],
  properties: {
    name: { type: 'string', minLength: 1, maxLength: 256 },
    kind: { type: 'string', enum: ['vtc', 'vtn'] },
    threshold: { type: 'integer', minimum: 1, maximum: 1000 },
    adminDids: { type: 'array', minItems: 1, maxItems: 100, items: NONEMPTY },
    parentCommunityDid: NONEMPTY,
    ext: EXT,
  },
} as const;

export const CEREMONY_CO_SIGN_PAYLOAD_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: { proposalHash: NONEMPTY, ext: EXT },
} as const;

export const CEREMONY_EMPTY_PAYLOAD_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: { ext: EXT },
} as const;

/** The closed status payload every ceremony reply states (`#response` of status and reset, and of a committed begin/co-sign). */
export const CEREMONY_RESPONSE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['ceremonyId', 'status', 'approvalCount', 'required'],
  properties: {
    ceremonyId: NONEMPTY,
    status: { type: 'string', enum: ['pending', 'crystallized', 'expired', 'failed', 'aborted'] },
    approvalCount: { type: 'integer', minimum: 0 },
    required: { type: 'integer', minimum: 1 },
    threshold: { type: 'integer', minimum: 1 },
    expiresAt: { type: 'string' },
    ext: EXT,
  },
} as const;

const mutating = (typeUri: string, payloadSchema: object): SpecPolicy => ({
  typeUri,
  isBearer: false,
  isProofRequired: true,
  isRecipientRequired: true,
  isIssuedAtRequired: true,
  payloadSchema,
});

export const CEREMONY_PROPOSE_SPEC: SpecPolicy = mutating(CEREMONY_PROPOSE_WIRE_TYPE, CEREMONY_PROPOSE_PAYLOAD_SCHEMA);
export const CEREMONY_CO_SIGN_SPEC: SpecPolicy = mutating(CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_CO_SIGN_PAYLOAD_SCHEMA);
export const CEREMONY_RESET_SPEC: SpecPolicy = mutating(CEREMONY_RESET_WIRE_TYPE, CEREMONY_EMPTY_PAYLOAD_SCHEMA);
/** A read: repeat-safe, and a proof is still required so the asker is a verified actor (the answer is not public). */
export const CEREMONY_STATUS_SPEC: SpecPolicy = {
  typeUri: CEREMONY_STATUS_WIRE_TYPE,
  isBearer: false,
  isProofRequired: true,
  isRecipientRequired: true,
  isIssuedAtRequired: false,
  payloadSchema: CEREMONY_EMPTY_PAYLOAD_SCHEMA,
};
