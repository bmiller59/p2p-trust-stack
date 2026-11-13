// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Policy for the suite-local `vrc/relationships/witness-share/0.1` task (conformance phase P7).
 *
 * The registry has no such specification, so the policy is written by hand from the suite-local
 * profile (docs/10-witness-share-profile.md of the conformance suite), section 3 and 5. The payload
 * is closed; `presentation`, `outcomeEvidence.initiating` and `outcomeEvidence.terminal` are required;
 * the proof is REQUIRED on the request and optional on the receipt; `recipient` and `issuedAt` are
 * required (profile choice for `issuedAt`: the task mutates state).
 *
 * Wire types. The task is served under the registry-style URI the profile names and under the
 * boundary's URN codec form of the internal name `task:p2pts:vrc:witness-share:0.1`, so a peer that
 * addresses it either way reaches the same handler.
 */
import { toWireTypeUri } from './urn-codec.js';
import type { SpecPolicy } from './runtime.js';

export const WITNESS_SHARE_SLUG = 'vrc/relationships/witness-share';
export const WITNESS_SHARE_TYPE = 'https://trusttasks.org/spec/vrc/relationships/witness-share/0.1';
export const WITNESS_SHARE_RESPONSE_TYPE = `${WITNESS_SHARE_TYPE}#response`;
export const WITNESS_SHARE_INTERNAL_NAME = 'task:p2pts:vrc:witness-share:0.1';
/** `urn:p2pts:tasks:spec:vrc:witness-share:0.1` */
export const WITNESS_SHARE_URN_TYPE = toWireTypeUri(WITNESS_SHARE_INTERNAL_NAME) as string;
/** The challenge-binding domain of the presentation (profile 3.3). */
export const WITNESS_SHARE_DOMAIN = 'vrc:witness-share';
/** The extended error code for every handler-level refusal (framework 8.5; profile 5.2). */
export const WITNESS_SHARE_NOT_ACCEPTED = 'vrc/relationships/witness-share:notAccepted';

const DIGEST = { type: 'string', minLength: 16, pattern: '^(z[1-9A-HJ-NP-Za-km-z]+|u[A-Za-z0-9_-]+)$' } as const;
const EXT = { type: 'object', minProperties: 1, additionalProperties: true } as const;

export const WITNESS_SHARE_PAYLOAD_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['presentation', 'outcomeEvidence'],
  properties: {
    presentation: { type: 'object' },
    outcomeEvidence: {
      type: 'object',
      additionalProperties: false,
      required: ['initiating', 'terminal'],
      properties: { initiating: { type: 'object' }, terminal: { type: 'object' } },
    },
    ext: EXT,
  },
} as const;

export const WITNESS_SHARE_RESPONSE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['vwcDigestMultibase'],
  properties: { vwcDigestMultibase: DIGEST, ext: EXT },
} as const;

export const WITNESS_SHARE_SPEC: SpecPolicy = {
  typeUri: WITNESS_SHARE_TYPE,
  isBearer: false,
  isProofRequired: true,
  isRecipientRequired: true,
  isIssuedAtRequired: true,
  payloadSchema: WITNESS_SHARE_PAYLOAD_SCHEMA,
};

export const WITNESS_SHARE_RESPONSE_SPEC: SpecPolicy = {
  typeUri: WITNESS_SHARE_RESPONSE_TYPE,
  isBearer: false,
  isProofRequired: false,
  isRecipientRequired: true,
  isIssuedAtRequired: true,
  payloadSchema: WITNESS_SHARE_RESPONSE_SCHEMA,
};
