// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Shared pieces of the agent-side Trust Task boundary handlers (conformance phase P6): the wire type
 * URIs, the extended error codes and the authorisation rule every handler applies.
 */

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

export { actorOf } from '@p2p-trust-stack/core/services/trust-tasks/boundary/actor.js';
