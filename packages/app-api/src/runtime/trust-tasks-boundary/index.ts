// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

export { VrcProposeService, HOLD_EVERYTHING, ensureRemoteIdentity } from './vrc-propose.js';
export type { ProposalInfo, ProposeConsentPolicy, ProposeDecision, VrcProposeDeps } from './vrc-propose.js';
export { createVrcIssueHandler } from './vrc-issue.js';
export type { IssueTransactions, VrcIssueDeps } from './vrc-issue.js';
export { settleAcceptedClaims } from './settle.js';
export * from './shared.js';
export { LISTENER_PATH, resolveListenerConfig, startBoundaryListener } from './listener.js';
export type { BoundaryListener, BoundaryListenerConfig } from './listener.js';
export { startAgentBoundary } from './agent-boundary.js';
export type { AgentBoundary, AgentBoundaryDeps } from './agent-boundary.js';
