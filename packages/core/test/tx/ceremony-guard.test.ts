// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P5 (plan rows TIME, DUP, 2PC-004, 2PC-005): the shared ceremony-proposal guards and
 * their use by the core coordinator. In-memory databases only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_SCHEMA_SQL, applyTxSchemaAdditions } from '../../src/tx/schema.js';
import { CeremonyStore } from '../../src/tx/ceremony-store.js';
import { CeremonyCoordinator } from '../../src/tx/ceremony-coordinator.js';
import {
  ABORT_REASON_CAP, assertOpen, assertResettable, clearAbortReasons, closeIfLapsed,
  describeFailure, getAbortReason, isLapsed, recordAbortReason,
} from '../../src/tx/ceremony-guard.js';
import { TaskError, taskErrorForReason } from '../../src/services/trust-tasks/boundary/errors.js';
import type { GovernanceGuard } from '../../src/services/governance-guard.js';
import type { TransactionManager } from '../../src/tx/manager.js';

async function openStore() {
  const ds = new SqliteDataSource(':memory:');
  ds.getRawDb().exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(ds);
  return { ds, store: new CeremonyStore(ds) };
}

const base = { proposerDid: 'did:a', vtcDid: 'did:v', name: 'n', kind: 'vtc' as const, adminDids: ['did:a', 'did:b'], threshold: 2, proposalHash: 'h' };

function reasonOf(fn: () => void): string | undefined {
  try { fn(); } catch (e) { assert.ok(e instanceof TaskError); return e.reason ?? e.code; }
  return undefined;
}

test('TIME: a deadline that has been reached (>=) is lapsed; one millisecond before is open', () => {
  const p = { status: 'pending' as const, expiresAt: 1000 };
  assert.equal(isLapsed(p, 999), false);
  assert.equal(isLapsed(p, 1000), true);
  assert.doesNotThrow(() => assertOpen(p, 999));
  assert.equal(reasonOf(() => assertOpen(p, 1000)), 'deadlineLapsed');
});

test('2PC-004: assertOpen maps each terminal state to its closed reason and keeps the old text', () => {
  assert.equal(reasonOf(() => assertOpen({ status: 'crystallized', expiresAt: 9e15 })), 'alreadyCommitted');
  assert.equal(reasonOf(() => assertOpen({ status: 'expired', expiresAt: 9e15 })), 'deadlineLapsed');
  assert.equal(reasonOf(() => assertOpen({ status: 'failed', expiresAt: 9e15 })), 'taskFailed');
  assert.throws(() => assertOpen({ status: 'failed', expiresAt: 9e15 }), /proposal is failed/);
  assert.throws(() => assertOpen({ status: 'aborted', expiresAt: 9e15 }), /proposal is aborted/);
});

test('2PC-005: reset is allowed only from failed or expired', () => {
  assert.doesNotThrow(() => assertResettable({ status: 'failed' }));
  assert.doesNotThrow(() => assertResettable({ status: 'expired' }));
  assert.equal(reasonOf(() => assertResettable({ status: 'crystallized' })), 'alreadyCommitted');
  assert.equal(reasonOf(() => assertResettable({ status: 'pending' })), 'taskFailed');
  assert.equal(reasonOf(() => assertResettable({ status: 'aborted' })), 'taskFailed');
});

test('TIME: closeIfLapsed flips a lapsed pending proposal to expired with its code, once, and never touches a terminal one', async () => {
  const { ds, store } = await openStore();
  await store.createProposal({ ...base, proposalId: 'lapsed', expiresAt: 1000 });
  await store.createProposal({ ...base, proposalId: 'live', expiresAt: 9e15 });
  const lapsed = await store.getProposal('lapsed');
  const closed = await closeIfLapsed(store, lapsed!, 1000);
  assert.equal(closed.status, 'expired');
  const stored = await store.getProposal('lapsed');
  assert.equal(stored?.status, 'expired');
  assert.equal(stored?.errorCode, 'taskFailed');
  assert.equal(stored?.retryable, false);
  assert.match(stored?.errorReason ?? '', /deadline/);
  const live = await closeIfLapsed(store, (await store.getProposal('live'))!, 1000);
  assert.equal(live.status, 'pending');
  // a crystallized proposal is never rewritten, even when its deadline is behind it
  await store.createProposal({ ...base, proposalId: 'done', expiresAt: 1000 });
  await store.updateStatus('done', 'crystallized');
  await store.markExpired('done');
  assert.equal((await store.getProposal('done'))?.status, 'crystallized');
  await ds.close();
});

test('isCrystallizable uses the same rule: reaching the deadline expires the proposal', async () => {
  const { ds, store } = await openStore();
  await store.createProposal({ ...base, proposalId: 'p', expiresAt: Date.now() });
  await store.recordApproval('p', 'did:a', 's');
  await store.recordApproval('p', 'did:b', 's');
  assert.equal(await store.isCrystallizable('p'), false);
  assert.equal((await store.getProposal('p'))?.status, 'expired');
  await ds.close();
});

function coordinator(store: CeremonyStore, ds: SqliteDataSource) {
  const guard = { validateCrystallization: async () => ({ allowed: false, requireConsent: true, reason: 'quorum' }), validateParentVtnPolicy: async () => ({ allowed: true }) } as unknown as GovernanceGuard;
  return new CeremonyCoordinator({ store, guard, manager: {} as TransactionManager, appDb: ds });
}

test('TIME + 2PC-004 (core path): an approval at or after expiresAt is refused deadlineLapsed and the proposal flips to expired', async () => {
  const { ds, store } = await openStore();
  const c = coordinator(store, ds);
  const id = await c.initiateProposal({ name: 'late', kind: 'vtc', proposerDid: 'did:a', adminDids: ['did:a', 'did:b'], threshold: 2, ttlMs: 0 });
  await assert.rejects(() => c.recordApproval(id, 'did:a', 'sig'), (e: unknown) => e instanceof TaskError && e.reason === 'deadlineLapsed');
  const stored = await store.getProposal(id);
  assert.equal(stored?.status, 'expired');
  assert.equal(await store.countApprovals(id), 0, 'the late approval was not recorded');
  // the proposal is now terminal: a further approval is refused with the same reason
  await assert.rejects(() => c.recordApproval(id, 'did:b', 'sig'), (e: unknown) => e instanceof TaskError && e.reason === 'deadlineLapsed');
  await ds.close();
});

test('DUP (core path): the same approver approving twice is idempotent, not a failure and not a second row', async () => {
  const { ds, store } = await openStore();
  const c = coordinator(store, ds);
  const id = await c.initiateProposal({ name: 'dup', kind: 'vtc', proposerDid: 'did:a', adminDids: ['did:a', 'did:b'], threshold: 2, ttlMs: 60_000 });
  // requireConsent keeps it pending, but the crystallize check throws on a hard deny only
  const first = await c.recordApproval(id, 'did:a', 'sig').catch((e) => e);
  assert.ok(!(first instanceof Error) || /crystallization denied/.test(first.message));
  const again = await c.recordApproval(id, 'did:a', 'sig');
  assert.equal(again.recorded, false);
  assert.equal(await store.countApprovals(id), 1);
  await ds.close();
});

test('DUP (core path): a repeat approval after commit is a no-op for the approver who signed, alreadyCommitted for anyone else', async () => {
  const { ds, store } = await openStore();
  const c = coordinator(store, ds);
  await store.createProposal({ ...base, proposalId: 'c', expiresAt: 9e15 });
  await store.recordApproval('c', 'did:a', 's');
  await store.updateStatus('c', 'crystallized', Date.now());
  const again = await c.recordApproval('c', 'did:a', 's');
  assert.deepEqual({ r: again.recorded, c: again.crystallized, n: again.approvalCount }, { r: false, c: true, n: 1 });
  await assert.rejects(() => c.recordApproval('c', 'did:b', 's'), (e: unknown) => e instanceof TaskError && e.reason === 'alreadyCommitted');
  await ds.close();
});

test('abort-reason registry: records the closed reason by transaction id, bounded, newest kept', () => {
  clearAbortReasons();
  assert.deepEqual(recordAbortReason('tx1', taskErrorForReason('notFoundOrNotPermitted')), { code: 'permissionDenied', retryable: false, reason: 'notFoundOrNotPermitted' });
  assert.deepEqual(getAbortReason('tx1'), { code: 'permissionDenied', retryable: false, reason: 'notFoundOrNotPermitted' });
  assert.deepEqual(recordAbortReason('tx2', new Error('boom with internal detail')), { code: 'internalError', retryable: false });
  for (let i = 0; i < ABORT_REASON_CAP + 5; i++) recordAbortReason(`bulk-${i}`, new Error('x'));
  assert.equal(getAbortReason('tx1'), undefined, 'the oldest entry was evicted');
  assert.ok(getAbortReason(`bulk-${ABORT_REASON_CAP + 4}`));
  clearAbortReasons();
});

test('describeFailure: a typed error keeps its code and retryability; anything else is internalError', () => {
  assert.deepEqual(describeFailure(taskErrorForReason('storeFailed')), { code: 'unavailable', retryable: true, reason: 'storeFailed' });
  assert.deepEqual(describeFailure('nope'), { code: 'internalError', retryable: false });
});
