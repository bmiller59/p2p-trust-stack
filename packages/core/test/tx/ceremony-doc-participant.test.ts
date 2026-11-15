// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * D1.3 on the ceremony-doc participant: the establishing effect is CHECKED at prepare (a refusal is still a veto and
 * leaves the ceremony `failed` with its closed reason) and APPLIED at commit from the intent recorded in
 * `pending_ops`. An abort leaves nothing; a commit that is re-run applies once; a crash between the apply and the
 * status update is repaired by the commit or by `reconcile`. D1.1: a host that relies on the boundary's verified proof
 * refuses an approval that did not come through it and tells the effect which approvals are verified.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { TX_ADDITIVE_COLUMNS, TX_SCHEMA_SQL } from '../../src/tx/schema.js';
import { CeremonyDocParticipant, CEREMONY_APPROVE, CEREMONY_BEGIN } from '../../src/tx/ceremony-doc-participant.js';
import type { CeremonyEffect, CeremonyEstablishment, CeremonyProposalInput } from '../../src/tx/ceremony-doc-participant.js';
import { clearAbortReasons, getAbortReason } from '../../src/tx/ceremony-guard.js';
import { TaskError } from '../../src/services/trust-tasks/boundary/errors.js';

const A = 'did:example:a';
const B = 'did:example:b';
const T0 = 1_000_000;

function openTx(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  ds.getRawDb().exec(TX_SCHEMA_SQL);
  for (const col of TX_ADDITIVE_COLUMNS) { try { ds.getRawDb().exec(col.ddl); } catch { /* already present */ } }
  return ds;
}

class SpyEffect implements CeremonyEffect {
  proposals: CeremonyProposalInput[] = [];
  checks: CeremonyEstablishment[] = [];
  applies: CeremonyEstablishment[] = [];
  established = new Set<string>();
  checkError: Error | undefined;
  applyError: Error | undefined;
  refuseProposal: Error | undefined;
  async checkProposal(input: CeremonyProposalInput): Promise<void> {
    if (this.refuseProposal) throw this.refuseProposal;
    this.proposals.push(input);
  }
  async check(input: CeremonyEstablishment): Promise<void> {
    this.checks.push(input);
    if (this.checkError) throw this.checkError;
  }
  async apply(input: CeremonyEstablishment): Promise<void> {
    if (this.applyError) throw this.applyError;
    this.applies.push(input);
    this.established.add(input.ceremonyId); // idempotent per ceremony id: a set
  }
}

function setup(options: ConstructorParameters<typeof CeremonyDocParticipant>[3] = {}) {
  clearAbortReasons();
  const txDb = openTx();
  const effect = new SpyEffect();
  const p = new CeremonyDocParticipant('ceremony:test', txDb, effect, options);
  return { txDb, effect, p };
}

const begin = (p: CeremonyDocParticipant, tx: string, extra: Record<string, unknown> = {}) =>
  p.prepare(tx, [{ op: CEREMONY_BEGIN, params: { ceremonyId: 'c1', proposerDid: A, name: 'Club', kind: 'vtc', threshold: 2, adminDids: [A, B], nowMs: T0, ...extra } }]);
const approve = (p: CeremonyDocParticipant, tx: string, who: string, extra: Record<string, unknown> = {}) =>
  p.prepare(tx, [{ op: CEREMONY_APPROVE, params: { ceremonyId: 'c1', approverDid: who, signature: `proof-${who}`, nowMs: T0 + 1, ...extra } }]);
const status = async (p: CeremonyDocParticipant) => (await p.store.getProposal('c1'))!;
const approvals = async (p: CeremonyDocParticipant) => (await p.store.getApprovals('c1')).length;

async function quorumPrepared() {
  const s = setup();
  assert.equal(await begin(s.p, 'tx-begin'), 'yes');
  await s.p.commit('tx-begin');
  assert.equal(await approve(s.p, 'tx-a', A), 'yes');
  await s.p.commit('tx-a');
  assert.equal(await approve(s.p, 'tx-b', B), 'yes');
  return s;
}

test('quorum: the effect is checked at prepare and applied once at commit, which crystallizes the ceremony', async () => {
  const { p, effect } = await quorumPrepared();
  assert.equal(effect.checks.length, 1, 'the gate ran at prepare');
  assert.equal(effect.applies.length, 0, 'nothing applied before the decision');
  assert.equal((await status(p)).status, 'pending');
  assert.equal(await approvals(p), 1, 'the approval that completes the quorum is recorded at commit, not at prepare');
  await p.commit('tx-b');
  assert.equal(effect.applies.length, 1);
  assert.equal((await status(p)).status, 'crystallized');
  assert.equal(await approvals(p), 2);
  assert.equal(await p.inquiry('tx-b'), 'committed');
});

test('a commit that is delivered twice applies once; a repeated approval after commit is a no-op', async () => {
  const { p, effect } = await quorumPrepared();
  await p.commit('tx-b');
  await p.commit('tx-b');
  assert.equal(effect.applies.length, 1);
  assert.equal(await approve(p, 'tx-b-again', B), 'yes');
  await p.commit('tx-b-again');
  assert.equal(effect.checks.length, 1, 'no second gate for a finished ceremony');
  assert.equal(effect.applies.length, 1);
  assert.equal((await status(p)).status, 'crystallized');
});

test('abort after the gate leaves nothing: no effect, no approval recorded, the ceremony stays pending, the intent is dropped', async () => {
  const { p, effect, txDb } = await quorumPrepared();
  await p.abort('tx-b');
  assert.equal(effect.applies.length, 0);
  assert.equal((await status(p)).status, 'pending');
  assert.equal(await approvals(p), 1, 'only the earlier committed approval');
  assert.equal(await p.inquiry('tx-b'), 'aborted');
  const row = await txDb.get<{ pending_ops: string | null }>("SELECT pending_ops FROM tx_participant_state WHERE tx_id = 'tx-b'");
  assert.equal(row?.pending_ops, null);
  // A commit arriving after an abort cannot resurrect the intent.
  await p.commit('tx-b');
  assert.equal(effect.applies.length, 0);
});

test('a refusal at the gate (nameTaken) votes no, applies nothing and leaves a failed ceremony with the closed reason', async () => {
  const { p, effect } = setup();
  await begin(p, 'tx-begin'); await p.commit('tx-begin');
  await approve(p, 'tx-a', A); await p.commit('tx-a');
  effect.checkError = new TaskError({ reason: 'nameTaken', internalMessage: 'taken' });
  assert.equal(await approve(p, 'tx-b', B), 'no');
  assert.equal(getAbortReason('tx-b')?.reason, 'nameTaken');
  assert.equal(effect.applies.length, 0);
  const stored = await status(p);
  assert.equal(stored.status, 'failed');
  assert.equal(stored.errorReason, 'nameTaken');
  assert.equal(stored.errorCode, 'taskFailed');
  assert.equal(await approvals(p), 2, 'the admin did approve; the refusal is the effect\'s');
});

test('an unreadable effect outcome (indeterminate) votes no, keeps the ceremony pending, and a repeated approval retries', async () => {
  const { p, effect } = setup();
  await begin(p, 'tx-begin'); await p.commit('tx-begin');
  await approve(p, 'tx-a', A); await p.commit('tx-a');
  effect.checkError = new TaskError({ code: 'indeterminate', retryable: true, internalMessage: 'cannot read' });
  assert.equal(await approve(p, 'tx-b', B), 'no');
  assert.equal(getAbortReason('tx-b')?.code, 'indeterminate');
  assert.equal((await status(p)).status, 'pending');
  effect.checkError = undefined;
  assert.equal(await approve(p, 'tx-b2', B), 'yes', 'the repeat re-runs the gate');
  await p.commit('tx-b2');
  assert.equal(effect.applies.length, 1);
  assert.equal((await status(p)).status, 'crystallized');
});

test('a refusal that slips past the gate (a race before commit) is recorded as the ceremony\'s failure and the commit still finishes', async () => {
  const { p, effect } = await quorumPrepared();
  effect.applyError = new TaskError({ reason: 'nameTaken', internalMessage: 'taken since the check' });
  await p.commit('tx-b');
  const stored = await status(p);
  assert.equal(stored.status, 'failed');
  assert.equal(stored.errorReason, 'nameTaken');
  assert.equal(await p.inquiry('tx-b'), 'committed');
});

test('crash between the apply and the status update: the commit stays prepared, a new instance reconciles it, one effect', async () => {
  const { p, effect, txDb } = await quorumPrepared();
  const realUpdate = p.store.updateStatus.bind(p.store);
  p.store.updateStatus = async () => { throw new Error('process died'); };
  await assert.rejects(() => p.commit('tx-b'), /process died/);
  assert.equal(effect.established.size, 1, 'the effect ran');
  assert.equal(await p.inquiry('tx-b'), 'prepared', 'the participant never reached committed');
  assert.equal((await status(p)).status, 'pending');
  p.store.updateStatus = realUpdate;

  // Restart: a fresh participant over the same database; the coordinator's log says committed.
  const again = new CeremonyDocParticipant('ceremony:test', txDb, effect);
  const result = await again.reconcile(async (id) => (id === 'tx-b' ? 'committed' : 'unknown'));
  assert.deepEqual(result.committed, ['tx-b']);
  assert.equal(effect.established.size, 1, 'the idempotent effect created nothing twice');
  assert.equal((await status(again)).status, 'crystallized');
  assert.equal(await again.inquiry('tx-b'), 'committed');
  // Nothing is left to reconcile.
  assert.deepEqual(await again.reconcile(async () => 'committed'), { committed: [], aborted: [], failed: [] });
});

test('reconcile aborts what the coordinator aborted and leaves undecided transactions alone', async () => {
  const { p, effect, txDb } = await quorumPrepared();
  const fresh = new CeremonyDocParticipant('ceremony:test', txDb, effect);
  assert.deepEqual(await fresh.reconcile(async () => 'inFlight'), { committed: [], aborted: [], failed: [] });
  assert.equal(await fresh.inquiry('tx-b'), 'prepared');
  assert.deepEqual((await fresh.reconcile(async () => 'aborted')).aborted, ['tx-b']);
  assert.equal(effect.applies.length, 0);
  assert.equal((await status(p)).status, 'pending');
});

test('deadline edge: an approval at expiresAt is deadlineLapsed (no gate, no effect), one millisecond earlier is accepted', async () => {
  const s1 = setup({ ttlMs: 1000 });
  await begin(s1.p, 'tx-begin'); await s1.p.commit('tx-begin');
  const expiresAt = (await status(s1.p)).expiresAt;
  assert.equal(expiresAt, T0 + 1000);
  assert.equal(await approve(s1.p, 'tx-late', A, { nowMs: expiresAt }), 'no');
  assert.equal(getAbortReason('tx-late')?.reason, 'deadlineLapsed');
  assert.equal(s1.effect.checks.length, 0);
  assert.equal((await status(s1.p)).status, 'expired');

  const s2 = setup({ ttlMs: 1000 });
  await begin(s2.p, 'tx-begin'); await s2.p.commit('tx-begin');
  assert.equal(await approve(s2.p, 'tx-edge', A, { nowMs: expiresAt - 1 }), 'yes');
});

test('non-admin and unknown ceremony are one answer, decided before anything is revealed or checked', async () => {
  const { p, effect } = setup();
  await begin(p, 'tx-begin'); await p.commit('tx-begin');
  assert.equal(await approve(p, 'tx-x', 'did:example:intruder'), 'no');
  const nonAdmin = getAbortReason('tx-x');
  assert.equal(await p.prepare('tx-y', [{ op: CEREMONY_APPROVE, params: { ceremonyId: 'nope', approverDid: A, signature: 's', nowMs: T0 } }]), 'no');
  assert.deepEqual(getAbortReason('tx-y'), nonAdmin);
  assert.equal(nonAdmin?.reason, 'notFoundOrNotPermitted');
  assert.equal(effect.checks.length, 0);
  assert.equal(await approvals(p), 0);
});

test('a begin is checked before anything is stored (an admin the host cannot map is refused, nothing is created)', async () => {
  const { p, effect } = setup();
  effect.refuseProposal = new TaskError({ reason: 'notAdmin', internalMessage: 'unknown admin' });
  assert.equal(await begin(p, 'tx-begin'), 'no');
  assert.equal(await p.store.getProposal('c1'), null);
  effect.refuseProposal = undefined;
  assert.equal(await begin(p, 'tx-begin2'), 'yes');
  assert.equal(effect.proposals.length, 1);
});

test('proposerApproves with one admin: gate at prepare, effect and approval at commit', async () => {
  const { p, effect } = setup({ proposerApproves: true });
  assert.equal(await p.prepare('tx-solo', [{ op: CEREMONY_BEGIN, params: { ceremonyId: 'c1', proposerDid: A, name: 'Solo', kind: 'vtc', threshold: 1, adminDids: [A], signature: 'proof-a', nowMs: T0 } }]), 'yes');
  assert.equal(effect.checks.length, 1);
  assert.equal(effect.applies.length, 0);
  assert.equal(await approvals(p), 0);
  await p.commit('tx-solo');
  assert.equal(effect.applies.length, 1);
  assert.equal((await status(p)).status, 'crystallized');
});

test('D1.1: a host that requires verified approvals refuses one that did not come through the boundary, and marks the rest verified', async () => {
  const { p, effect } = setup({ requireVerifiedApprovals: true });
  await begin(p, 'tx-begin'); await p.commit('tx-begin');
  assert.equal(await approve(p, 'tx-raw', A), 'no', 'no boundary verification, no approval');
  assert.equal(getAbortReason('tx-raw')?.reason, 'notFoundOrNotPermitted');
  assert.equal(await approvals(p), 0);
  assert.equal(await approve(p, 'tx-a', A, { verified: true }), 'yes'); await p.commit('tx-a');
  assert.equal(await approve(p, 'tx-b', B, { verified: true }), 'yes');
  assert.ok(effect.checks[0]!.approvals.every((a) => a.verified), 'every approval handed to the effect is marked verified');
  assert.deepEqual(effect.checks[0]!.approvals.map((a) => a.signature).sort(), ['proof-did:example:a', 'proof-did:example:b']);
});

test('without requireVerifiedApprovals the approvals are handed over unverified (the default is unchanged)', async () => {
  const { p, effect } = setup();
  await begin(p, 'tx-begin'); await p.commit('tx-begin');
  await approve(p, 'tx-a', A); await p.commit('tx-a');
  await approve(p, 'tx-b', B);
  assert.ok(effect.checks[0]!.approvals.every((a) => a.verified === false));
});
