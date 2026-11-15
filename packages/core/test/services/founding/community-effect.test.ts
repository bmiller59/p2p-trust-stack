// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The real ceremony host effect (item 1: D1.1 to D1.3) over the REAL `createVtc` on an in-memory database, driven
 * through the real ceremony-doc participant and a real two-phase-commit coordinator (log in a database). Nothing
 * here is a fixture of the establishment itself: a community either exists with its founding admins, VMCs and
 * trust-task records, or it does not.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../../src/db/migrate.js';
import { getMigrationsDir } from '../../../src/db/migrations-dir.js';
import * as identitiesRepo from '../../../src/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../../../src/db/repositories/did-documents-repo.js';
import * as peerEndpointsRepo from '../../../src/db/repositories/peer-endpoints-repo.js';
import * as relationshipsRepo from '../../../src/db/repositories/relationships-repo.js';
import * as trustTasksRepo from '../../../src/db/repositories/trust-tasks-repo.js';
import * as keysRepo from '../../../src/db/repositories/keys-repo.js';
import { CompensationExecutor, DataSourceLogSink, TransactionCoordinator, TransactionLog, TransactionManager, TX_ADDITIVE_COLUMNS, TX_SCHEMA_SQL } from '../../../src/tx/index.js';
import type { Operation, Participant, Vote, Outcome } from '../../../src/tx/types.js';
import { CEREMONY_APPROVE, CEREMONY_BEGIN, CeremonyDocParticipant } from '../../../src/tx/ceremony-doc-participant.js';
import { clearAbortReasons, getAbortReason } from '../../../src/tx/ceremony-guard.js';
import { CommunityFoundingEffect } from '../../../src/services/founding/community-effect.js';
import type { EstablishedCommunity } from '../../../src/services/founding/community-effect.js';
import { generateEd25519KeyPair } from '../../../src/crypto/primitives.js';
import { VTC_ESTABLISH_TYPE } from '../../../src/services/trust-tasks/type-uris.js';
import { GovernanceGuard } from '../../../src/services/governance-guard.js';
import { LocalPolicyEngine } from '../../../src/services/local-policy-engine.js';

const T0 = 1_000_000;

interface World {
  appDb: SqliteDataSource;
  txDb: SqliteDataSource;
  effect: CommunityFoundingEffect;
  participant: CeremonyDocParticipant;
  txm: TransactionManager;
  fanouts: EstablishedCommunity[];
  uuids: Record<string, string>;
}

async function vta(db: SqliteDataSource, did: string, o: { endpoint?: boolean; key?: Uint8Array } = {}): Promise<string> {
  const uuid = await identitiesRepo.create(db, { realDid: did, role: 'vta', subjectKind: 'human', name: did });
  await didDocumentsRepo.create(db, { identityUuid: uuid, did, method: 'scid', isPrimary: true });
  if (o.endpoint !== false) await peerEndpointsRepo.upsertForIdentity(db, { identityUuid: uuid, peerId: `peer-${uuid}`, multiaddrs: ['/ip4/127.0.0.1/tcp/1'] });
  if (o.key !== undefined) await keysRepo.create(db, { identityUuid: uuid, keyType: 'ed25519', publicKey: Buffer.from(o.key) });
  return uuid;
}

async function world(opts: { admins?: string[]; link?: boolean; verified?: boolean } = {}): Promise<World> {
  clearAbortReasons();
  const appDb = new SqliteDataSource(':memory:');
  runMigrations(appDb.getRawDb(), getMigrationsDir());
  const txDb = new SqliteDataSource(':memory:');
  txDb.getRawDb().exec(TX_SCHEMA_SQL);
  for (const col of TX_ADDITIVE_COLUMNS) { try { txDb.getRawDb().exec(col.ddl); } catch { /* present */ } }
  const uuids: Record<string, string> = {};
  for (const did of opts.admins ?? ['did:example:a', 'did:example:b']) uuids[did] = await vta(appDb, did);
  const ids = Object.values(uuids);
  if (opts.link !== false) for (const other of ids.slice(1)) await relationshipsRepo.create(appDb, { localIdentityUuid: ids[0]!, remoteIdentityUuid: other, direction: 'bidirectional', status: 'established' });
  const fanouts: EstablishedCommunity[] = [];
  const effect = new CommunityFoundingEffect(appDb, { afterEstablished: async (c) => { fanouts.push(c); } });
  const participant = new CeremonyDocParticipant('ceremony:host', txDb, effect, { requireVerifiedApprovals: opts.verified !== false });
  const txm = new TransactionManager(new TransactionCoordinator(new TransactionLog(new DataSourceLogSink(txDb))), new CompensationExecutor());
  return { appDb, txDb, effect, participant, txm, fanouts, uuids };
}

const A = 'did:example:a';
const B = 'did:example:b';
const run = (w: World, participant: Participant, op: Operation, extra: Participant[] = []) => w.txm.run(async (tx) => {
  tx.enlist(participant, [op]);
  for (const p of extra) tx.enlist(p, [{ op: 'noop', params: {} }]);
});
const begin = (w: World, extra: Record<string, unknown> = {}, id = 'c1') => run(w, w.participant, { op: CEREMONY_BEGIN, params: { ceremonyId: id, proposerDid: A, name: 'Real Club', kind: 'vtc', threshold: 2, adminDids: [A, B], verified: true, nowMs: T0, ...extra } });
const approve = (w: World, who: string, extra: Record<string, unknown> = {}, id = 'c1', extraParticipants: Participant[] = []) => run(w, w.participant, { op: CEREMONY_APPROVE, params: { ceremonyId: id, approverDid: who, signature: `proof-${who}`, verified: true, nowMs: T0 + 1, ...extra } }, extraParticipants);
const communities = async (w: World) => (await w.appDb.get<{ n: number }>("SELECT COUNT(*) AS n FROM identities WHERE role IN ('vtc','vtn')"))!.n;
const status = async (w: World, id = 'c1') => (await w.participant.store.getProposal(id))!;

class Veto implements Participant {
  readonly pid = 'veto';
  committed = 0;
  async prepare(): Promise<Vote> { return 'no'; }
  async commit(): Promise<void> { this.committed += 1; }
  async abort(): Promise<void> {}
  async compensate(): Promise<void> {}
  async inquiry(): Promise<Outcome> { return 'aborted'; }
  async query(): Promise<unknown> { return null; }
  handlesOperation(op: Operation): boolean { return op.op === 'noop'; }
}

test('quorum commit creates exactly one community with its founding admins and VMCs, records the thread and queues the fan-out once', async () => {
  const w = await world();
  assert.equal((await begin(w)).outcome, 'committed');
  assert.equal((await approve(w, A)).outcome, 'committed');
  assert.equal(await communities(w), 0, 'no effect before the quorum');
  assert.equal((await approve(w, B)).outcome, 'committed');

  assert.equal(await communities(w), 1);
  const stored = await status(w);
  assert.equal(stored.status, 'crystallized');
  const community = (await w.appDb.get<{ uuid: string; name: string }>("SELECT uuid, name FROM identities WHERE role = 'vtc'"))!;
  assert.equal(community.name, 'Real Club');
  const members = await w.appDb.all<{ role: string; membership_credential_uuid: string | null }>('SELECT role, membership_credential_uuid FROM memberships WHERE community_identity_uuid = ?', community.uuid);
  assert.equal(members.length, 2);
  assert.ok(members.every((m) => m.role === 'founding_admin' && m.membership_credential_uuid !== null), 'every founding admin holds a VMC');
  const thread = await trustTasksRepo.listByThread(w.appDb, 'c1');
  assert.ok(thread.some((r) => r.type === VTC_ESTABLISH_TYPE && r.direction === 'response' && r.status === 'completed'), 'the establishment is in the task log under the ceremony id');
  assert.equal(w.fanouts.length, 1, 'fan-out queued once');
  assert.equal(w.fanouts[0]!.communityUuid, community.uuid);
  assert.equal(w.fanouts[0]!.foundingAdmins.length, 2);
  assert.equal(w.fanouts[0]!.replayed, false);
});

test('replay is idempotent: a repeated approval and a repeated commit create no second community and no second fan-out', async () => {
  const w = await world();
  await begin(w); await approve(w, A); await approve(w, B);
  await approve(w, B);
  await approve(w, A);
  assert.equal(await communities(w), 1);
  assert.equal(w.fanouts.length, 1);
  // A commit that is re-delivered after the fact is also a no-op.
  const row = (await w.txDb.get<{ tx_id: string }>("SELECT tx_id FROM tx_participant_state WHERE pid = 'ceremony:host' AND pending_ops LIKE '%did:example:b%' ORDER BY rowid LIMIT 1"))!;
  await w.participant.commit(row.tx_id);
  assert.equal(await communities(w), 1);
  assert.equal(w.fanouts.length, 1);
});

test('a taken name leaves no second community and a failed ceremony with the closed reason nameTaken', async () => {
  const w = await world();
  await begin(w); await approve(w, A); await approve(w, B);
  assert.equal(await communities(w), 1);
  await begin(w, {}, 'c2'); await approve(w, A, {}, 'c2');
  const refused = await approve(w, B, {}, 'c2');
  assert.equal(refused.outcome, 'aborted');
  assert.equal(getAbortReason(refused.txId)?.reason, 'nameTaken');
  assert.equal(await communities(w), 1, 'still one');
  const failed = await status(w, 'c2');
  assert.equal(failed.status, 'failed');
  assert.equal(failed.errorReason, 'nameTaken');
  assert.equal(w.fanouts.length, 1);
});

test('a parent VTN policy denial leaves nothing and a failed ceremony (policyDenied)', async () => {
  const w = await world();
  const vtn = await identitiesRepo.create(w.appDb, { realDid: 'did:example:net', role: 'vtn', name: 'Net' });
  await didDocumentsRepo.create(w.appDb, { identityUuid: vtn, did: 'did:example:net', method: 'scid', isPrimary: true });
  // The network accepts only VTN children.
  const { seedDefaultBindings } = await import('../../../src/services/policy-bindings.js');
  await seedDefaultBindings(w.appDb, vtn, 'vtn', { allowedChildKinds: ['vtn'] });
  await begin(w, { parentCommunityDid: 'did:example:net' }); await approve(w, A);
  const refused = await approve(w, B);
  assert.equal(refused.outcome, 'aborted');
  assert.equal(getAbortReason(refused.txId)?.reason, 'policyDenied');
  assert.equal((await w.appDb.get<{ n: number }>("SELECT COUNT(*) AS n FROM identities WHERE role = 'vtc'"))!.n, 0);
  assert.equal((await status(w)).status, 'failed');
  assert.equal(w.fanouts.length, 0);
});

test('an admin without a mutual VRC (createVtc validation) is refused at the gate: nothing created, ceremony failed', async () => {
  const w = await world({ link: false });
  await begin(w); await approve(w, A);
  const refused = await approve(w, B);
  assert.equal(refused.outcome, 'aborted');
  assert.equal(getAbortReason(refused.txId)?.reason, 'policyDenied');
  assert.equal(await communities(w), 0);
  assert.equal((await status(w)).status, 'failed');
});

test('a begin naming an admin the server does not know is refused before anything is stored', async () => {
  const w = await world();
  const refused = await begin(w, { adminDids: [A, 'did:example:stranger'] });
  assert.equal(refused.outcome, 'aborted');
  assert.equal(await w.participant.store.getProposal('c1'), null);
});

test('abort after the gate leaves nothing: a second participant votes no after the effect was checked', async () => {
  const w = await world();
  await begin(w); await approve(w, A);
  const aborted = await approve(w, B, {}, 'c1', [new Veto()]);
  assert.equal(aborted.outcome, 'aborted');
  assert.equal(await communities(w), 0);
  assert.equal(w.fanouts.length, 0);
  const stored = await status(w);
  assert.equal(stored.status, 'pending');
  assert.equal((await w.participant.store.getApprovals('c1')).length, 1, 'only the committed first approval');
  // The ceremony is still completable.
  assert.equal((await approve(w, B)).outcome, 'committed');
  assert.equal(await communities(w), 1);
});

test('crash between the apply and the status update: restart reconciles, one community, the fan-out runs again for the replay', async () => {
  const w = await world();
  await begin(w); await approve(w, A);
  const realUpdate = w.participant.store.updateStatus.bind(w.participant.store);
  w.participant.store.updateStatus = async () => { throw new Error('process died'); };
  const result = await approve(w, B);
  assert.equal(result.outcome, 'committed', 'the coordinator decided commit');
  assert.equal(await communities(w), 1, 'the establishment is durable');
  assert.equal((await status(w)).status, 'pending', 'but the ceremony was not marked');
  assert.equal(await w.participant.inquiry(result.txId), 'prepared');
  w.participant.store.updateStatus = realUpdate;

  // Restart.
  const again = new CeremonyDocParticipant('ceremony:host', w.txDb, w.effect, { requireVerifiedApprovals: true });
  const reconciled = await again.reconcile((id) => w.txm.getOutcome(id));
  assert.deepEqual(reconciled.committed, [result.txId]);
  assert.equal(await communities(w), 1, 'no second community');
  assert.equal((await again.store.getProposal('c1'))!.status, 'crystallized');
  assert.ok(w.fanouts.some((f) => f.replayed), 'the fan-out is at-least-once: the replay runs it again');
});

test('non-admin and unknown ceremony are the same refusal, and nothing is checked or created', async () => {
  const w = await world();
  await begin(w);
  const intruder = await approve(w, 'did:example:intruder');
  const unknown = await approve(w, A, {}, 'nope');
  assert.equal(intruder.outcome, 'aborted');
  assert.deepEqual(getAbortReason(intruder.txId), getAbortReason(unknown.txId));
  assert.equal(getAbortReason(intruder.txId)?.reason, 'notFoundOrNotPermitted');
  assert.equal(await communities(w), 0);
});

test('deadline edge: the approval that would complete the quorum at expiresAt is refused deadlineLapsed and creates nothing', async () => {
  const w = await world();
  await begin(w); await approve(w, A);
  const expiresAt = (await status(w)).expiresAt;
  const late = await approve(w, B, { nowMs: expiresAt });
  assert.equal(late.outcome, 'aborted');
  assert.equal(getAbortReason(late.txId)?.reason, 'deadlineLapsed');
  assert.equal(await communities(w), 0);
  assert.equal((await status(w)).status, 'expired');
});

test('stub admin: an endpoint-less did:peer:4 stub is mapped to the real VTA that shares its key, and that one founds the community', async () => {
  const w = await world({ admins: [A] });
  const key = generateEd25519KeyPair().publicKey;
  // B's real VTA (endpoint, key) and the TSP-bridge stub the ceremony's admin DID resolves to (no endpoint, same key).
  const real = await vta(w.appDb, 'did:example:b-real', { key });
  await relationshipsRepo.create(w.appDb, { localIdentityUuid: w.uuids[A]!, remoteIdentityUuid: real, direction: 'bidirectional', status: 'established' });
  await vta(w.appDb, 'did:peer:4zstub', { endpoint: false, key });
  const b = await begin(w, { adminDids: [A, 'did:peer:4zstub'] });
  assert.equal(b.outcome, 'committed', JSON.stringify(getAbortReason(b.txId)));
  await approve(w, A);
  const done = await approve(w, 'did:peer:4zstub');
  assert.equal(done.outcome, 'committed', JSON.stringify(getAbortReason(done.txId)));
  assert.equal(await communities(w), 1);
  const founders = (await w.appDb.all<{ member_identity_uuid: string }>("SELECT member_identity_uuid FROM memberships WHERE role = 'founding_admin'")).map((r) => r.member_identity_uuid);
  assert.ok(founders.includes(real), 'the real VTA, not the stub, is the founding admin');
});

test('D1.1: approvals pre-verified by the boundary count without a signature over the hash; the same approvals unmarked do not', async () => {
  // Host that relies on the boundary (requireVerifiedApprovals): the proof values are not signatures over the hash, and it counts.
  const real = await world();
  await begin(real); await approve(real, A);
  assert.equal((await approve(real, B)).outcome, 'committed');
  assert.equal(await communities(real), 1);

  // A host that does NOT mark approvals verified falls back to the legacy signature check: a proof value is not a signature, nothing counts.
  const unmarked = await world({ verified: false });
  await begin(unmarked, { verified: undefined }); await approve(unmarked, A, { verified: undefined });
  const refused = await approve(unmarked, B, { verified: undefined });
  assert.equal(refused.outcome, 'aborted');
  assert.equal(getAbortReason(refused.txId)?.reason, 'policyDenied');
  assert.equal(await communities(unmarked), 0);
});

test('D1.1: an approval that did not come through the boundary handler is refused by a host that requires verification', async () => {
  const w = await world();
  await begin(w);
  const raw = await approve(w, A, { verified: undefined });
  assert.equal(raw.outcome, 'aborted');
  assert.equal((await w.participant.store.getApprovals('c1')).length, 0, 'a forged or unverified approval is never recorded, so it never counts');
});

test('the guard is the same one: a stricter guard (policy engine) is honoured by the host', async () => {
  const w = await world();
  const strict = new CommunityFoundingEffect(w.appDb, { guard: new GovernanceGuard(w.appDb, new LocalPolicyEngine()) });
  await assert.doesNotReject(() => strict.checkProposal({ ceremonyId: 'x', proposerDid: A, name: 'X', kind: 'vtc', adminDids: [A, B], threshold: 2, parentCommunityDid: null }));
});

test('the establishment is atomic: a failure after the community row was written rolls everything back, and the retry after restart creates exactly one', async () => {
  const w = await world();
  await begin(w); await approve(w, A);
  const realRun = w.appDb.run.bind(w.appDb);
  w.appDb.run = (async (sql: string, ...params: unknown[]) => {
    if (/INSERT\s+INTO\s+memberships/i.test(sql)) throw new Error('disk full');
    return realRun(sql, ...params);
  }) as typeof w.appDb.run;
  const result = await approve(w, B);
  assert.equal(result.outcome, 'committed', 'the coordinator decided commit');
  assert.equal(await communities(w), 0, 'the half-written community was rolled back');
  assert.equal(await w.participant.inquiry(result.txId), 'prepared', 'the commit stays open for a retry');
  assert.equal((await status(w)).status, 'pending');
  w.appDb.run = realRun as typeof w.appDb.run;
  const again = new CeremonyDocParticipant('ceremony:host', w.txDb, w.effect, { requireVerifiedApprovals: true });
  assert.deepEqual((await again.reconcile((id) => w.txm.getOutcome(id))).committed, [result.txId]);
  assert.equal(await communities(w), 1);
  assert.equal((await again.store.getProposal('c1'))!.status, 'crystallized');
});

test('a name taken between the check and the commit is recorded as the ceremony\'s failure (nameTaken) and the commit finishes', async () => {
  const w = await world();
  await begin(w);
  await approve(w, A);
  // The gate passes inside this transaction; another community takes the name before the commit runs.
  const p = w.participant;
  const txId = 'tx-race';
  assert.equal(await p.prepare(txId, [{ op: CEREMONY_APPROVE, params: { ceremonyId: 'c1', approverDid: B, signature: 'proof-b', verified: true, nowMs: T0 + 1 } }]), 'yes');
  await identitiesRepo.create(w.appDb, { realDid: 'did:example:other-club', role: 'vtc', name: 'Real Club' });
  await p.commit(txId);
  const stored = await status(w);
  assert.equal(stored.status, 'failed');
  assert.equal(stored.errorReason, 'nameTaken');
  assert.equal(await p.inquiry(txId), 'committed');
  assert.equal(await communities(w), 1, 'only the other community exists');
});

test('a fan-out that throws never fails the commit: the community exists and the ceremony is crystallized', async () => {
  const w = await world();
  const failing = new CommunityFoundingEffect(w.appDb, { afterEstablished: async () => { throw new Error('queue down'); } });
  const participant = new CeremonyDocParticipant('ceremony:host', w.txDb, failing, { requireVerifiedApprovals: true });
  const w2 = { ...w, participant, effect: failing };
  await begin(w2); await approve(w2, A);
  const done = await approve(w2, B);
  assert.equal(done.outcome, 'committed');
  assert.equal(await communities(w2), 1);
  assert.equal(await w2.participant.inquiry(done.txId), 'committed');
  assert.equal((await status(w2)).status, 'crystallized');
});

test('a repeated approval after a crash between the apply and the status update retries cleanly: the check passes for the already-established ceremony, no second community', async () => {
  const w = await world();
  await begin(w); await approve(w, A);
  const realUpdate = w.participant.store.updateStatus.bind(w.participant.store);
  w.participant.store.updateStatus = async () => { throw new Error('process died'); };
  await approve(w, B);
  w.participant.store.updateStatus = realUpdate;
  assert.equal(await communities(w), 1);
  const repeat = await approve(w, B);
  assert.equal(repeat.outcome, 'committed', JSON.stringify(getAbortReason(repeat.txId)));
  assert.equal(await communities(w), 1);
  assert.equal((await status(w)).status, 'crystallized');
});
