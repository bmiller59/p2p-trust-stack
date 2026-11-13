// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P3 persistence: migration 0021 on a populated database and its version bump, the
 * `trust_tasks` repository fields, the per-VRC relationship-DID mapping repository, the additive
 * transaction columns and `TransactionManager.getOutcome`. Temp directories only.
 */
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';
import * as trustTasksRepo from '../../src/db/repositories/trust-tasks-repo.js';
import * as exchangeDids from '../../src/db/repositories/vrc-exchange-dids-repo.js';
import { RelationshipDidReuseError } from '../../src/db/repositories/vrc-exchange-dids-repo.js';
import { applyTxSchemaAdditions, TX_SCHEMA_SQL } from '../../src/tx/schema.js';
import { CeremonyStore } from '../../src/tx/ceremony-store.js';
import { GovernanceChangeStore } from '../../src/tx/governance-change-store.js';
import {
  CompensationExecutor,
  DataSourceLogSink,
  TransactionCoordinator,
  TransactionLog,
  TransactionManager,
} from '../../src/tx/index.js';
import type { Operation, Participant, Vote } from '../../src/tx/types.js';

const root = mkdtempSync(join(tmpdir(), 'p3-persist-'));
after(() => rmSync(root, { recursive: true, force: true }));
const MIGRATIONS = getMigrationsDir();
const columns = async (ds: SqliteDataSource, table: string): Promise<string[]> =>
  (await ds.all<{ name: string }>(`PRAGMA table_info(${table})`)).map((c) => c.name);

describe('migration 0021 and the schema version', () => {
  it('is the next free number after 0020, named per the plan; the version file is 26 with P7\'s 0022 (0021 took it 24 -> 25)', () => {
    const files = readdirSync(MIGRATIONS).filter((f) => f.endsWith('.sql')).sort();
    assert.equal(files.at(-1), '0022_witness_shares.sql');
    assert.equal(files.at(-2), '0021_trust_task_boundary.sql');
    assert.equal(files.at(-3), '0020_community_policy_bindings.sql');
    assert.equal(readFileSync(join(MIGRATIONS, '..', 'SCHEMA_VERSION'), 'utf8').trim(), '26');
  });

  it('applies to a populated 0020-era database: old rows survive with null new columns, new tables are empty', async () => {
    const dir = join(root, 'populated');
    const migrations = join(dir, 'migrations');
    mkdirSync(migrations, { recursive: true });
    for (const f of readdirSync(MIGRATIONS)) if (f.endsWith('.sql') && f < '0021') cpSync(join(MIGRATIONS, f), join(migrations, f));
    writeFileSync(join(dir, 'SCHEMA_VERSION'), '24');
    const ds = new SqliteDataSource(join(dir, 'app.sqlite'));
    runMigrations(ds.getRawDb(), migrations);
    await ds.run(
      `INSERT INTO trust_tasks (uuid, thread_id, type, direction, payload, status, created_at, updated_at)
       VALUES ('old-1', 't-1', 'task:p2pts:vtc:establish:0.1', 'request', '{"a":1}', 'recorded', 1, 1)`,
    );
    assert.ok(!(await columns(ds, 'trust_tasks')).includes('raw_document'));

    const applied = runMigrations(ds.getRawDb(), MIGRATIONS);
    assert.deepEqual(applied, ['0021_trust_task_boundary.sql', '0022_witness_shares.sql']);
    const old = await trustTasksRepo.findByUuid(ds, 'old-1');
    assert.equal(old?.payload, '{"a":1}');
    for (const k of ['rawDocument', 'digest', 'taskDigest', 'issuedAt', 'expiresAt', 'inReplyTo', 'errorCode', 'disposition', 'verifiedSigner', 'lifecycle'] as const) {
      assert.equal(old?.[k], null, k);
    }
    for (const t of ['trust_task_accepted', 'vrc_exchange_relationship_dids']) assert.equal((await ds.all(`SELECT * FROM ${t}`)).length, 0);
    assert.deepEqual(runMigrations(ds.getRawDb(), MIGRATIONS), [], 'idempotent');
    await ds.close();
  });

  it('records the bumped version in the ledger (the downgrade guard reads it; see the P3 report on its reach)', async () => {
    const ds = new SqliteDataSource(':memory:');
    runMigrations(ds.getRawDb(), MIGRATIONS);
    const rows = await ds.all<{ filename: string }>("SELECT filename FROM schema_migrations WHERE filename LIKE '__schema_version__%'");
    assert.deepEqual(rows.map((r) => r.filename), ['__schema_version__:26']);
    await ds.close();
  });

  it('the migration is additive and nullable: no NOT NULL column was added to trust_tasks, no existing table dropped', () => {
    const sql = readFileSync(join(MIGRATIONS, '0021_trust_task_boundary.sql'), 'utf8');
    const alters = sql.split('\n').filter((l) => /^ALTER TABLE/i.test(l));
    assert.equal(alters.length, 10);
    assert.ok(alters.every((l) => l.startsWith('ALTER TABLE trust_tasks ADD COLUMN') && !/NOT NULL/i.test(l)));
    assert.ok(!/DROP|DELETE|RENAME/i.test(sql.replace(/--.*$/gm, '')));
    assert.ok(!/INSERT OR|ON CONFLICT|unixepoch|datetime/i.test(sql.replace(/--.*$/gm, '')), 'dialect-neutral');
  });
});

describe('trust_tasks repository carries the new fields', () => {
  it('writes and reads them back; 64-bit columns that arrive as strings are numbers', async () => {
    const ds = new SqliteDataSource(':memory:');
    runMigrations(ds.getRawDb(), MIGRATIONS);
    const row = await trustTasksRepo.record(ds, {
      uuid: 'doc-1', threadId: 't', type: 'x', direction: 'request',
      rawDocument: '{"id":"doc-1"}', digest: 'dd', taskDigest: 'td', issuedAt: 1_762_941_600_000, expiresAt: 1_762_945_200_000,
      inReplyTo: 'doc-0', errorCode: 'expired', disposition: 'refused', verifiedSigner: 'did:web:a.example', lifecycle: 'errored',
    });
    assert.equal(row.rawDocument, '{"id":"doc-1"}');
    assert.equal(row.issuedAt, 1_762_941_600_000);
    assert.equal(row.verifiedSigner, 'did:web:a.example');
    assert.equal(row.lifecycle, 'errored');
    const plain = await trustTasksRepo.record(ds, { uuid: 'doc-2', threadId: 't', type: 'x', direction: 'response' });
    assert.equal(plain.rawDocument, null);
    await ds.close();
  });
});

describe('per-VRC relationship-DID mapping (decision 35): schema and repository only', () => {
  const base = (id: string, mine: string, theirs?: string) => ({
    exchangeId: id, localConnectionDid: 'did:peer:conn-me', remoteConnectionDid: 'did:peer:conn-you',
    localRelationshipDid: mine, ...(theirs === undefined ? {} : { remoteRelationshipDid: theirs }),
    localIdentityUuid: 'ident-me', role: 'proposer' as const,
  });
  const open = () => {
    const ds = new SqliteDataSource(':memory:');
    runMigrations(ds.getRawDb(), MIGRATIONS);
    return ds;
  };

  it('is keyed by the propose id and stores both connection DIDs, both relationship DIDs, role, state and root identity', async () => {
    const ds = open();
    const row = await exchangeDids.create(ds, { ...base('urn:uuid:propose-1', 'did:peer:4zMine1', 'did:peer:4zTheirs1'), remoteIdentityUuid: 'ident-you', state: 'accepted', now: 1000 });
    assert.deepEqual(row, {
      exchangeId: 'urn:uuid:propose-1', localConnectionDid: 'did:peer:conn-me', remoteConnectionDid: 'did:peer:conn-you',
      localRelationshipDid: 'did:peer:4zMine1', remoteRelationshipDid: 'did:peer:4zTheirs1', localIdentityUuid: 'ident-me',
      remoteIdentityUuid: 'ident-you', role: 'proposer', state: 'accepted', recordedByNode: null, createdAt: 1000, updatedAt: 1000,
    });
    assert.equal((await exchangeDids.findByRelationshipDid(ds, 'did:peer:4zTheirs1'))?.exchangeId, 'urn:uuid:propose-1');
    await assert.rejects(() => exchangeDids.create(ds, base('urn:uuid:propose-1', 'did:peer:4zOther')), /UNIQUE|constraint/i, 'one row per exchange id');
    await ds.close();
  });

  it('a second exchange between the same parties is a new row with new DIDs', async () => {
    const ds = open();
    await exchangeDids.create(ds, { ...base('p-1', 'did:peer:4zA1', 'did:peer:4zB1'), now: 1 });
    await exchangeDids.create(ds, { ...base('p-2', 'did:peer:4zA2', 'did:peer:4zB2'), now: 2 });
    assert.deepEqual((await exchangeDids.listByConnections(ds, 'did:peer:conn-me', 'did:peer:conn-you')).map((r) => r.exchangeId), ['p-1', 'p-2']);
    await ds.close();
  });

  it('refuses a relationship DID reused in either direction, or equal to a connection DID', async () => {
    const ds = open();
    await exchangeDids.create(ds, base('p-1', 'did:peer:4zA1', 'did:peer:4zB1'));
    await assert.rejects(() => exchangeDids.create(ds, base('p-2', 'did:peer:4zA1')), RelationshipDidReuseError, 'our DID reused as ours');
    await assert.rejects(() => exchangeDids.create(ds, base('p-3', 'did:peer:4zC', 'did:peer:4zB1')), RelationshipDidReuseError, 'their DID reused as theirs');
    await assert.rejects(() => exchangeDids.create(ds, base('p-4', 'did:peer:4zB1')), RelationshipDidReuseError, 'their DID offered as ours');
    await assert.rejects(() => exchangeDids.create(ds, base('p-5', 'did:peer:4zD', 'did:peer:4zA1')), RelationshipDidReuseError, 'our DID offered as theirs');
    await assert.rejects(() => exchangeDids.create(ds, base('p-6', 'did:peer:conn-me')), RelationshipDidReuseError, 'a connection DID');
    await assert.rejects(() => exchangeDids.create(ds, base('p-7', 'did:peer:4zE', 'did:peer:4zE')), RelationshipDidReuseError, 'both sides the same');
    assert.equal(await exchangeDids.findByExchangeId(ds, 'p-2'), null, 'a refused row is not left behind');
    await ds.close();
  });

  it('the schema itself holds the same-column uniqueness (belt and braces beside the repository check)', async () => {
    const ds = open();
    await exchangeDids.create(ds, base('p-1', 'did:peer:4zA1', 'did:peer:4zB1'));
    const insert = (id: string, mine: string, theirs: string) =>
      ds.run(`INSERT INTO vrc_exchange_relationship_dids (exchange_id, local_connection_did, remote_connection_did, local_relationship_did, remote_relationship_did, role, state, created_at, updated_at) VALUES (?, 'a', 'b', ?, ?, 'proposer', 'proposed', 1, 1)`, id, mine, theirs);
    await assert.rejects(() => insert('x1', 'did:peer:4zA1', 'did:peer:4zZ'), /UNIQUE/);
    await assert.rejects(() => insert('x2', 'did:peer:4zY', 'did:peer:4zB1'), /UNIQUE/);
    await ds.close();
  });

  it('records the counterparty DID once known, durably (second connection sees it), refusing reuse and a changed value', async () => {
    const path = join(root, 'mapping.sqlite');
    const ds = new SqliteDataSource(path);
    runMigrations(ds.getRawDb(), MIGRATIONS);
    await exchangeDids.create(ds, base('p-1', 'did:peer:4zA1'));
    await exchangeDids.create(ds, base('p-2', 'did:peer:4zA2', 'did:peer:4zB2'));
    await assert.rejects(() => exchangeDids.setRemoteRelationshipDid(ds, 'p-1', 'did:peer:4zB2'), RelationshipDidReuseError);
    await assert.rejects(() => exchangeDids.setRemoteRelationshipDid(ds, 'p-1', 'did:peer:4zA1'), RelationshipDidReuseError);
    const updated = await exchangeDids.setRemoteRelationshipDid(ds, 'p-1', 'did:peer:4zB1', 5);
    assert.equal(updated.remoteRelationshipDid, 'did:peer:4zB1');
    await assert.rejects(() => exchangeDids.setRemoteRelationshipDid(ds, 'p-1', 'did:peer:4zOther'), RelationshipDidReuseError);
    await exchangeDids.setState(ds, 'p-1', 'ended', 9);
    await ds.close();
    const again = new SqliteDataSource(path);
    const row = await exchangeDids.findByExchangeId(again, 'p-1');
    assert.equal(row?.remoteRelationshipDid, 'did:peer:4zB1');
    assert.equal(row?.state, 'ended');
    assert.equal(row?.updatedAt, 9);
    await again.close();
  });
});

describe('additive transaction columns', () => {
  it('error_code and retryable are added to an existing 0020-era tx database, once, and stay null', async () => {
    const ds = new SqliteDataSource(':memory:');
    // An old database: the proposal tables exactly as they were before this column existed.
    ds.getRawDb().exec(TX_SCHEMA_SQL);
    const first = await applyTxSchemaAdditions(ds);
    assert.ok(['ceremony_proposals', 'governance_change_proposals'].every((t) => first.includes(`${t}.error_code`) && first.includes(`${t}.retryable`)));
    assert.deepEqual(await applyTxSchemaAdditions(ds), []);
    const store = new CeremonyStore(ds);
    await store.createProposal({ proposalId: 'p1', proposerDid: 'did:a', vtcDid: 'did:v', name: 'n', kind: 'vtc', adminDids: ['did:a'], threshold: 1, expiresAt: Date.now() + 1000, proposalHash: 'h' });
    const before = await store.getProposal('p1');
    assert.equal(before?.errorCode, null);
    assert.equal(before?.retryable, null);
    await store.recordFailure('p1', 'unavailable', true);
    const after = await store.getProposal('p1');
    assert.equal(after?.errorCode, 'unavailable');
    assert.equal(after?.retryable, true);
    await store.recordFailure('p1', 'taskFailed', false);
    assert.equal((await store.getProposal('p1'))?.retryable, false);
    assert.equal(typeof GovernanceChangeStore.prototype.recordFailure, 'function');
    await ds.close();
  });
});

describe('TransactionManager.getOutcome', () => {
  class Participant1 implements Participant {
    readonly pid = 'p';
    private readonly vote: Vote;
    constructor(vote: Vote) {
      this.vote = vote;
    }
    async prepare(_t: string, _o: Operation[]): Promise<Vote> { return this.vote; }
    async commit(): Promise<void> {}
    async abort(): Promise<void> {}
    async compensate(): Promise<void> {}
    async inquiry(): Promise<'unknown'> { return 'unknown'; }
  }
  const setup = (vote: Vote) => {
    const ds = new SqliteDataSource(':memory:');
    ds.getRawDb().exec(TX_SCHEMA_SQL);
    const log = new TransactionLog(new DataSourceLogSink(ds));
    const coordinator = new TransactionCoordinator(log);
    const manager = new TransactionManager(coordinator, new CompensationExecutor());
    const participant = new Participant1(vote);
    manager.registerParticipant(participant);
    return { ds, log, manager, participant };
  };
  const operations = [{ op: 'x', params: {} }] as Operation[];

  it('committed after a commit, aborted after a no vote, unknown for an id never seen', async () => {
    for (const [vote, want] of [['yes', 'committed'], ['no', 'aborted']] as const) {
      const { manager, ds, participant } = setup(vote);
      const result = await manager.run(async (tx) => { tx.enlist(participant, operations); }).catch(() => undefined);
      void result;
      const ids = (await ds.all<{ tx_id: string }>('SELECT DISTINCT tx_id FROM tx_log')).map((r) => r.tx_id);
      assert.equal(ids.length, 1);
      assert.equal(await manager.getOutcome(ids[0]!), want);
      assert.equal(await manager.getOutcome('never-seen'), 'unknown');
      await ds.close();
    }
  });

  it('inFlight while started with no decision, then the logged decision wins; the read changes nothing', async () => {
    const { manager, log, ds } = setup('yes');
    await log.append('tx-live', 'TX_STARTED', { pids: ['p'] });
    const before = (await log.read('tx-live')).length;
    assert.equal(await manager.getOutcome('tx-live'), 'inFlight');
    await log.append('tx-live', 'COMMIT_INTENT');
    assert.equal(await manager.getOutcome('tx-live'), 'inFlight');
    await log.append('tx-live', 'committed');
    assert.equal(await manager.getOutcome('tx-live'), 'committed');
    assert.equal((await log.read('tx-live')).length, before + 2, 'only the appends above');
    await ds.close();
  });
});
