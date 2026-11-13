// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P5: a failed step leaves a `failed` row with its standard `error_code` (also on the
 * non-transactional path, so no orphan request row), and a refusal keeps its reason. In-memory only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { driveCeremony, driveAtomically } from '../../src/services/trust-tasks/driver.js';
import { registerExecutor } from '../../src/services/trust-tasks/catalog.js';
import * as trustTasksRepo from '../../src/db/repositories/trust-tasks-repo.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';
import { taskErrorForReason } from '../../src/services/trust-tasks/boundary/errors.js';

const ESTABLISH = 'task:p2pts:vtc:establish:0.1';
let mode: 'plain' | 'typed' | 'ok' = 'plain';
registerExecutor(ESTABLISH, async () => {
  if (mode === 'plain') throw new Error('disk on fire: /secret/path');
  if (mode === 'typed') throw taskErrorForReason('nameTaken', { internalMessage: 'name taken' });
  return { identity: { name: 'x' }, foundingAdmins: [] };
});

function open() {
  const db = new SqliteDataSource(':memory:');
  runMigrations(db.getRawDb(), getMigrationsDir());
  return db;
}

test('executor failure on the NON-transactional path: request row has a failed response with error_code (no orphan)', async () => {
  mode = 'plain';
  const db = open();
  await assert.rejects(() => driveCeremony(db, 'vtc-establish', 't-plain', {}), /disk on fire/);
  const rows = await trustTasksRepo.listByThread(db, 't-plain');
  assert.deepEqual(rows.map((r) => r.direction), ['request', 'response']);
  assert.equal(rows[1].status, 'failed');
  const failed = rows.find((r) => r.status === 'failed')!;
  assert.equal(failed.errorCode, 'internalError');
  assert.equal(failed.type, ESTABLISH);
  assert.equal(JSON.parse(failed.payload!).retryable, false);
  await db.close();
});

test('executor failure carries a typed error\'s code and retryability', async () => {
  mode = 'typed';
  const db = open();
  await assert.rejects(() => driveCeremony(db, 'vtc-establish', 't-typed', {}));
  const failed = (await trustTasksRepo.listByThread(db, 't-typed')).find((r) => r.status === 'failed')!;
  assert.equal(failed.errorCode, 'taskFailed');
  assert.equal(JSON.parse(failed.payload!).errorCode, 'taskFailed');
  await db.close();
});

test('executor failure inside a transaction: the rollback removes the request row, driveAtomically leaves the failed row', async () => {
  mode = 'plain';
  const db = open();
  await assert.rejects(
    () => driveAtomically(db, 't-tx', (tx) => driveCeremony(tx, 'vtc-establish', 't-tx', {})),
    /disk on fire/,
  );
  const rows = await trustTasksRepo.listByThread(db, 't-tx');
  assert.equal(rows.length, 1, 'only the failed row survives the rollback');
  assert.equal(rows[0].status, 'failed');
  assert.equal(rows[0].direction, 'response');
  assert.equal(rows[0].errorCode, 'internalError');
  await db.close();
});

test('a successful atomic drive commits its rows and leaves no failed row', async () => {
  mode = 'ok';
  const db = open();
  const res = await driveAtomically(db, 't-ok', (tx) => driveCeremony(tx, 'vtc-establish', 't-ok', {}));
  assert.equal(res.completed, true);
  const rows = await trustTasksRepo.listByThread(db, 't-ok');
  assert.ok(rows.length >= 2 && rows.every((r) => r.status !== 'failed'));
  await db.close();
});

test('a denied gate persists its reason (reason + explanation) and returns it as haltReason', async () => {
  mode = 'ok';
  const db = open();
  await db.run(
    `INSERT INTO ceremony_templates (uuid, name, version, template, recorded_by_node, created_at, updated_at)
     VALUES ('00000000-0000-4000-8000-00000000fff0','p5-gate','0.1',
       '{"steps":[{"step":"task:p2pts:policy:membership-vmc-authorized:0.1"},{"step":"task:p2pts:vtc:establish:0.1"}]}',
       'test',0,0)`,
  );
  const res = await driveCeremony(db, 'p5-gate', 't-deny', { authorizer: { authorize: async () => ({ allowed: false, reason: 'actor is not an admin' }) } });
  assert.equal(res.completed, false);
  assert.equal(res.haltReason, 'actor is not an admin');
  const denied = (await trustTasksRepo.listByThread(db, 't-deny')).find((r) => r.status === 'denied')!;
  const payload = JSON.parse(denied.payload!);
  assert.equal(payload.decision, 'deny');
  assert.equal(payload.reason, 'actor is not an admin');
  assert.equal(payload.explanation, 'actor is not an admin');
  await db.close();
});

test('a policy explanation wins over the engine reason and a denial with neither stays reason-less', async () => {
  mode = 'ok';
  const db = open();
  await db.run(
    `INSERT INTO ceremony_templates (uuid, name, version, template, recorded_by_node, created_at, updated_at)
     VALUES ('00000000-0000-4000-8000-00000000fff1','p5-gate2','0.1',
       '{"steps":[{"step":"task:p2pts:policy:membership-vmc-authorized:0.1"}]}','test',0,0)`,
  );
  const res = await driveCeremony(db, 'p5-gate2', 't-expl', {
    authorizer: { authorize: async () => ({ allowed: false, reason: 'raw', decision: { decision: 'deny' as const, explanation: 'needs two admins' } }) },
  });
  assert.equal(res.haltReason, 'needs two admins');
  const bare = await driveCeremony(db, 'p5-gate2', 't-bare', { authorizer: { authorize: async () => ({ allowed: false }) } });
  assert.equal(bare.haltReason, undefined);
  const row = (await trustTasksRepo.listByThread(db, 't-bare')).find((r) => r.status === 'denied')!;
  assert.equal(JSON.parse(row.payload!).reason, undefined);
  await db.close();
});
