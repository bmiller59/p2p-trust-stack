// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';

import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { runDataSourceMigrations } from '../../src/db/migrate-via-datasource.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();

/**
 * The DataSource runner creates its ledger with a PostgreSQL-only default
 * (EXTRACT(EPOCH FROM NOW())). Swap in the SQLite spelling so the runner's
 * version logic can run on the in-memory test data source.
 */
class LedgerCompatDataSource extends SqliteDataSource {
  override async exec(sql: string): Promise<void> {
    if (sql.includes('EXTRACT(EPOCH')) {
      return super.exec(sql.replace('(EXTRACT(EPOCH FROM NOW())::BIGINT)', '(unixepoch())'));
    }
    return super.exec(sql);
  }
}
const PREFIX = '__schema_version__:';

function versionRows(db: InstanceType<typeof DatabaseSync>): string[] {
  return (
    db
      .prepare('SELECT filename FROM schema_migrations WHERE filename LIKE ? ORDER BY filename')
      .all(`${PREFIX}%`) as { filename: string }[]
  ).map((r) => r.filename);
}

function seedVersion(db: InstanceType<typeof DatabaseSync>, version: number): void {
  db.prepare('INSERT INTO schema_migrations (filename, applied_at) VALUES (?, 1)').run(`${PREFIX}${version}`);
}

test('runMigrations refuses a database recorded at a newer schema version', () => {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, MIGRATIONS_DIR);
  seedVersion(db, 9999);
  assert.throws(() => runMigrations(db, MIGRATIONS_DIR), /newer than/);
});

test('runMigrations keeps a single recorded version row across a version bump', () => {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, MIGRATIONS_DIR);
  // Simulate a database last opened by an older release.
  db.exec(`DELETE FROM schema_migrations WHERE filename LIKE '${PREFIX}%'`);
  seedVersion(db, 3);
  runMigrations(db, MIGRATIONS_DIR);
  const rows = versionRows(db);
  assert.equal(rows.length, 1, `expected one version row, got ${rows.join(', ')}`);
});

test('runMigrations compares versions numerically (9 vs 10)', () => {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, MIGRATIONS_DIR);
  db.exec(`DELETE FROM schema_migrations WHERE filename LIKE '${PREFIX}%'`);
  // A newer database whose version sorts lexically BEFORE a smaller one.
  seedVersion(db, 10000);
  seedVersion(db, 9);
  assert.throws(() => runMigrations(db, MIGRATIONS_DIR), /newer than/);
});

test('runMigrations still opens a database at the current or an older version', () => {
  const db = new DatabaseSync(':memory:');
  runMigrations(db, MIGRATIONS_DIR);
  assert.deepEqual(runMigrations(db, MIGRATIONS_DIR), []);
  const rows = versionRows(db);
  assert.equal(rows.length, 1);
});

test('runDataSourceMigrations refuses a database recorded at a newer schema version', async () => {
  const ds = new LedgerCompatDataSource(':memory:');
  await runDataSourceMigrations(ds, MIGRATIONS_DIR);
  await ds.run('INSERT INTO schema_migrations (filename, applied_at) VALUES (?, 1)', `${PREFIX}9999`);
  await assert.rejects(() => runDataSourceMigrations(ds, MIGRATIONS_DIR), /newer than/);
});

test('runDataSourceMigrations is not fooled by an older row that sorts first in key order', async () => {
  const ds = new LedgerCompatDataSource(':memory:');
  await runDataSourceMigrations(ds, MIGRATIONS_DIR);
  await ds.exec(`DELETE FROM schema_migrations WHERE filename LIKE '${PREFIX}%'`);
  // Both rows accumulate across upgrades; the older one is first in key order.
  await ds.run('INSERT INTO schema_migrations (filename, applied_at) VALUES (?, 1)', `${PREFIX}1`);
  await ds.run('INSERT INTO schema_migrations (filename, applied_at) VALUES (?, 1)', `${PREFIX}9999`);
  await assert.rejects(() => runDataSourceMigrations(ds, MIGRATIONS_DIR), /newer than/);
});

test('runDataSourceMigrations keeps a single recorded version row across a version bump', async () => {
  const ds = new LedgerCompatDataSource(':memory:');
  await runDataSourceMigrations(ds, MIGRATIONS_DIR);
  await ds.exec(`DELETE FROM schema_migrations WHERE filename LIKE '${PREFIX}%'`);
  await ds.run('INSERT INTO schema_migrations (filename, applied_at) VALUES (?, 1)', `${PREFIX}3`);
  await runDataSourceMigrations(ds, MIGRATIONS_DIR);
  const rows = await ds.all<{ filename: string }>(
    'SELECT filename FROM schema_migrations WHERE filename LIKE ?',
    `${PREFIX}%`,
  );
  assert.equal(rows.length, 1);
});
