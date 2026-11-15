// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Migration runner — shared by agent-app and utility-server.
 *
 * Reads every `*.sql` file from a caller-supplied migrations directory
 * (sorted lexically, so the `NNNN_` numeric prefix controls order), and
 * applies any not yet recorded in the `schema_migrations` ledger table,
 * each inside its own transaction.
 *
 * ## Versioning
 *
 * A `SCHEMA_VERSION` file in the migrations directory contains a single
 * integer that represents the expected schema version (number of migrations).
 *
 * After all migrations are applied, the version is recorded in the
 * `schema_migrations` table as a row with filename `__schema_version__:<n>` (one row, replaced on each bump).
 *
 * On startup, if the database's recorded version is NEWER than the
 * `SCHEMA_VERSION` file, the runner throws an error — the application
 * is too old to operate on this database.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { getMigrationsDir } from './migrations-dir.js';
import { maxRecordedVersion, schemaVersionFilename } from './schema-version.js';

function ensureLedger(db: InstanceType<typeof DatabaseSync>): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename    TEXT PRIMARY KEY,
      applied_at  INTEGER NOT NULL DEFAULT (unixepoch())
    )
  `);
}

function alreadyApplied(db: InstanceType<typeof DatabaseSync>, filename: string): boolean {
  const row = db.prepare('SELECT 1 FROM schema_migrations WHERE filename = ?').get(filename);
  return row !== undefined;
}

function markApplied(db: InstanceType<typeof DatabaseSync>, filename: string): void {
  db.prepare('INSERT INTO schema_migrations (filename) VALUES (?)').run(filename);
}

/**
 * Read the expected schema version from the SCHEMA_VERSION file.
 */
function readExpectedVersion(migrationsDir: string): number {
  const content = readFileSync(join(migrationsDir, '..', 'SCHEMA_VERSION'), 'utf8').trim();
  const version = parseInt(content, 10);
  if (isNaN(version)) {
    throw new Error(`SCHEMA_VERSION file contains invalid version: "${content}"`);
  }
  return version;
}

/**
 * Read the schema version recorded in the database (if any): the largest
 * `__schema_version__:<n>` row in the ledger.
 */
function getRecordedVersion(db: InstanceType<typeof DatabaseSync>): number | undefined {
  const rows = db.prepare(
    "SELECT filename FROM schema_migrations WHERE filename LIKE '\\_\\_schema\\_version\\_\\_:%' ESCAPE '\\'",
  ).all() as { filename: string }[];
  return maxRecordedVersion(rows.map((r) => r.filename));
}

/**
 * Record the schema version in the database, leaving exactly one version row.
 */
function setRecordedVersion(db: InstanceType<typeof DatabaseSync>, version: number): void {
  const current = schemaVersionFilename(version);
  db.prepare(
    "DELETE FROM schema_migrations WHERE filename LIKE '\\_\\_schema\\_version\\_\\_:%' ESCAPE '\\' AND filename <> ?",
  ).run(current);
  db.prepare(
    "INSERT OR REPLACE INTO schema_migrations (filename, applied_at) VALUES (?, unixepoch())",
  ).run(current);
}

/**
 * Apply all pending migrations to the given (already-open) database.
 *
 * @param db  An open DatabaseSync connection.
 * @param migrationsDir  Absolute or relative path to the directory containing `*.sql` files.
 * @returns The names of migration files that were applied during this call.
 *
 * @throws If the database schema version is newer than expected.
 *
 * Idempotent — running twice is a no-op for already-applied files.
 */
export function runMigrations(
  db: InstanceType<typeof DatabaseSync>,
  migrationsDir: string = getMigrationsDir(),
): string[] {
  ensureLedger(db);

  // Version check: if the DB has a newer version than our source code, fail.
  const expectedVersion = readExpectedVersion(migrationsDir);
  const recordedVersion = getRecordedVersion(db);
  if (recordedVersion !== undefined && recordedVersion > expectedVersion) {
    throw new Error(
      `Database schema version (${recordedVersion}) is newer than ` +
      `this application's expected version (${expectedVersion}). ` +
      `The application may need updating.`,
    );
  }

  const files = readdirSync(migrationsDir)
    .filter((f: string) => f.endsWith('.sql'))
    .sort();

  const applied: string[] = [];

  for (const filename of files) {
    if (alreadyApplied(db, filename)) continue;

    const sql = readFileSync(join(migrationsDir, filename), 'utf8');
    db.exec('BEGIN');
    try {
      db.exec(sql);
      markApplied(db, filename);
      db.exec('COMMIT');
      applied.push(filename);
    } catch (err) {
      db.exec('ROLLBACK');
      throw new Error(`Migration failed: ${filename}: ${(err as Error).message}`);
    }
  }

  // Record the version after migrations complete.
  setRecordedVersion(db, expectedVersion);

  return applied;
}