// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * D1.3: `createVtc`'s validation is a function of its own (`checkCreateVtc`) that only reads, so a ceremony host can
 * run it at prepare (where a refusal still vetoes) and `createVtc` at commit. These tests pin that the check writes
 * nothing, refuses exactly what `createVtc` refused, and that `createVtc` still runs the same check.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import * as peerEndpointsRepo from '../../src/db/repositories/peer-endpoints-repo.js';
import * as relationshipsRepo from '../../src/db/repositories/relationships-repo.js';
import { checkCreateVtc, createVtc, CreateVtcConflictError, CreateVtcNotFoundError, CreateVtcValidationError } from '../../src/services/vtc.js';

function open(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}

async function admin(db: SqliteDataSource, tag: string, opts: { endpoint?: boolean; kind?: 'human' | 'organization' } = {}): Promise<string> {
  const uuid = await identitiesRepo.create(db, { realDid: `did:example:${tag}`, role: 'vta', subjectKind: opts.kind ?? 'human', name: tag });
  if (opts.endpoint !== false) await peerEndpointsRepo.upsertForIdentity(db, { identityUuid: uuid, peerId: `peer-${tag}`, multiaddrs: ['/ip4/127.0.0.1/tcp/1'] });
  return uuid;
}

async function link(db: SqliteDataSource, a: string, b: string): Promise<void> {
  await relationshipsRepo.create(db, { localIdentityUuid: a, remoteIdentityUuid: b, direction: 'bidirectional', status: 'established' });
}

const count = async (db: SqliteDataSource, table: string): Promise<number> => (await db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table}`))!.n;

test('a passing check resolves the admins and the threshold and writes nothing', async () => {
  const db = open();
  const a = await admin(db, 'a');
  const b = await admin(db, 'b');
  await link(db, a, b);
  const before = { identities: await count(db, 'identities'), memberships: await count(db, 'memberships'), governance: await count(db, 'governance') };

  const checked = await checkCreateVtc(db, { name: 'Check Club', kind: 'vtc', adminIdentityUuids: [a, b], threshold: 2 });
  assert.equal(checked.kind, 'vtc');
  assert.equal(checked.threshold, 2);
  assert.deepEqual(checked.admins.map((x) => x.uuid), [a, b]);
  assert.deepEqual({ identities: await count(db, 'identities'), memberships: await count(db, 'memberships'), governance: await count(db, 'governance') }, before);
});

test('the check refuses what createVtc refused, with the same error classes', async () => {
  const db = open();
  const a = await admin(db, 'a');
  const b = await admin(db, 'b');
  const noEndpoint = await admin(db, 'stub', { endpoint: false });
  const org = await admin(db, 'org', { kind: 'organization' });
  await link(db, a, b);
  await link(db, a, noEndpoint);
  await link(db, a, org);
  const cases: Array<[string, Parameters<typeof checkCreateVtc>[1], new (...args: never[]) => Error]> = [
    ['empty name', { name: ' ', adminIdentityUuids: [a] }, CreateVtcValidationError],
    ['no admins', { name: 'X', adminIdentityUuids: [] }, CreateVtcValidationError],
    ['unknown admin', { name: 'X', adminIdentityUuids: ['nope'] }, CreateVtcNotFoundError],
    ['admin without an endpoint', { name: 'X', adminIdentityUuids: [a, noEndpoint] }, CreateVtcValidationError],
    ['admin not human', { name: 'X', adminIdentityUuids: [a, org] }, CreateVtcValidationError],
    ['no mutual VRC with the creator', { name: 'X', adminIdentityUuids: [b, noEndpoint] }, CreateVtcValidationError],
    ['threshold above the admin count', { name: 'X', adminIdentityUuids: [a, b], threshold: 3 }, CreateVtcValidationError],
    ['parent that does not exist', { name: 'X', adminIdentityUuids: [a], threshold: 1, parentCommunityUuid: 'nope' }, CreateVtcNotFoundError],
  ];
  for (const [label, input, cls] of cases) {
    await assert.rejects(() => checkCreateVtc(db, input), cls, `check: ${label}`);
    await assert.rejects(() => createVtc(db, input), cls, `createVtc: ${label}`);
  }
  assert.equal(await count(db, 'memberships'), 0, 'nothing was written by any refusal');
});

test('a taken name is a conflict at the check, and createVtc then creates the community when the check passes', async () => {
  const db = open();
  const a = await admin(db, 'a');
  const b = await admin(db, 'b');
  await link(db, a, b);
  const input = { name: 'Once Club', kind: 'vtc' as const, adminIdentityUuids: [a, b], threshold: 2 };
  await checkCreateVtc(db, input);
  const made = await createVtc(db, input);
  assert.equal(made.identity.name, 'Once Club');
  await assert.rejects(() => checkCreateVtc(db, { ...input, name: 'once club' }), CreateVtcConflictError);
});
