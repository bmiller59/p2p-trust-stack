// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P7 (core side): migration 0022 on a populated 0021-era database, the witnessed
 * credential and evidence repository (the pair is written together or not at all), the wire types of
 * the suite-local task, and the proof verifier's holder/challenge/domain handling that presentations
 * need. The end-to-end WSH vectors run in app-api. Temp directories only.
 */
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';
import * as witnessShares from '../../src/db/repositories/witness-shares-repo.js';
import { DidProofVerifier } from '../../src/services/trust-tasks/boundary/proof/verify.js';
import { createLocalKeyResolver } from '../../src/services/trust-tasks/boundary/proof/install.js';
import { didKeyFromEd25519 } from '../../src/services/trust-tasks/boundary/proof/resolver.js';
import { createEd25519BoundarySigner, signDocument } from '../../src/services/trust-tasks/boundary/proof/signer.js';
import { fromWireTypeUri } from '../../src/services/trust-tasks/boundary/urn-codec.js';
import { tryParseTypeUri } from '../../src/services/trust-tasks/boundary/runtime.js';
import {
  WITNESS_SHARE_DOMAIN,
  WITNESS_SHARE_INTERNAL_NAME,
  WITNESS_SHARE_RESPONSE_TYPE,
  WITNESS_SHARE_TYPE,
  WITNESS_SHARE_URN_TYPE,
} from '../../src/services/trust-tasks/boundary/witness-share-spec.js';

const MIGRATIONS = getMigrationsDir();
const root = mkdtempSync(join(tmpdir(), 'p7-core-'));
after(() => rmSync(root, { recursive: true, force: true }));
const tables = async (ds: SqliteDataSource) => (await ds.all<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'")).map((r) => r.name);

describe('migration 0022', () => {
  it('is the next free number, the version file is 26, and it applies to a populated 0021-era database without touching it', async () => {
    const files = readdirSync(MIGRATIONS).filter((f) => f.endsWith('.sql')).sort();
    assert.equal(files.at(-1), '0022_witness_shares.sql');
    assert.equal(readFileSync(join(MIGRATIONS, '..', 'SCHEMA_VERSION'), 'utf8').trim(), '26');

    const dir = join(root, 'populated');
    const migrations = join(dir, 'migrations');
    mkdirSync(migrations, { recursive: true });
    for (const f of files) if (f < '0022') cpSync(join(MIGRATIONS, f), join(migrations, f));
    writeFileSync(join(dir, 'SCHEMA_VERSION'), '25');
    const ds = new SqliteDataSource(join(dir, 'app.sqlite'));
    runMigrations(ds.getRawDb(), migrations);
    const before = await tables(ds);
    assert.ok(!before.includes('witnessed_credentials'));
    await ds.run(
      `INSERT INTO trust_tasks (uuid, thread_id, type, direction, payload, status, created_at, updated_at)
       VALUES ('old-1', 't-1', 'task:p2pts:vtc:establish:0.1', 'request', '{"a":1}', 'recorded', 1, 1)`,
    );
    assert.deepEqual(runMigrations(ds.getRawDb(), MIGRATIONS), ['0022_witness_shares.sql']);
    assert.deepEqual((await tables(ds)).filter((t) => !before.includes(t)).sort(), ['witness_share_evidence', 'witnessed_credentials']);
    assert.equal((await ds.get<{ payload: string }>("SELECT payload FROM trust_tasks WHERE uuid = 'old-1'"))!.payload, '{"a":1}');
    assert.deepEqual(runMigrations(ds.getRawDb(), MIGRATIONS), [], 'idempotent');
    await ds.close();
  });

  it('is additive and dialect-neutral: two CREATE TABLE statements, no ALTER, DROP, upsert or DB-side time', () => {
    const sql = readFileSync(join(MIGRATIONS, '0022_witness_shares.sql'), 'utf8').replace(/--.*$/gm, '');
    assert.equal((sql.match(/CREATE TABLE/g) ?? []).length, 2);
    assert.ok(!/ALTER|DROP|DELETE|RENAME|INSERT OR|ON CONFLICT|unixepoch|datetime|DEFAULT/i.test(sql));
  });
});

describe('witness share repository', () => {
  const input = (id: string, exchangeId: string) => ({
    id,
    exchangeId,
    subjectDid: 'did:key:zR',
    witnessDid: 'did:key:zW',
    senderConnectionDid: 'did:key:zA',
    w3cVcJson: '{"a":1}',
    shareDocumentId: 'urn:uuid:1',
    presentationJson: '{"p":1}',
    initiatingJson: '{"i":1}',
    terminalJson: '{"t":1}',
    now: 1_000,
  });

  it('writes the credential and its evidence together and reads both back', async () => {
    const ds = new SqliteDataSource(':memory:');
    runMigrations(ds.getRawDb(), MIGRATIONS);
    await witnessShares.insert(ds, input('zDigest1', 'ex-1'));
    const row = (await witnessShares.findByDigest(ds, 'zDigest1'))!;
    assert.deepEqual({ ...row }, { id: 'zDigest1', exchangeId: 'ex-1', kind: 'vwc', subjectDid: 'did:key:zR', witnessDid: 'did:key:zW', senderConnectionDid: 'did:key:zA', w3cVcJson: '{"a":1}', witnessVerified: true, shareDocumentId: 'urn:uuid:1', createdAt: 1000 });
    assert.equal((await witnessShares.findByExchange(ds, 'ex-1'))!.id, 'zDigest1');
    const ev = (await witnessShares.findEvidence(ds, 'zDigest1'))!;
    assert.deepEqual([ev.presentationJson, ev.initiatingJson, ev.terminalJson], ['{"p":1}', '{"i":1}', '{"t":1}']);
    assert.equal(await witnessShares.count(ds), 1);
    await ds.close();
  });

  it('one credential per exchange: a second insert for the exchange is refused and leaves no orphan evidence', async () => {
    const ds = new SqliteDataSource(':memory:');
    runMigrations(ds.getRawDb(), MIGRATIONS);
    await witnessShares.insert(ds, input('zDigest1', 'ex-1'));
    await assert.rejects(witnessShares.insert(ds, input('zDigest2', 'ex-1')));
    assert.equal(await witnessShares.findEvidence(ds, 'zDigest2'), null);
    assert.equal(await witnessShares.count(ds), 1);
    await assert.rejects(witnessShares.insert(ds, input('zDigest1', 'ex-2')), 'the same digest twice');
    await ds.close();
  });
});

describe('wire types of the suite-local task', () => {
  it('the URI is a valid Trust Task type URI; the URN form is the codec form of the internal name and round-trips', () => {
    assert.equal(WITNESS_SHARE_URN_TYPE, 'urn:p2pts:tasks:spec:vrc:witness-share:0.1');
    assert.equal(fromWireTypeUri(WITNESS_SHARE_URN_TYPE), WITNESS_SHARE_INTERNAL_NAME);
    assert.notEqual(tryParseTypeUri(WITNESS_SHARE_TYPE), null);
    assert.notEqual(tryParseTypeUri(WITNESS_SHARE_URN_TYPE), null);
    assert.equal(WITNESS_SHARE_RESPONSE_TYPE, `${WITNESS_SHARE_TYPE}#response`);
    assert.equal(WITNESS_SHARE_DOMAIN, 'vrc:witness-share');
  });
});

describe('presentation proofs: holder, challenge and domain', () => {
  const seed = new Uint8Array(32).fill(7);
  const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
  const signer = createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) });
  const verifier = new DidProofVerifier({ resolver: createLocalKeyResolver({}) });
  const NOW = Date.parse('2026-11-12T10:00:00Z');
  const vp = (extra: Record<string, unknown> = {}) =>
    signDocument({ '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiablePresentation'], holder: did, verifiableCredential: [] }, signer, { created: NOW, challenge: 'thread-1', domain: WITNESS_SHARE_DOMAIN, allowIssuerMismatch: true, ...extra });

  it('verifies under the holder with the expected challenge and domain, and names the holder as the signer', async () => {
    const v = await verifier.verify(vp(), { nowMs: NOW, purposes: ['authentication'], signerMember: 'holder', challenge: 'thread-1', domain: WITNESS_SHARE_DOMAIN });
    assert.equal(v.valid, true);
    assert.equal(v.signer, did);
  });

  it('a different challenge, a different domain, or a missing challenge is refused with its own failure', async () => {
    const ctx = { nowMs: NOW, purposes: ['authentication'], signerMember: 'holder' as const, challenge: 'thread-1', domain: WITNESS_SHARE_DOMAIN };
    assert.equal((await verifier.verify(vp({ challenge: 'thread-2' }), ctx)).failure, 'challengeMismatch');
    assert.equal((await verifier.verify(vp({ domain: 'other' }), ctx)).failure, 'domainMismatch');
    const bare = signDocument({ holder: did }, signer, { created: NOW, allowIssuerMismatch: true });
    assert.equal((await verifier.verify(bare, ctx)).failure, 'challengeMismatch');
  });

  it('without a signer member the document must still carry an issuer (envelope behaviour is unchanged)', async () => {
    assert.equal((await verifier.verify(vp(), { nowMs: NOW, purposes: ['authentication'] })).failure, 'issuerMismatch');
  });

  it('a credential issuer given as an object with an id is read for credential proofs only', async () => {
    const vc = signDocument({ issuer: { id: did }, credentialSubject: { id: 'x' } }, signer, { created: NOW, purpose: 'assertionMethod', allowIssuerMismatch: true });
    assert.equal((await verifier.verify(vc, { nowMs: NOW, purposes: ['assertionMethod'], signerMember: 'credential' })).valid, true);
    assert.equal((await verifier.verify(vc, { nowMs: NOW, purposes: ['assertionMethod'] })).valid, false);
  });
});
