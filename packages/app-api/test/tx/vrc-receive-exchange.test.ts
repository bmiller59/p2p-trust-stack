// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P5c: the VRC receive participant on the boundary (exchange) path. Bindings come from the
 * exchange record; a wrong issuer or subject, a broken proof, an unknown or ended exchange and a second
 * different credential in one exchange are refused with a recorded reason; a repeat is idempotent; the
 * credential is stored against the exchange's root identities and not the remote's identity data.
 * Temp directories only.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { applyTxSchemaAdditions, TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/schema.js';
import { mintExchangeRelationshipDid, endExchange, loadExchangeSigner } from '@p2p-trust-stack/core/relationship/exchange-dids.js';
import { mintExchangeVrc } from '@p2p-trust-stack/core/relationship/vrc-mint.js';
import { buildDtgCredential, serializeDtgCredential } from '@p2p-trust-stack/core/services/dtg-credential.js';
import { getAbortReason, clearAbortReasons } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import { VtcStore } from '@p2p-trust-stack/core/vtc/store.js';
import type { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import { VrcReceiveParticipant } from '../../src/runtime/tx/vrc-receive-participant.js';

const PASS = 'test-passphrase-not-a-default';
const root = mkdtempSync(join(tmpdir(), 'p5c-recv-'));
after(() => rmSync(root, { recursive: true, force: true }));

async function db(name: string): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(join(root, `${name}.db`));
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}
async function ident(ds: SqliteDataSource, did: string): Promise<string> {
  const uuid = await identitiesRepo.create(ds, { realDid: did, role: 'vta', subjectKind: 'human', custody: 'local', name: did });
  await didDocumentsRepo.create(ds, { identityUuid: uuid, did, method: 'did:scid:vh', documentJson: '{}', isPrimary: true });
  return uuid;
}

async function setup(name: string, exchangeId = 'propose-1') {
  const A = 'did:scid:vh:a', B = 'did:scid:vh:b';
  const dsA = await db(`${name}-a`);
  const dsB = await db(`${name}-b`);
  const aA = await ident(dsA, A), bInA = await ident(dsA, B);
  const bB = await ident(dsB, B), aInB = await ident(dsB, A);
  const aRow = await mintExchangeRelationshipDid(dsA, { exchangeId, role: 'proposer', localIdentityUuid: aA, localConnectionDid: A, remoteConnectionDid: B, remoteIdentityUuid: bInA, passphrase: PASS });
  const bRow = await mintExchangeRelationshipDid(dsB, { exchangeId, role: 'acceptor', localIdentityUuid: bB, localConnectionDid: B, remoteConnectionDid: A, remoteIdentityUuid: aInB, remoteRelationshipDid: aRow.localRelationshipDid, passphrase: PASS });
  await exchangeDids.setRemoteRelationshipDid(dsA, exchangeId, bRow.localRelationshipDid);
  await exchangeDids.setState(dsA, exchangeId, 'accepted');
  const txDb = new SqliteDataSource(':memory:');
  txDb.getRawDb().exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  const participant = new VrcReceiveParticipant('peer:b', dsB, txDb, new VtcStore(dsB.getRawDb(), {} as IdentityResolver), {} as IdentityResolver);
  const vrc = await mintExchangeVrc({ dataSource: dsA, exchangeId, passphrase: PASS });
  assert.ok(vrc.success);
  const json = (vrc as { w3cVcJson: string }).w3cVcJson;
  const prepare = (txId: string, w3cVcJson: string, id: string | undefined = exchangeId) =>
    participant.prepare(txId, [{ op: 'store_remote_vrc', params: { w3cVcJson, issuerDid: aRow.localRelationshipDid, subjectDid: bRow.localRelationshipDid, exchangeId: id, issuerIdentity: { forged: true } } } as never]);
  const count = async () => (await dsB.get<{ n: number }>("SELECT COUNT(*) AS n FROM credentials WHERE vc_type = 'vrc'"))!.n;
  return { dsA, dsB, aRow, bRow, aA, bB, aInB, json, prepare, count };
}

describe('VrcReceiveParticipant, exchange path', () => {
  it('stores the credential against the exchange identities and is idempotent on a repeat', async () => {
    const s = await setup('ok');
    assert.equal(await s.prepare('tx-1', s.json), 'yes');
    assert.equal(await s.prepare('tx-2', s.json), 'yes');
    assert.equal(await s.count(), 1);
    const row = (await s.dsB.get<{ issuer_identity_uuid: string; subject_identity_uuid: string }>("SELECT * FROM credentials WHERE vc_type = 'vrc'"))!;
    assert.equal(row.issuer_identity_uuid, s.aInB);
    assert.equal(row.subject_identity_uuid, s.bB);
    assert.equal((await exchangeDids.findByExchangeId(s.dsB, 'propose-1'))?.state, 'received');
  });

  it('refuses an unknown exchange, an ended exchange and a replay under another exchange id, storing nothing', async () => {
    clearAbortReasons();
    const s = await setup('refuse');
    assert.equal(await s.prepare('tx-a', s.json, 'nope'), 'no');
    assert.equal(getAbortReason('tx-a')?.code, 'taskFailed');
    await mintExchangeRelationshipDid(s.dsB, { exchangeId: 'propose-2', role: 'acceptor', localIdentityUuid: s.bB, localConnectionDid: 'did:scid:vh:b', remoteConnectionDid: 'did:scid:vh:a', remoteIdentityUuid: s.aInB, remoteRelationshipDid: 'did:peer:4zSomeoneElse', passphrase: PASS });
    assert.equal(await s.prepare('tx-b', s.json, 'propose-2'), 'no');
    assert.equal(getAbortReason('tx-b')?.reason, 'vcInvalid');
    await endExchange(s.dsB, 'propose-1');
    assert.equal(await s.prepare('tx-c', s.json), 'no');
    assert.equal(await s.count(), 0);
  });

  it('refuses a credential whose proof is broken', async () => {
    const s = await setup('proof');
    const bad = JSON.parse(s.json);
    bad.validFrom = '2001-01-01T00:00:00.000Z';
    assert.equal(await s.prepare('tx-p', JSON.stringify(bad)), 'no');
    assert.equal(await s.count(), 0);
  });

  it('answers a different credential from the same relationship DID in one exchange with alreadyIssued', async () => {
    clearAbortReasons();
    const s = await setup('again');
    assert.equal(await s.prepare('tx-1', s.json), 'yes');
    const signer = (await loadExchangeSigner(s.dsA, 'propose-1', PASS))!;
    const second = buildDtgCredential({
      subtype: 'RelationshipCredential', id: 'urn:uuid:11111111-1111-4111-8111-111111111111',
      issuerDid: s.aRow.localRelationshipDid, subjectDid: s.bRow.localRelationshipDid, issuerScope: 'pairwise',
      claim: { relationshipType: 'peer-relationship' }, validFrom: Math.floor(Date.now() / 1000),
      verificationMethod: signer.verificationMethod, signerSecretKey: signer.secretKey,
    });
    assert.equal(await s.prepare('tx-2', serializeDtgCredential(second)), 'no');
    assert.equal(getAbortReason('tx-2')?.code, 'vrc/relationships/issue:alreadyIssued');
    assert.equal(await s.count(), 1);
  });
});
