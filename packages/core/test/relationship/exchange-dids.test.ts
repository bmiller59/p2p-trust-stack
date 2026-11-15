// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P5c: per-VRC relationship DIDs. Minting and custody, the mapping, the VRC mint on
 * relationship DIDs, receive-side bindings and offline proof, lifecycle end, the archive payload and
 * the store's exchange path. Temp directories only; the passphrase here is a test literal.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../../src/db/repositories/did-documents-repo.js';
import * as exchangeDids from '../../src/db/repositories/vrc-exchange-dids-repo.js';
import { RelationshipDidReuseError } from '../../src/db/repositories/vrc-exchange-dids-repo.js';
import { DidManager } from '../../src/services/did-manager.js';
import { decryptSecretKey } from '../../src/keystore/sqlite-keystore.js';
import { DidResolver } from '../../src/did/did-resolver.js';
import {
  ExchangeDidLimitError,
  MAX_PENDING_PER_COUNTERPARTY,
  checkProposedRelationshipDid,
  endExchange,
  endExchangesForConnections,
  loadExchangeSigner,
  mintExchangeRelationshipDid,
} from '../../src/relationship/exchange-dids.js';
import { mintExchangeVrc } from '../../src/relationship/vrc-mint.js';
import {
  buildConformantVrcArchivePayload,
  checkIncomingBindings,
  checkIncomingVrc,
  findExchangeVrc,
  labelVrc,
  verifyInnerProof,
} from '../../src/relationship/exchange-vrc.js';
import { VtcStore } from '../../src/vtc/store.js';
import type { IdentityResolver } from '../../src/services/identity-resolver.js';
import type { DtgCredentialVc } from '../../src/services/dtg-credential.js';

const PASS = 'test-passphrase-not-a-default';
const root = mkdtempSync(join(tmpdir(), 'p5c-'));
after(() => rmSync(root, { recursive: true, force: true }));

interface Party {
  ds: SqliteDataSource;
  identityUuid: string;
  connectionDid: string;
}

async function newDb(name: string): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(join(root, `${name}.db`));
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}

async function addIdentity(ds: SqliteDataSource, did: string): Promise<string> {
  const uuid = await identitiesRepo.create(ds, { realDid: did, role: 'vta', subjectKind: 'human', custody: 'local', name: did });
  await didDocumentsRepo.create(ds, { identityUuid: uuid, did, method: 'did:scid:vh', documentJson: '{}', isPrimary: true });
  return uuid;
}

/** Two agents' views share nothing; each has its own DB with both root identities known. */
async function pair(name: string): Promise<{ a: Party; b: Party; aRemote: string; bRemote: string }> {
  const aDid = `did:scid:vh:a-${name}`;
  const bDid = `did:scid:vh:b-${name}`;
  const dsA = await newDb(`${name}-a`);
  const dsB = await newDb(`${name}-b`);
  const aUuid = await addIdentity(dsA, aDid);
  const bInA = await addIdentity(dsA, bDid);
  const bUuid = await addIdentity(dsB, bDid);
  const aInB = await addIdentity(dsB, aDid);
  return {
    a: { ds: dsA, identityUuid: aUuid, connectionDid: aDid },
    b: { ds: dsB, identityUuid: bUuid, connectionDid: bDid },
    aRemote: bInA,
    bRemote: aInB,
  };
}

/** Run a full proposer(A)->acceptor(B) exchange and have A issue; returns both rows and the VRC. */
async function exchange(p: Awaited<ReturnType<typeof pair>>, id: string) {
  const aRow = await mintExchangeRelationshipDid(p.a.ds, {
    exchangeId: id, role: 'proposer', localIdentityUuid: p.a.identityUuid, localConnectionDid: p.a.connectionDid,
    remoteConnectionDid: p.b.connectionDid, remoteIdentityUuid: p.aRemote, passphrase: PASS,
  });
  const bRow = await mintExchangeRelationshipDid(p.b.ds, {
    exchangeId: id, role: 'acceptor', localIdentityUuid: p.b.identityUuid, localConnectionDid: p.b.connectionDid,
    remoteConnectionDid: p.a.connectionDid, remoteIdentityUuid: p.bRemote, remoteRelationshipDid: aRow.localRelationshipDid, passphrase: PASS,
  });
  const aAfter = await exchangeDids.setRemoteRelationshipDid(p.a.ds, id, bRow.localRelationshipDid);
  await exchangeDids.setState(p.a.ds, id, 'accepted');
  return { aRow: (await exchangeDids.findByExchangeId(p.a.ds, id))!, bRow, aAfter };
}

describe('relationship DID creation and key custody', () => {
  it('is a signing-only did:peer:4: one key under authentication and assertionMethod, no service, no key agreement', async () => {
    const p = await pair('doc');
    const r = await new DidManager(p.a.ds).createRelationshipDid(p.a.identityUuid, 'x-1', PASS);
    assert.match(r.did, /^did:peer:4/);
    const row = await didDocumentsRepo.findByRealDid(p.a.ds, r.did);
    assert.equal(row?.contextType, 'relationship');
    assert.equal(row?.isPrimary === 0 || row?.isPrimary === false, true);
    const doc = JSON.parse(row!.documentJson);
    assert.equal(doc.verificationMethod.length, 1);
    assert.deepEqual(doc.assertionMethod, ['#key-1']);
    assert.deepEqual(doc.authentication, ['#key-1']);
    assert.deepEqual(doc.keyAgreement, []);
    assert.equal(doc.service, undefined);
    const resolved = await new DidResolver().dereferenceVerificationMethod(`${r.did}#key-1`);
    assert.ok(resolved?.proofPurposes.includes('assertionMethod'));
    assert.deepEqual(Array.from(resolved!.rawKey), Array.from(r.signingKeyPair.publicKey));
  });

  it('stores the secret encrypted under the passphrase it was given, and refuses a missing one', async () => {
    const p = await pair('key');
    const m = new DidManager(p.a.ds);
    await assert.rejects(() => m.createRelationshipDid(p.a.identityUuid, 'x-1', ''), /passphrase is required/);
    const r = await m.createRelationshipDid(p.a.identityUuid, 'x-2', PASS);
    const doc = (await didDocumentsRepo.findByRealDid(p.a.ds, r.did))!;
    const key = (await p.a.ds.get<{ encrypted_secret_key: Buffer; salt: Buffer; nonce: Buffer; auth_tag: Buffer }>(
      'SELECT * FROM keys WHERE did_document_uuid = ?', doc.uuid,
    ))!;
    assert.ok(key.encrypted_secret_key.length > 0);
    assert.equal(Buffer.from(key.encrypted_secret_key).includes(Buffer.from(r.signingKeyPair.secretKey)), false, 'not stored in clear');
    const plain = await decryptSecretKey(
      { ciphertext: key.encrypted_secret_key, salt: key.salt, nonce: key.nonce, authTag: key.auth_tag }, PASS);
    assert.deepEqual(Array.from(plain), Array.from(r.signingKeyPair.secretKey));
    await assert.rejects(() => m.loadRelationshipSigningKey(r.did, 'wrong-passphrase'), /decryption failed/);
    assert.deepEqual(Array.from((await m.loadRelationshipSigningKey(r.did, PASS))!.secretKey), Array.from(r.signingKeyPair.secretKey));
    // The development constant never protects these keys.
    await assert.rejects(() => m.loadRelationshipSigningKey(r.did, 'dev-only-insecure-passphrase'), /decryption failed/);
  });
});

describe('minting and the exchange mapping', () => {
  it('two exchanges with one counterparty give distinct DIDs on both sides, none equal to a connection DID', async () => {
    const p = await pair('two');
    const e1 = await exchange(p, 'propose-1');
    const e2 = await exchange(p, 'propose-2');
    const all = [e1.aRow.localRelationshipDid, e1.bRow.localRelationshipDid, e2.aRow.localRelationshipDid, e2.bRow.localRelationshipDid];
    assert.equal(new Set(all).size, 4);
    for (const d of all) assert.ok(d !== p.a.connectionDid && d !== p.b.connectionDid);
    assert.equal((await exchangeDids.listByConnections(p.a.ds, p.a.connectionDid, p.b.connectionDid)).length, 2);
    assert.equal(e1.aRow.remoteRelationshipDid, e1.bRow.localRelationshipDid);
  });

  it('is durable before it is returned: a reopened database holds the mapping and the encrypted key', async () => {
    const p = await pair('durable');
    const row = await mintExchangeRelationshipDid(p.a.ds, {
      exchangeId: 'propose-d', role: 'proposer', localIdentityUuid: p.a.identityUuid, localConnectionDid: p.a.connectionDid,
      remoteConnectionDid: p.b.connectionDid, passphrase: PASS,
    });
    p.a.ds.close?.();
    const reopened = new SqliteDataSource(join(root, 'durable-a.db'));
    assert.equal((await exchangeDids.findByExchangeId(reopened, 'propose-d'))?.localRelationshipDid, row.localRelationshipDid);
    assert.ok(await loadExchangeSigner(reopened, 'propose-d', PASS));
  });

  it('a resend of the same exchange returns the same DID; a conflicting resend is refused', async () => {
    const p = await pair('resend');
    const input = {
      exchangeId: 'propose-r', role: 'proposer' as const, localIdentityUuid: p.a.identityUuid, localConnectionDid: p.a.connectionDid,
      remoteConnectionDid: p.b.connectionDid, passphrase: PASS,
    };
    const first = await mintExchangeRelationshipDid(p.a.ds, input);
    assert.equal((await mintExchangeRelationshipDid(p.a.ds, input)).localRelationshipDid, first.localRelationshipDid);
    await assert.rejects(() => mintExchangeRelationshipDid(p.a.ds, { ...input, role: 'acceptor' }), /different parties or role/);
  });

  it('refuses a counterparty relationship DID that another exchange holds (either column)', async () => {
    const p = await pair('reuse');
    const e1 = await exchange(p, 'propose-1');
    await mintExchangeRelationshipDid(p.a.ds, {
      exchangeId: 'propose-2', role: 'proposer', localIdentityUuid: p.a.identityUuid, localConnectionDid: p.a.connectionDid,
      remoteConnectionDid: p.b.connectionDid, passphrase: PASS,
    });
    await assert.rejects(() => exchangeDids.setRemoteRelationshipDid(p.a.ds, 'propose-2', e1.bRow.localRelationshipDid), RelationshipDidReuseError);
    await assert.rejects(() => exchangeDids.setRemoteRelationshipDid(p.a.ds, 'propose-2', e1.aRow.localRelationshipDid), RelationshipDidReuseError);
  });

  it('caps pending exchanges per counterparty and mints nothing past the cap', async () => {
    const p = await pair('cap');
    const base = { role: 'proposer' as const, localIdentityUuid: p.a.identityUuid, localConnectionDid: p.a.connectionDid, remoteConnectionDid: p.b.connectionDid, passphrase: PASS };
    for (let i = 0; i < MAX_PENDING_PER_COUNTERPARTY; i++) await mintExchangeRelationshipDid(p.a.ds, { ...base, exchangeId: `p-${i}` });
    const before = (await p.a.ds.get<{ n: number }>("SELECT COUNT(*) AS n FROM did_documents WHERE context_type = 'relationship'"))!.n;
    await assert.rejects(() => mintExchangeRelationshipDid(p.a.ds, { ...base, exchangeId: 'p-over' }), ExchangeDidLimitError);
    assert.equal((await p.a.ds.get<{ n: number }>("SELECT COUNT(*) AS n FROM did_documents WHERE context_type = 'relationship'"))!.n, before);
  });
});

describe('propose pre-check', () => {
  it('refuses malformed, connection DIDs, known identities, DIDs held by another exchange, and a changed DID', async () => {
    const p = await pair('pre');
    const e1 = await exchange(p, 'propose-1');
    const base = { senderConnectionDid: p.b.connectionDid, localConnectionDid: p.a.connectionDid, exchangeId: 'propose-9' };
    const reason = async (relationshipDid: unknown, exchangeId = base.exchangeId) =>
      (await checkProposedRelationshipDid(p.a.ds, { ...base, relationshipDid, exchangeId }) as { reason?: string }).reason;
    assert.equal(await reason('not-a-did'), 'malformed');
    assert.equal(await reason(42), 'malformed');
    assert.equal(await reason(p.b.connectionDid), 'equalsConnectionDid');
    assert.equal(await reason(p.a.connectionDid), 'equalsConnectionDid');
    assert.equal(await reason('did:scid:vh:someone-we-know'), undefined);
    await addIdentity(p.a.ds, 'did:scid:vh:third-party');
    assert.equal(await reason('did:scid:vh:third-party'), 'knownConnectionDid');
    assert.equal(await reason(e1.aRow.remoteRelationshipDid), 'reusedRelationshipDid');
    assert.equal(await reason('did:peer:4zOther', 'propose-1'), 'exchangeConflict');
    assert.equal(await reason(e1.aRow.remoteRelationshipDid, 'propose-1'), undefined, 'a resend with the same DID passes');
  });
});

describe('VRC on relationship DIDs', () => {
  it('uses the relationship DIDs as issuer and subject, signs with the relationship key, declares pairwise, repeats no connection DID', async () => {
    const p = await pair('vrc');
    const e = await exchange(p, 'propose-1');
    const r = await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-1', passphrase: PASS });
    assert.equal(r.success, true);
    if (!r.success) return;
    assert.equal(r.alreadyIssued, false);
    const vc = JSON.parse(r.w3cVcJson) as DtgCredentialVc & { credentialSubject: { id: string } };
    assert.equal(vc.issuer, e.aRow.localRelationshipDid);
    assert.equal(vc.credentialSubject.id, e.bRow.localRelationshipDid);
    assert.equal(vc.issuerScope, 'pairwise');
    assert.equal(vc.proof.verificationMethod, `${e.aRow.localRelationshipDid}#key-1`);
    assert.equal(vc.proof.proofPurpose, 'assertionMethod');
    assert.equal(r.w3cVcJson.includes(p.a.connectionDid), false);
    assert.equal(r.w3cVcJson.includes(p.b.connectionDid), false);
    assert.equal(labelVrc(r.w3cVcJson), 'conformant');
    assert.equal(await verifyInnerProof(vc), true, 'verifies offline from the did:peer:4 alone');
    // issuerScope is inside the signed bytes.
    assert.equal(await verifyInnerProof({ ...vc, issuerScope: 'public' } as DtgCredentialVc), false);
    // The credential row hangs off the root identities: one node per peer.
    const row = (await p.a.ds.get<{ issuer_identity_uuid: string; subject_identity_uuid: string }>('SELECT * FROM credentials WHERE uuid = ?', r.credentialUuid))!;
    assert.equal(row.issuer_identity_uuid, p.a.identityUuid);
    assert.equal(row.subject_identity_uuid, p.aRemote);
  });

  it('a resend is alreadyIssued with the stored credential; a second exchange is a new VRC', async () => {
    const p = await pair('second');
    await exchange(p, 'propose-1');
    const first = await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-1', passphrase: PASS });
    const again = await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-1', passphrase: PASS });
    assert.ok(first.success && again.success);
    if (!first.success || !again.success) return;
    assert.equal(again.alreadyIssued, true);
    assert.equal(again.w3cVcJson, first.w3cVcJson);
    await exchange(p, 'propose-2');
    const second = await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-2', passphrase: PASS });
    assert.ok(second.success);
    if (!second.success) return;
    assert.equal(second.alreadyIssued, false);
    assert.notEqual(second.credentialUuid, first.credentialUuid);
    assert.equal((await p.a.ds.get<{ n: number }>("SELECT COUNT(*) AS n FROM credentials WHERE vc_type = 'vrc'"))!.n, 2);
  });

  it('refuses to mint before acceptance, for an unknown exchange, and with a wrong passphrase', async () => {
    const p = await pair('mintrefuse');
    await mintExchangeRelationshipDid(p.a.ds, {
      exchangeId: 'propose-1', role: 'proposer', localIdentityUuid: p.a.identityUuid, localConnectionDid: p.a.connectionDid,
      remoteConnectionDid: p.b.connectionDid, remoteIdentityUuid: p.aRemote, passphrase: PASS,
    });
    assert.deepEqual(await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-1', passphrase: PASS }), { success: false, reason: 'notAccepted' });
    assert.deepEqual(await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'nope', passphrase: PASS }), { success: false, reason: 'noExchange' });
  });
});

describe('receive side', () => {
  async function issued(name: string) {
    const p = await pair(name);
    const e = await exchange(p, 'propose-1');
    const r = await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-1', passphrase: PASS });
    assert.ok(r.success);
    return { p, e, json: (r as { w3cVcJson: string }).w3cVcJson };
  }

  it('accepts the credential for its exchange and refuses a wrong issuer, subject, missing scope or broken proof', async () => {
    const { e, json } = await issued('recv');
    assert.deepEqual(await checkIncomingVrc(json, e.bRow), { ok: true });
    const other = { ...e.bRow, remoteRelationshipDid: 'did:peer:4zWrong' };
    assert.deepEqual(await checkIncomingVrc(json, other), { ok: false, reason: 'issuerMismatch' });
    assert.deepEqual(await checkIncomingVrc(json, { ...e.bRow, localRelationshipDid: 'did:peer:4zWrong' }), { ok: false, reason: 'subjectMismatch' });
    const noScope = JSON.parse(json);
    delete noScope.issuerScope;
    assert.deepEqual(checkIncomingBindings(noScope, e.bRow), { ok: false, reason: 'scopeMissing' });
    assert.deepEqual(checkIncomingBindings('x', e.bRow), { ok: false, reason: 'malformed' });
    const tampered = JSON.parse(json);
    tampered.validFrom = '2001-01-01T00:00:00.000Z';
    assert.deepEqual(await checkIncomingVrc(JSON.stringify(tampered), e.bRow), { ok: false, reason: 'proofInvalid' });
  });

  it('stores a second exchange as a new credential (digest-only dedup), ignoring remote identity data', async () => {
    const p = await pair('store');
    const stores = new VtcStore(p.b.ds.getRawDb(), {} as IdentityResolver);
    const jsons: string[] = [];
    for (const id of ['propose-1', 'propose-2']) {
      await exchange(p, id);
      const r = await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: id, passphrase: PASS });
      assert.ok(r.success);
      jsons.push((r as { w3cVcJson: string }).w3cVcJson);
    }
    for (const j of [jsons[0], jsons[1], jsons[0]]) {
      const vc = JSON.parse(j);
      stores.storeReceivedDtgVrc(j, vc.issuer, vc.credentialSubject.id, { forged: true }, {
        issuerIdentityUuid: p.b.ds === p.b.ds ? p.bRemote : '', subjectIdentityUuid: p.b.identityUuid,
      });
    }
    const rows = await p.b.ds.all<{ issuer_identity_uuid: string }>("SELECT issuer_identity_uuid FROM credentials WHERE vc_type = 'vrc'");
    assert.equal(rows.length, 2, 'two exchanges, two credentials; the repeat is idempotent');
    assert.ok(rows.every((r) => r.issuer_identity_uuid === p.bRemote));
    const bRow = (await exchangeDids.findByExchangeId(p.b.ds, 'propose-1'))!;
    assert.ok(await findExchangeVrc(p.b.ds, bRow, 'received'));
    assert.equal(await findExchangeVrc(p.b.ds, bRow, 'issued'), null);
  });
});

describe('lifecycle and archive', () => {
  it('ending an exchange deletes the secret key, keeps the public document and the row, and stops minting', async () => {
    const p = await pair('end');
    const e = await exchange(p, 'propose-1');
    const r = await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-1', passphrase: PASS });
    assert.ok(r.success);
    assert.equal(await endExchangesForConnections(p.a.ds, p.a.connectionDid, p.b.connectionDid), 1);
    assert.equal((await exchangeDids.findByExchangeId(p.a.ds, 'propose-1'))?.state, 'ended');
    const doc = (await didDocumentsRepo.findByRealDid(p.a.ds, e.aRow.localRelationshipDid))!;
    assert.ok(doc, 'public document retained');
    const key = (await p.a.ds.get<{ encrypted_secret_key: unknown; salt: unknown; public_key: Buffer }>('SELECT * FROM keys WHERE did_document_uuid = ?', doc.uuid))!;
    assert.equal(key.encrypted_secret_key, null);
    assert.equal(key.salt, null);
    assert.ok(key.public_key.length > 0);
    assert.equal(await loadExchangeSigner(p.a.ds, 'propose-1', PASS), null);
    assert.deepEqual(await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-1', passphrase: PASS }), { success: false, reason: 'ended' });
    assert.equal(await verifyInnerProof(JSON.parse((r as { w3cVcJson: string }).w3cVcJson)), true, 'stored VRC still verifies');
    assert.equal(await endExchange(p.a.ds, 'propose-1'), true, 'idempotent');
    assert.equal(await endExchange(p.a.ds, 'absent'), false);
  });

  it('the archive payload carries the credential only: no connection identity record, no connection DID', async () => {
    const p = await pair('archive');
    await exchange(p, 'propose-1');
    const r = await mintExchangeVrc({ dataSource: p.a.ds, exchangeId: 'propose-1', passphrase: PASS });
    assert.ok(r.success);
    if (!r.success) return;
    const payload = await buildConformantVrcArchivePayload(p.a.ds, r.credentialUuid);
    assert.deepEqual(Object.keys(payload), ['vrcArchive']);
    const text = JSON.stringify(payload);
    for (const banned of ['realDid', 'didDocument', 'publicKeys', 'peerId', 'relationship"', p.a.connectionDid, p.b.connectionDid]) {
      assert.equal(text.includes(banned), false, `payload must not contain ${banned}`);
    }
    await p.a.ds.run(
      "INSERT INTO credentials (vc_type, issuer_identity_uuid, subject_identity_uuid, w3c_vc_json, claim, status, valid_from, uuid, created_at) VALUES ('vrc', ?, ?, '{\"issuer\":\"did:x\"}', '{}', 'issued', 1, 'legacy-1', 1)",
      p.a.identityUuid, p.aRemote);
    await assert.rejects(() => buildConformantVrcArchivePayload(p.a.ds, 'legacy-1'), /not a conformant VRC/);
    assert.equal(labelVrc('{"issuer":"did:x"}'), 'legacy');
    assert.equal(labelVrc(null), 'legacy');
  });
});
