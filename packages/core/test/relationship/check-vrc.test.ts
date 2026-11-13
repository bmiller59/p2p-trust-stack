// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P6a: `checkVrc` (the one receive check the boundary uses), the held / declined exchange
 * states and the helper that ends a declined proposal. Temp directories only.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';
import * as identitiesRepo from '../../src/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../../src/db/repositories/did-documents-repo.js';
import * as exchangeDids from '../../src/db/repositories/vrc-exchange-dids-repo.js';
import { declineExchange, loadExchangeSigner, mintExchangeRelationshipDid } from '../../src/relationship/exchange-dids.js';
import { mintExchangeVrc } from '../../src/relationship/vrc-mint.js';
import { checkVrc, checkIncomingVrc } from '../../src/relationship/exchange-vrc.js';
import { DidProofVerifier } from '../../src/services/trust-tasks/boundary/proof/verify.js';
import { createLocalKeyResolver } from '../../src/services/trust-tasks/boundary/proof/install.js';
import { didKeyFromEd25519 } from '../../src/services/trust-tasks/boundary/proof/resolver.js';
import { createEd25519BoundarySigner, signDocument } from '../../src/services/trust-tasks/boundary/proof/signer.js';

const PASS = 'test-passphrase-not-a-default';
const root = mkdtempSync(join(tmpdir(), 'p6-checkvrc-'));
after(() => rmSync(root, { recursive: true, force: true }));
const NOW = Date.now() + 1000; // the mint stamps the real clock
const verifier = new DidProofVerifier({ resolver: createLocalKeyResolver({}) });

async function db(name: string) {
  const ds = new SqliteDataSource(join(root, `${name}.db`));
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}
async function ident(ds: SqliteDataSource, did: string) {
  const uuid = await identitiesRepo.create(ds, { realDid: did, role: 'vta', subjectKind: 'human', custody: 'local', name: did });
  await didDocumentsRepo.create(ds, { identityUuid: uuid, did, method: 'did:scid:vh', documentJson: '{}', isPrimary: true });
  return uuid;
}

describe('checkVrc', () => {
  let n = 0;
  async function minted() {
    const tag = `m${n++}`;
    const A = 'did:scid:vh:a', B = 'did:scid:vh:b';
    const dsA = await db(`a-${tag}`);
    const aUuid = await ident(dsA, A);
    const bUuid = await ident(dsA, B);
    const row = await mintExchangeRelationshipDid(dsA, { exchangeId: 'ex-1', role: 'proposer', localIdentityUuid: aUuid, localConnectionDid: A, remoteConnectionDid: B, remoteIdentityUuid: bUuid, passphrase: PASS });
    await exchangeDids.setRemoteRelationshipDid(dsA, 'ex-1', 'did:peer:4zReceiversRelationshipDid');
    const vrc = await mintExchangeVrc({ dataSource: dsA, exchangeId: 'ex-1', passphrase: PASS });
    assert.ok(vrc.success);
    return { vc: JSON.parse((vrc as { w3cVcJson: string }).w3cVcJson), issuer: row.localRelationshipDid, subject: 'did:peer:4zReceiversRelationshipDid' };
  }

  it('accepts a did:peer:4 relationship VRC (offline) and a did:key one, under assertionMethod', async () => {
    const m = await minted();
    assert.deepEqual(await checkVrc(m.vc, m.issuer, m.subject, { verifier, nowMs: NOW }), { ok: true });

    const seed = new Uint8Array(32).fill(7);
    const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
    const signer = createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) });
    const vc = signDocument({ '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential'], issuer: did, validFrom: '2026-11-12T10:00:00Z', issuerScope: 'pairwise', credentialSubject: { id: 'did:key:zSubject' } }, signer, { created: NOW, purpose: 'assertionMethod' });
    assert.deepEqual(await checkVrc(vc, did, 'did:key:zSubject', { verifier, nowMs: NOW }), { ok: true });
  });

  it('refuses wrong issuer, wrong subject, missing scope, a changed body, and a proof under another purpose', async () => {
    const m = await minted();
    const run = (vc: unknown, i = m.issuer, s = m.subject) => checkVrc(vc, i, s, { verifier, nowMs: NOW });
    assert.deepEqual(await run(m.vc, 'did:peer:4zOther'), { ok: false, reason: 'issuerMismatch' });
    assert.deepEqual(await run(m.vc, m.issuer, 'did:peer:4zOther'), { ok: false, reason: 'subjectMismatch' });
    const { issuerScope: _s, ...noScope } = m.vc;
    assert.deepEqual(await run(noScope), { ok: false, reason: 'scopeMissing' });
    assert.deepEqual(await run({ ...m.vc, validFrom: '2001-01-01T00:00:00Z' }), { ok: false, reason: 'proofInvalid' });
    assert.deepEqual(await run(null), { ok: false, reason: 'malformed' });
    assert.deepEqual(await run('x'), { ok: false, reason: 'malformed' });
    const seed = new Uint8Array(32).fill(8);
    const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
    const signer = createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) });
    const auth = signDocument({ '@context': ['https://www.w3.org/ns/credentials/v2'], issuer: did, issuerScope: 'pairwise', credentialSubject: { id: 's' } }, signer, { created: NOW, purpose: 'authentication' });
    assert.deepEqual(await run(auth, did, 's'), { ok: false, reason: 'proofInvalid' });
  });

  it('checkIncomingVrc with a verifier uses the exchange record, never the credential, for the expected parties', async () => {
    const m = await minted();
    const dsB = await db('b');
    const bUuid = await ident(dsB, 'did:scid:vh:b');
    const aUuid = await ident(dsB, 'did:scid:vh:a');
    const rowB = await mintExchangeRelationshipDid(dsB, { exchangeId: 'ex-1', role: 'acceptor', localIdentityUuid: bUuid, localConnectionDid: 'did:scid:vh:b', remoteConnectionDid: 'did:scid:vh:a', remoteIdentityUuid: aUuid, remoteRelationshipDid: m.issuer, passphrase: PASS });
    // Receiver's own DID differs from the subject the credential names (the fixture used a literal): refused.
    assert.deepEqual(await checkIncomingVrc(JSON.stringify(m.vc), rowB, { verifier, nowMs: NOW }), { ok: false, reason: 'subjectMismatch' });
  });
});

describe('held and declined exchanges', () => {
  it('a held proposal counts toward the pending cap; declining it deletes the unused key and keeps the row', async () => {
    const ds = await db('held');
    const me = await ident(ds, 'did:scid:vh:me');
    const row = await mintExchangeRelationshipDid(ds, { exchangeId: 'h-1', role: 'acceptor', localIdentityUuid: me, localConnectionDid: 'did:scid:vh:me', remoteConnectionDid: 'did:key:zPeer', remoteRelationshipDid: 'did:key:zTheirs', passphrase: PASS, state: 'held' });
    assert.equal(row.state, 'held');
    assert.ok(await loadExchangeSigner(ds, 'h-1', PASS));
    assert.equal(await declineExchange(ds, 'h-1'), true);
    assert.equal((await exchangeDids.findByExchangeId(ds, 'h-1'))!.state, 'declined');
    assert.equal(await loadExchangeSigner(ds, 'h-1', PASS), null);
    assert.equal(await declineExchange(ds, 'h-1'), false, 'not held any more');
    // The counterparty's DID stays reserved.
    await assert.rejects(() => exchangeDids.create(ds, { exchangeId: 'h-2', localConnectionDid: 'x', remoteConnectionDid: 'y', localRelationshipDid: 'did:peer:4zNew', remoteRelationshipDid: 'did:key:zTheirs', role: 'acceptor' }));
  });
});
