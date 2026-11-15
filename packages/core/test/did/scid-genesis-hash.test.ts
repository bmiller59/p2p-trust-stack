// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The identifier must be the hash of the genesis entry, checked inside `resolveFromLog`
 * and the chain validation behind it (not only by the time-pinned resolver), so every resolver that
 * replays a log refuses a self-consistent log served under an identifier it does not belong to.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';
import { ScidVhMethod, scidMatchesGenesis } from '../../src/did/scid-vh-method.js';
import { DidResolutionService } from '../../src/did/did-resolution-service.js';
import { packRotationEntry } from '../../src/did/rotation-entry-codec.js';
import { computeRotationEntryDigest } from '../../src/did/rotation-codec.js';
import { generateEd25519KeyPair, signEd25519 } from '../../src/crypto/primitives.js';
import type { RotationLogEntry } from '../../src/did/rotation-types.js';

const method = new ScidVhMethod({});
// validateChain is private; the tests pin its behaviour through this view of it.
const validEntries = (log: RotationLogEntry[], did?: string): RotationLogEntry[] =>
  (method as unknown as { validateChain(l: RotationLogEntry[], d?: string): { validEntries: RotationLogEntry[] } }).validateChain(log, did).validEntries;

/** A self-consistent log (valid digest and signature) that is labelled with the victim's DID but is not that DID's preimage. */
async function forgedFor(victimDid: string): Promise<RotationLogEntry[]> {
  const forger = await method.create();
  const g = forger.log[0]!;
  const didDocument = { ...g.didDocument, id: victimDid };
  const digest = computeRotationEntryDigest({ ...g, didDocument });
  return [{ ...g, didDocument, digest, signature: signEd25519(digest, forger.signingKeyPair.secretKey), mlDsa65Signature: undefined }];
}

async function rotated() {
  const created = await method.create();
  const e1 = await method.rotate({
    currentLog: created.log,
    outgoingSigningKeyPair: created.signingKeyPair,
    newSigningKeyPair: created.nextSigningKeyPairs[0]!,
    nextSigningPublicKey: generateEd25519KeyPair().publicKey,
    witnessAttestations: [],
  });
  return { did: created.did, log: [...created.log, e1] };
}

describe('resolveFromLog: the identifier is the hash of the genesis entry', () => {
  it('a genuine log, genesis only or rotated, still resolves', async () => {
    const created = await method.create();
    assert.equal(method.resolveFromLog(created.did, created.log).id, created.did);
    const r = await rotated();
    assert.equal(r.log.length, 2);
    assert.equal(method.resolveFromLog(r.did, r.log).id, r.did);
  });

  it('a self-consistent log relabelled with another identifier is refused as an SCID mismatch', async () => {
    const victim = await method.create();
    const forged = await forgedFor(victim.did);
    assert.equal(validEntries(forged).length, 1, 'precondition: chain-valid on its own');
    assert.throws(() => method.resolveFromLog(victim.did, forged), /SCID mismatch/);
  });

  it("another identifier's genuine log is refused for this DID", async () => {
    const a = await method.create();
    const b = await method.create();
    assert.throws(() => method.resolveFromLog(a.did, b.log), /SCID mismatch/);
  });

  it('a forged genesis followed by genuine-looking rotations is refused too', async () => {
    const r = await rotated();
    const victim = await method.create();
    assert.throws(() => method.resolveFromLog(victim.did, r.log), /SCID mismatch/);
  });

  it('a DID whose SCID differs by one character, or in another format, is refused', async () => {
    const created = await method.create();
    const last = created.did.slice(-1);
    const tweaked = created.did.slice(0, -1) + (last === '1' ? '2' : '1');
    assert.throws(() => method.resolveFromLog(tweaked, created.log), /SCID mismatch/);
    assert.throws(() => method.resolveFromLog(created.did.replace('did:scid:vh:1:', 'did:scidvh:'), created.log), /SCID mismatch/);
  });

  it('the store-backed resolve() inherits the check', async () => {
    const victim = await method.create();
    const forged = await forgedFor(victim.did);
    const store = { getLog: (did: string) => (did === victim.did ? forged : []) } as never;
    assert.throws(() => new ScidVhMethod({ store }).resolve(victim.did), /SCID mismatch/);
  });
});

describe('chain validation with an identifier', () => {
  it('validateChain(log, did) accepts only a chain whose genesis hashes to the identifier; without one it checks consistency only', async () => {
    const r = await rotated();
    assert.equal(validEntries(r.log, r.did).length, 2);
    const victim = await method.create();
    const forged = await forgedFor(victim.did);
    assert.equal(validEntries(forged).length, 1);
    assert.equal(validEntries(forged, victim.did).length, 0);
    assert.equal(validEntries(r.log, victim.did).length, 0);
  });

  it('scidMatchesGenesis is the shared check', async () => {
    const created = await method.create();
    assert.equal(scidMatchesGenesis(created.did, created.log[0]!), true);
    assert.equal(scidMatchesGenesis(created.did, { ...created.log[0]!, version: 1 }), false);
  });
});

describe('the server resolver (DidResolutionService) does not report a mismatched log as a verified replay', () => {
  async function seed(ds: SqliteDataSource, did: string, log: RotationLogEntry[]): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await ds.run(`INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at) VALUES ('id-1', 'vta', 'human', 'local', 'alice', ?, ?)`, now, now);
    await ds.run(
      `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, status, created_at, updated_at) VALUES ('doc-1', 'id-1', ?, 'did:scid:vh', NULL, 1, 'active', ?, ?)`,
      did, now, now,
    );
    for (const entry of log) {
      await ds.run(
        `INSERT INTO rotation_log (uuid, did_document_uuid, version, previous_hash, new_public_key, signed_entry, created_at) VALUES (?, 'doc-1', ?, ?, ?, ?, ?)`,
        `rl-${entry.version}`, entry.version, entry.prevHash ?? null,
        Buffer.from(JSON.stringify(entry.nextKeyCommitments.map((k) => Buffer.from(k).toString('base64')))),
        Buffer.from(packRotationEntry({ didDocument: entry.didDocument, parameters: entry.parameters, digest: entry.digest, signature: entry.signature, mlDsa65Signature: entry.mlDsa65Signature })),
        entry.createdAt,
      );
    }
  }
  const db = (): SqliteDataSource => {
    const ds = new SqliteDataSource(':memory:');
    runMigrations(ds.getRawDb(), getMigrationsDir());
    return ds;
  };

  it('a genuine stored log resolves from the log; a forged one stored under the victim identifier does not', async () => {
    const r = await rotated();
    const good = db();
    await seed(good, r.did, r.log);
    assert.equal((await new DidResolutionService(good).resolve(r.did)).source, 'log');

    const victim = await method.create();
    const bad = db();
    await seed(bad, victim.did, await forgedFor(victim.did));
    const report = await new DidResolutionService(bad).resolve(victim.did);
    assert.notEqual(report.source, 'log', 'no verified replay of a log that is not the identifier\'s preimage');
  });
});
