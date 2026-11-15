// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Participants apply their effect at COMMIT (from `pending_ops`), never at prepare: a prepare followed by an
 * abort, or by a crash and a restart, leaves no state behind, and a commit by a fresh participant instance
 * (a process restart) still applies. Covers the legacy branch of VrcReceiveParticipant and the personhood
 * acknowledgement participant. The witness-share and presentation participants are covered in their own suites.
 * Temp databases only.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after } from 'node:test';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { applyTxSchemaAdditions, TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/schema.js';
import { VrcCeremonyStore } from '@p2p-trust-stack/core/tx/vrc-ceremony-store.js';
import type { VtcStore } from '@p2p-trust-stack/core/vtc/store.js';
import type { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import { VrcReceiveParticipant } from '../../src/runtime/tx/vrc-receive-participant.js';
import { PersonhoodAckReceiveParticipant } from '../../src/runtime/tx/personhood-ack-participant.js';

const root = mkdtempSync(join(tmpdir(), 'commit-apply-'));
after(() => rmSync(root, { recursive: true, force: true }));

/** A file-backed tx database, so a "restart" can reopen the same bytes. */
async function openTxDb(path: string): Promise<SqliteDataSource> {
  const ds = new SqliteDataSource(path);
  ds.getRawDb().exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(ds);
  return ds;
}

const LOCAL = 'did:peer:4zlocal';
const REMOTE = 'did:peer:4zremote';

describe('VrcReceiveParticipant, legacy branch: apply at commit', () => {
  function stubStore(): { store: VtcStore; calls: string[] } {
    const calls: string[] = [];
    const seen = new Set<string>();
    const store = {
      storeReceivedDtgVrc: (json: string) => {
        calls.push(json);
        seen.add(json);
      },
    } as unknown as VtcStore;
    return { store, calls };
  }
  const op = { op: 'store_remote_vrc', params: { w3cVcJson: '{"vrc":1}', issuerDid: REMOTE, subjectDid: LOCAL } } as never;
  const make = (txDb: SqliteDataSource, store: VtcStore) =>
    new VrcReceiveParticipant('peer:local', txDb, txDb, store, {} as IdentityResolver);
  const leg = async (txDb: SqliteDataSource) => (await new VrcCeremonyStore(txDb).getByPair(LOCAL, REMOTE))?.peerVrcReceived ?? false;

  it('prepare stores nothing and sets no ceremony leg', async () => {
    const txDb = await openTxDb(join(root, 'v1.db'));
    const { store, calls } = stubStore();
    assert.equal(await make(txDb, store).prepare('tx-1', [op]), 'yes');
    assert.equal(calls.length, 0);
    assert.equal(await leg(txDb), false);
  });

  it('prepare then abort leaves no credential and no peerVrcReceived', async () => {
    const txDb = await openTxDb(join(root, 'v2.db'));
    const { store, calls } = stubStore();
    const p = make(txDb, store);
    await p.prepare('tx-1', [op]);
    await p.abort('tx-1');
    assert.equal(calls.length, 0);
    assert.equal(await leg(txDb), false);
    assert.equal(await p.inquiry('tx-1'), 'aborted');
  });

  it('prepare, restart, abort leaves nothing; prepare, restart, commit applies with a fresh instance', async () => {
    const path = join(root, 'v3.db');
    const first = stubStore();
    let txDb = await openTxDb(path);
    await make(txDb, first.store).prepare('tx-a', [op]);
    await make(txDb, first.store).prepare('tx-b', [op]);
    txDb.getRawDb().close();

    txDb = await openTxDb(path);
    const after = stubStore();
    const p = make(txDb, after.store);
    assert.equal(await p.inquiry('tx-a'), 'prepared');
    await p.abort('tx-a');
    assert.equal(after.calls.length, 0);
    assert.equal(await leg(txDb), false);
    await p.commit('tx-b');
    assert.equal(after.calls.length, 1);
    assert.equal(await leg(txDb), true);
    assert.equal(await p.inquiry('tx-b'), 'committed');
  });

  it('commit twice applies idempotently and leaves one leg flag', async () => {
    const txDb = await openTxDb(join(root, 'v4.db'));
    const { store } = stubStore();
    const p = make(txDb, store);
    await p.prepare('tx-1', [op]);
    await p.commit('tx-1');
    await p.commit('tx-1');
    assert.equal(await leg(txDb), true);
    const n = await txDb.get<{ n: number }>('SELECT COUNT(*) AS n FROM vrc_ceremonies');
    assert.equal(Number(n!.n), 1);
    assert.equal(await p.inquiry('tx-1'), 'committed');
  });

  it('a prepare with no credential still votes no', async () => {
    const txDb = await openTxDb(join(root, 'v5.db'));
    const bad = { op: 'store_remote_vrc', params: { issuerDid: REMOTE, subjectDid: LOCAL } } as never;
    assert.equal(await make(txDb, stubStore().store).prepare('tx-1', [bad]), 'no');
  });
});

describe('PersonhoodAckReceiveParticipant: apply at commit', () => {
  const op = { op: 'personhood_ack', params: { fromDid: REMOTE } } as never;
  const make = (txDb: SqliteDataSource, onAck?: (d: string) => void) => new PersonhoodAckReceiveParticipant('peer:local', txDb, LOCAL, onAck);
  const acked = async (txDb: SqliteDataSource) => (await new VrcCeremonyStore(txDb).getByPair(LOCAL, REMOTE))?.remoteAcked ?? false;

  it('prepare does not set the remote-acked flag', async () => {
    const txDb = await openTxDb(join(root, 'p1.db'));
    assert.equal(await make(txDb).prepare('tx-1', [op]), 'yes');
    assert.equal(await acked(txDb), false);
  });

  it('prepare, restart, abort leaves the flag unset (no in-memory state needed)', async () => {
    const path = join(root, 'p2.db');
    let txDb = await openTxDb(path);
    await make(txDb).prepare('tx-1', [op]);
    txDb.getRawDb().close();
    txDb = await openTxDb(path);
    await make(txDb).abort('tx-1');
    assert.equal(await acked(txDb), false);
  });

  it('prepare, restart, commit sets the flag and notifies once; a second commit is idempotent', async () => {
    const path = join(root, 'p3.db');
    let txDb = await openTxDb(path);
    await make(txDb).prepare('tx-1', [op]);
    txDb.getRawDb().close();
    txDb = await openTxDb(path);
    const seen: string[] = [];
    const p = make(txDb, (d) => seen.push(d));
    await p.commit('tx-1');
    assert.equal(await acked(txDb), true);
    assert.deepEqual(seen, [REMOTE]);
    await p.commit('tx-1');
    assert.equal(await acked(txDb), true);
    assert.equal(seen.length, 1, 'a repeated commit does not notify again');
  });

  it('a prepare without a sender DID votes no', async () => {
    const txDb = await openTxDb(join(root, 'p4.db'));
    assert.equal(await make(txDb).prepare('tx-1', [{ op: 'personhood_ack', params: {} } as never]), 'no');
  });
});
