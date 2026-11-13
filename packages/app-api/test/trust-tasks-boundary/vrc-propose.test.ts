// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P6a: the agent's `vrc/relationships/propose` handler, driven by vector id through the
 * suite's own runner against the real pipeline, store and per-exchange relationship DIDs. Temp
 * directories only. Vectors VRC-PRO-001..021 run at Tier 1 and Tier 2; the issue group is exercised
 * in 6b. Design tests (named) cover what the vectors cannot see: authorisation from the verified
 * actor (AUTHZ-001), nothing stored for a refusal, the mapping, the held state surviving a restart.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { VrcBoundaryAdapter } from './vrc-adapter.ts';
import { SKIP, VECTORS_DIR, loadSuiteApi } from './suite-runner.ts';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { signDocument, createEd25519BoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { ed25519 } from '@noble/curves/ed25519.js';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));
const make = async (attested: boolean) => {
  const a = await new VrcBoundaryAdapter({ attested }).init();
  adapters.push(a);
  return a;
};

const PROPOSE = 'https://trusttasks.org/spec/vrc/relationships/propose/0.1';
const NOW = '2026-11-12T10:00:00Z';

describe('VRC-PRO vectors against the agent boundary', { skip: SKIP, timeout: 300_000 }, () => {
  for (const tier of [1, 2] as const) {
    it(`tier ${tier}: every VRC-PRO vector that applies passes (none FAIL)`, async () => {
      const api = await loadSuiteApi();
      const suite = api.loadSuite(VECTORS_DIR);
      const adapter = await make(tier === 2);
      const run = await api.runSuite({ adapter, suite, tier, today: '2026-11-13', fixtureRoot: VECTORS_DIR });
      const pro = run.results.filter((r) => r.group === 'VRC-PRO');
      const failed = pro.filter((r) => r.status === 'FAIL').map((r) => `${r.id}: ${(r.failures ?? []).join('; ')}`);
      assert.deepEqual(failed, []);
      // Settled expectations pass (not merely observed); CLARIFY vectors observed pass too.
      const status = new Map(pro.map((r) => [r.id, r]));
      for (const id of ['VRC-PRO-001', 'VRC-PRO-002', 'VRC-PRO-003', 'VRC-PRO-004', 'VRC-PRO-005', 'VRC-PRO-006', 'VRC-PRO-007', 'VRC-PRO-008', 'VRC-PRO-009', 'VRC-PRO-010', 'VRC-PRO-014', 'VRC-PRO-015', 'VRC-PRO-020', 'VRC-PRO-021']) {
        assert.equal(status.get(id)?.status, 'PASS', id);
      }
      if (tier === 1) assert.equal(status.get('VRC-PRO-011')?.status, 'PASS');
      if (tier === 2) {
        for (const id of ['VRC-PRO-012', 'VRC-PRO-013', 'VRC-PRO-019']) assert.equal(status.get(id)?.status, 'PASS', id);
        assert.equal(status.get('VRC-PRO-011')?.status, 'SKIP');
      }
      for (const id of ['VRC-PRO-016', 'VRC-PRO-017', 'VRC-PRO-018']) {
        assert.equal(status.get(id)?.status, 'CLARIFY');
        assert.match(status.get(id)?.reason ?? '', /observed: pass/, id);
      }
    });
  }
});

/** Hand-built signed documents from a harness-style actor, for the design tests. */
function actor(seedByte: number) {
  const seed = new Uint8Array(32).fill(seedByte);
  const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
  return { did, signer: createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) }) };
}
const propose = (from: ReturnType<typeof actor>, iut: string, id: string, rel: string, extra: Record<string, unknown> = {}) =>
  JSON.stringify(signDocument({ id, threadId: id, type: PROPOSE, issuer: from.did, recipient: iut, issuedAt: NOW, payload: { relationshipDid: rel }, ...extra }, from.signer, { created: Date.parse(NOW) }));

describe('design: propose authorisation and storage (AUTHZ-001, refuse before storing)', () => {
  const A = actor(0x0a), X = actor(0x0b), R = actor(0x0c), R2 = actor(0x0d);
  const req = (n: number) => `urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-00000000000${n}`;

  it('AUTHZ-001 design: a verified proof by someone other than the issuer, or no actor at all, is not an actor', async () => {
    const adapter = await make(false);
    await adapter.setClock(NOW);
    await adapter.trigger('policy', { propose: 'accept' });
    // No transport sender and no proof: nothing establishes who is asking.
    const unsigned = JSON.stringify({ id: req(1), threadId: req(1), type: PROPOSE, issuer: A.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { relationshipDid: R.did } });
    const r1 = await adapter.send({ from: { kind: 'none' }, bytes: unsigned });
    assert.equal(JSON.parse(r1.replies[0]!).payload.code, 'permissionDenied');
    // Properly signed by A, but the carrier authenticated someone else: the in-band identity is contested.
    const r2 = await adapter.send({ from: { kind: 'actor', vid: X.did }, bytes: propose(A, adapter.signer.did, req(2), R.did) });
    assert.equal(JSON.parse(r2.replies[0]!).payload.code, 'identityMismatch');
    assert.equal(await adapter.storedCount(), 0);
    const rows = await adapter.db.all('SELECT * FROM vrc_exchange_relationship_dids');
    assert.deepEqual(rows, [], 'nothing minted or stored for a refused document');
  });

  it('design: a refused or declined proposal mints nothing, stores nothing, and creates no identity for the sender', async () => {
    const adapter = await make(false);
    await adapter.setClock(NOW);
    const identitiesBefore = (await adapter.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM identities'))!.n;
    await adapter.trigger('policy', { propose: 'decline' });
    const declined = JSON.parse((await adapter.send({ from: { kind: 'actor', vid: A.did }, bytes: propose(A, adapter.signer.did, req(3), R.did) })).replies[0]!);
    assert.equal(declined.payload.code, 'vrc/relationships/propose:declined');
    await adapter.trigger('policy', { propose: 'accept' });
    const bad = JSON.parse((await adapter.send({ from: { kind: 'actor', vid: A.did }, bytes: propose(A, adapter.signer.did, req(4), A.did) })).replies[0]!);
    assert.equal(bad.payload.code, 'malformedRequest');
    assert.deepEqual(await adapter.db.all('SELECT * FROM vrc_exchange_relationship_dids'), []);
    assert.equal((await adapter.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM identities'))!.n, identitiesBefore);
  });

  it('design: a held proposal is durable, has no remote identity until accepted, and survives a restart', async () => {
    const adapter = await make(false);
    await adapter.setClock(NOW);
    await adapter.trigger('policy', { propose: 'hold' });
    const reply = JSON.parse((await adapter.send({ from: { kind: 'actor', vid: A.did }, bytes: propose(A, adapter.signer.did, req(5), R.did) })).replies[0]!);
    assert.equal(reply.type, 'https://trusttasks.org/spec/trust-task-next-step/0.1');
    const held = (await exchangeDids.findByExchangeId(adapter.db, req(5)))!;
    assert.equal(held.state, 'held');
    assert.equal(held.remoteRelationshipDid, R.did);
    assert.equal(held.remoteIdentityUuid, null);
    assert.notEqual(held.localRelationshipDid, adapter.signer.did);
    await adapter.restart();
    const [row] = await adapter.propose.listHeld();
    assert.equal(row?.exchangeId, req(5));
    // The decision after the restart answers on the same thread and fills in the remote identity.
    const doc = (await adapter.propose.decide(req(5), 'accept')) as unknown as { threadId: string; payload: { accept: boolean; relationshipDid: string } };
    assert.equal(doc.threadId, req(5));
    assert.equal(doc.payload.relationshipDid, held.localRelationshipDid);
    const after = (await exchangeDids.findByExchangeId(adapter.db, req(5)))!;
    assert.equal(after.state, 'accepted');
    assert.notEqual(after.remoteIdentityUuid, null);
    await assert.rejects(() => adapter.propose.decide(req(5), 'decline'), /no held proposal/);
  });

  it('design: another sender cannot use or probe a thread that is not theirs', async () => {
    const adapter = await make(false);
    await adapter.setClock(NOW);
    await adapter.trigger('policy', { propose: 'hold' });
    await adapter.send({ from: { kind: 'actor', vid: A.did }, bytes: propose(A, adapter.signer.did, req(6), R.did) });
    const probe = JSON.parse((await adapter.send({ from: { kind: 'actor', vid: X.did }, bytes: propose(X, adapter.signer.did, req(7), R2.did, { threadId: req(6) }) })).replies[0]!);
    assert.equal(probe.payload.code, 'permissionDenied');
    assert.equal((await exchangeDids.findByExchangeId(adapter.db, req(6)))!.remoteConnectionDid, A.did);
  });

  it('design: the per-counterparty cap on pending proposals is an unavailable (retryable) answer, not a crash', async () => {
    const adapter = await make(false);
    await adapter.setClock(NOW);
    await adapter.trigger('policy', { propose: 'hold' });
    const codes: string[] = [];
    for (let i = 0; i < 7; i++) {
      const rel = actor(0x30 + i);
      const r = JSON.parse((await adapter.send({ from: { kind: 'actor', vid: A.did }, bytes: propose(A, adapter.signer.did, `urn:uuid:bbbbbbbb-bbbb-4bbb-8bbb-00000000000${i}`, rel.did) })).replies[0]!);
      codes.push(r.type.endsWith('next-step/0.1') ? 'hold' : r.payload.code);
    }
    assert.deepEqual(codes, ['hold', 'hold', 'hold', 'hold', 'hold', 'unavailable', 'unavailable']);
  });
});
