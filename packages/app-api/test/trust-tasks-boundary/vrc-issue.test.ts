// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P6b: the agent's `vrc/relationships/issue` handler. VRC-ISS-001..023 run by vector id
 * through the suite's own runner against the real pipeline, the durable duplicate record, the
 * transaction coordinator and the VRC receive participant; named design tests cover authorisation
 * (AUTHZ-001), the receipt read back from the table, what is and is not passed to the participant,
 * and the transaction outcome seam (2PC-001/002/006/007/008, design ids: the suite has no 2PC file).
 * Temp directories only.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { VrcBoundaryAdapter } from './vrc-adapter.ts';
import { SKIP, VECTORS_DIR, loadSuiteApi } from './suite-runner.ts';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { endExchange } from '@p2p-trust-stack/core/relationship/exchange-dids.js';
import { digestMultibaseOf } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/digest.js';
import { createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { settleAcceptedClaims } from '../../src/runtime/trust-tasks-boundary/settle.ts';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));
const make = async (attested: boolean, options: { issue?: boolean } = {}) => {
  const a = await new VrcBoundaryAdapter({ attested, ...options }).init();
  adapters.push(a);
  return a;
};

describe('VRC-ISS vectors against the agent boundary', { skip: SKIP, timeout: 300_000 }, () => {
  for (const tier of [1, 2] as const) {
    it(`tier ${tier}: every VRC-ISS vector that applies passes (none FAIL), CLARIFY ones observed pass`, async () => {
      const api = await loadSuiteApi();
      const suite = api.loadSuite(VECTORS_DIR);
      const run = await api.runSuite({ adapter: await make(tier === 2), suite, tier, today: '2026-11-13', fixtureRoot: VECTORS_DIR });
      const iss = run.results.filter((r) => r.group === 'VRC-ISS');
      assert.deepEqual(iss.filter((r) => r.status === 'FAIL').map((r) => `${r.id}: ${(r.failures ?? []).join('; ')}`), []);
      const status = new Map(iss.map((r) => [r.id, r]));
      const settled = ['001', '002', '004', '005', '006', '007', '008', '009', '010', '011', '012', '013', '014', '015', '016'];
      for (const n of settled) assert.equal(status.get(`VRC-ISS-${n}`)?.status, 'PASS', n);
      if (tier === 2) for (const n of ['017', '018', '019']) assert.equal(status.get(`VRC-ISS-${n}`)?.status, 'PASS', n);
      for (const n of ['003', '020', '021', '022', '023']) {
        assert.equal(status.get(`VRC-ISS-${n}`)?.status, 'CLARIFY');
        assert.match(status.get(`VRC-ISS-${n}`)?.reason ?? '', /observed: pass/, n);
      }
    });
  }
});

const NOW = '2026-11-12T10:00:00Z';
const ISSUE = 'https://trusttasks.org/spec/vrc/relationships/issue/0.1';
const PROPOSE = 'https://trusttasks.org/spec/vrc/relationships/propose/0.1';
const mk = (byte: number) => {
  const seed = new Uint8Array(32).fill(byte);
  const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
  return { did, signer: createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) }) };
};
const A = mk(0x0a), X = mk(0x0b), R = mk(0x0c), S = mk(0x0d);
const uid = (n: number) => `urn:uuid:cccccccc-cccc-4ccc-8ccc-${String(n).padStart(12, '0')}`;
const sign = (who: ReturnType<typeof mk>, doc: Record<string, unknown>) => JSON.stringify(signDocument(doc, who.signer, { created: Date.parse(NOW) }));
const vrcFrom = (issuer: ReturnType<typeof mk>, subject: string, extra: Record<string, unknown> = {}) =>
  signDocument(
    { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'VerifiableRelationshipCredential'], issuer: issuer.did, validFrom: NOW, issuerScope: 'pairwise', credentialSubject: { id: subject, ...extra } },
    issuer.signer,
    { created: Date.parse(NOW), purpose: 'assertionMethod' },
  );

/** Accept a proposal from A naming relationship DID R; returns the IUT's relationship DID. */
async function accepted(adapter: VrcBoundaryAdapter, thread = uid(1), rel = R): Promise<string> {
  await adapter.setClock(NOW);
  await adapter.trigger('policy', { propose: 'accept' });
  const reply = await adapter.send({ from: { kind: 'actor', vid: A.did }, bytes: sign(A, { id: thread, threadId: thread, type: PROPOSE, issuer: A.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { relationshipDid: rel.did } }) });
  return JSON.parse(reply.replies[0]!).payload.relationshipDid as string;
}
const issueDoc = (adapter: VrcBoundaryAdapter, id: string, thread: string, vrc: unknown, from = A) =>
  sign(from, { id, threadId: thread, type: ISSUE, issuer: from.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { vrc } });
const send = async (adapter: VrcBoundaryAdapter, bytes: string, from = A) => JSON.parse((await adapter.send({ from: { kind: 'actor', vid: from.did }, bytes })).replies[0]!);

describe('design: issue authorisation, storage and receipt', () => {
  it('AUTHZ-001 design: a verified third party on someone else\'s accepted thread gets the very answer an unknown thread gets', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    const vrc = vrcFrom(R, mine);
    const foreign = await send(adapter, issueDoc(adapter, uid(10), uid(1), vrc, X), X);
    const unknown = await send(adapter, issueDoc(adapter, uid(11), uid(99), vrc, X), X);
    assert.equal(foreign.payload.code, 'vrc/relationships/issue:notAccepted');
    const strip = (d: { payload: Record<string, unknown> }) => ({ ...d.payload, inResponseTo: undefined });
    assert.deepEqual(strip(foreign), strip(unknown), 'no existence oracle');
    assert.equal(await adapter.storedCount(), 0);
  });

  it('stores the credential against the exchange\'s root identities, creates no identity for a relationship DID, and receipts the stored form', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    const identitiesBefore = (await adapter.db.all<{ uuid: string }>('SELECT uuid FROM identities')).length;
    const vrc = vrcFrom(R, mine, { note: 'b' });
    const reply = await send(adapter, issueDoc(adapter, uid(12), uid(1), vrc));
    assert.equal(reply.type, `${ISSUE}#response`);
    const rows = await adapter.db.all<{ w3c_vc_json: string; issuer_identity_uuid: string; subject_identity_uuid: string; credential_digest: string }>("SELECT * FROM credentials WHERE vc_type = 'vrc'");
    assert.equal(rows.length, 1);
    const ex = (await exchangeDids.findByExchangeId(adapter.db, uid(1)))!;
    assert.equal(rows[0]!.issuer_identity_uuid, ex.remoteIdentityUuid);
    assert.equal(rows[0]!.subject_identity_uuid, ex.localIdentityUuid);
    assert.equal(reply.payload.vrcDigestMultibase, digestMultibaseOf(JSON.parse(rows[0]!.w3c_vc_json)));
    assert.equal(reply.payload.vrcDigestMultibase, digestMultibaseOf(vrc), 'canonical form: the same credential has one digest');
    assert.equal((await adapter.db.all('SELECT uuid FROM identities')).length, identitiesBefore, 'the remote issuerIdentity path is not used');
    assert.equal(ex.state, 'received');
  });

  it('alreadyIssued only within one exchange: a different credential on the same exchange is refused with exactly that code, a new exchange stores a new one', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    await send(adapter, issueDoc(adapter, uid(13), uid(1), vrcFrom(R, mine, { n: 1 })));
    const second = await send(adapter, issueDoc(adapter, uid(14), uid(1), vrcFrom(R, mine, { n: 2 })));
    assert.equal(second.payload.code, 'vrc/relationships/issue:alreadyIssued');
    assert.equal(await adapter.storedCount(), 1);
    const mine2 = await accepted(adapter, uid(2), S);
    const third = await send(adapter, issueDoc(adapter, uid(15), uid(2), vrcFrom(S, mine2, { n: 3 })));
    assert.equal(third.type, `${ISSUE}#response`);
    assert.equal(await adapter.storedCount(), 2);
  });

  it('refuses before storing: a relationship DID envelope, a wrong exchange state and a missing credential leave the table untouched', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    const bad = await send(adapter, issueDoc(adapter, uid(16), uid(1), 'not-an-object'));
    assert.equal(bad.payload.code, 'malformedRequest');
    await endExchange(adapter.db, uid(1));
    const ended = await send(adapter, issueDoc(adapter, uid(17), uid(1), vrcFrom(R, mine)));
    assert.equal(ended.payload.code, 'vrc/relationships/issue:notAccepted');
    assert.equal(await adapter.storedCount(), 0);
  });
});

describe('design: transaction outcome seam (2PC-001, 2PC-002, 2PC-006, 2PC-007, 2PC-008)', () => {
  it('2PC-001 design: a participant that votes no gives an error and no receipt; nothing is stored', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    const real = adapter.receive.prepare.bind(adapter.receive);
    // The exchange ends between the handler's check and the participant's own check (a race).
    adapter.receive.prepare = async (txId, ops) => {
      await endExchange(adapter.db, uid(1));
      return real(txId, ops);
    };
    const reply = await send(adapter, issueDoc(adapter, uid(20), uid(1), vrcFrom(R, mine)));
    assert.equal(reply.type, 'https://trusttasks.org/spec/trust-task-error/0.6');
    assert.notEqual(reply.type, `${ISSUE}#response`);
    assert.equal(await adapter.storedCount(), 0);
  });

  it('2PC-002 design: the abort reason reaches the wire from the closed vocabulary, with the standard retryable flag', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    const real = adapter.receive.prepare.bind(adapter.receive);
    adapter.receive.prepare = async (txId, ops) => {
      await endExchange(adapter.db, uid(1));
      return real(txId, ops);
    };
    const reply = await send(adapter, issueDoc(adapter, uid(21), uid(1), vrcFrom(R, mine)));
    assert.equal(reply.payload.code, 'vrc/relationships/issue:notAccepted');
    assert.equal(reply.payload.retryable, false);
    assert.equal(reply.payload.details.reason, 'notAccepted');
    assert.deepEqual(Object.keys(reply.payload.details), ['reason']);
  });

  it('2PC-006 design: a claim whose transaction committed is settled from the coordinator outcome', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    await send(adapter, issueDoc(adapter, uid(22), uid(1), vrcFrom(R, mine)));
    // A crash after the commit but before the response was recorded: the claim is left open with its transaction.
    const [txRow] = await adapter.txDb.all<{ tx_id: string }>('SELECT DISTINCT tx_id FROM tx_log LIMIT 1');
    assert.ok(txRow);
    await adapter.db.run("UPDATE trust_task_accepted SET state = 'claimed', response = NULL, tx_id = ? WHERE id = ?", txRow.tx_id, uid(22));
    assert.deepEqual(await settleAcceptedClaims(adapter.guard, adapter.txManager), { completed: 1, released: 0, pending: 0 });
    assert.equal((await adapter.guard.find(uid(22)))!.state, 'completed');
  });

  it('2PC-007 design: an unresolved transaction is neither guessed committed nor released; a resend is 202', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    const bytes = issueDoc(adapter, uid(23), uid(1), vrcFrom(R, mine));
    await send(adapter, bytes);
    await adapter.db.run("UPDATE trust_task_accepted SET state = 'claimed', response = NULL, tx_id = ? WHERE id = ?", 'tx-never-seen', uid(23));
    assert.deepEqual(await settleAcceptedClaims(adapter.guard, adapter.txManager), { completed: 0, released: 0, pending: 1 });
    const again = await adapter.pipeline.process({ raw: bytes, sender: A.did });
    assert.equal(again.status, 202);
    assert.equal(again.kind, 'inFlight');
  });

  it('2PC-008 design: an unreadable duplicate record fails closed with unavailable, runs nothing and stores nothing', async () => {
    const adapter = await make(false);
    const mine = await accepted(adapter);
    const unreadable = async (): Promise<never> => {
      throw new Error('record unreadable');
    };
    adapter.guard.claim = unreadable;
    adapter.guard.claimFor = unreadable;
    const result = await adapter.pipeline.process({ raw: issueDoc(adapter, uid(24), uid(1), vrcFrom(R, mine)), sender: A.did });
    assert.equal(result.status, 503);
    assert.equal((result.document as { payload: { code: string; retryable: boolean } }).payload.code, 'unavailable');
    assert.equal(await adapter.storedCount(), 0);
  });
});
