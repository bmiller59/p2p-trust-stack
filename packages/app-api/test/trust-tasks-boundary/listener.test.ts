// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P6c: the opt-in agent listener. Off unless switched on and given a port, never on a
 * forbidden (UI) port, credentials ignored (proof-only), raw bounded body, the pipeline's status
 * mapping on the wire, and the full wiring (`startAgentBoundary`) answering a real HTTP request.
 * Loopback only, ephemeral ports, temp directories only.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { VrcBoundaryAdapter } from './vrc-adapter.ts';
import { createEd25519BoundarySigner, setBoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { LISTENER_PATH, resolveListenerConfig, startBoundaryListener } from '../../src/runtime/trust-tasks-boundary/listener.ts';
import * as witnessShares from '@p2p-trust-stack/core/db/repositories/witness-shares-repo.js';
import { A, R, WS, bundle, clock, shareDoc, sign, text, uid, useClock } from './witness-bundle.ts';
import { startAgentBoundary } from '../../src/runtime/trust-tasks-boundary/agent-boundary.ts';

const PROPOSE = 'https://trusttasks.org/spec/vrc/relationships/propose/0.1';
const cleanup: Array<() => void | Promise<void>> = [];
after(async () => {
  setBoundarySigner(undefined);
  for (const c of cleanup.reverse()) await c();
});

const peerSeed = new Uint8Array(32).fill(0x0a);
const peerDid = didKeyFromEd25519(ed25519.getPublicKey(peerSeed));
const peerSigner = createEd25519BoundarySigner({ did: peerDid, secretKey: peerSeed, fragment: peerDid.slice('did:key:'.length) });
const relDid = didKeyFromEd25519(ed25519.getPublicKey(new Uint8Array(32).fill(0x0c)));
const nowIso = () => new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z');
const proposeBytes = (iut: string, id: string, sign = true, threadId = id) => {
  const doc = { id, threadId, type: PROPOSE, issuer: peerDid, recipient: iut, issuedAt: nowIso(), payload: { relationshipDid: relDid } };
  return JSON.stringify(sign ? signDocument(doc, peerSigner, { created: Date.now() }) : doc);
};
const post = (port: number, body: string, headers: Record<string, string> = { 'content-type': 'application/json' }, path = LISTENER_PATH) =>
  fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', body, headers });

describe('listener configuration is opt-in', () => {
  it('is off by default and with the switch off, whatever else is set', () => {
    assert.equal(resolveListenerConfig({}), null);
    assert.equal(resolveListenerConfig({ TRUST_TASKS_LISTENER_PORT: '4000' }), null);
    assert.equal(resolveListenerConfig({ TRUST_TASKS_LISTENER: '0', TRUST_TASKS_LISTENER_PORT: '4000' }), null);
    assert.equal(resolveListenerConfig({ TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: '4000' }, { enabled: false }), null);
  });
  it('needs an explicit valid port (no default), refuses a forbidden one, and defaults to loopback, attested, hold', () => {
    assert.throws(() => resolveListenerConfig({ TRUST_TASKS_LISTENER: '1' }), /no valid port/);
    assert.throws(() => resolveListenerConfig({ TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: 'abc' }), /no valid port/);
    assert.throws(() => resolveListenerConfig({ TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: '3000' }, {}, [3000]), /reserved for the UI/);
    assert.deepEqual(resolveListenerConfig({ TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: '4000' }), { host: '127.0.0.1', port: 4000, tier: 2, proposePolicy: 'hold' });
    assert.equal(resolveListenerConfig({ TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: '4000', TRUST_TASKS_TIER: '1', TRUST_TASKS_PROPOSE_POLICY: 'decline' })!.proposePolicy, 'decline');
  });
});

describe('the HTTP carrier', () => {
  it('serves POST /trust-tasks over the pipeline, ignores cookies and bearer tokens, and bounds the body', async () => {
    const adapter = await new VrcBoundaryAdapter({ attested: false }).init();
    cleanup.push(() => adapter.dispose());
    const listener = await startBoundaryListener({ host: '127.0.0.1', port: 0, process: (i) => adapter.pipeline.process(i), maxBodyBytes: 4096 });
    cleanup.push(() => listener.close());
    const iut = adapter.signer.did;

    // A signed proposal is held: 200 with a next-step.
    const ok = await post(listener.port, proposeBytes(iut, 'urn:uuid:eeeeeeee-eeee-4eee-8eee-000000000001'));
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('content-type'), 'application/json');
    assert.equal(((await ok.json()) as { type: string }).type, 'https://trusttasks.org/spec/trust-task-next-step/0.1');

    // A cookie or bearer token does not authenticate anyone: an unsigned document is nobody's.
    const withCreds = await post(listener.port, proposeBytes(iut, 'urn:uuid:eeeeeeee-eeee-4eee-8eee-000000000002', false), {
      'content-type': 'application/json',
      cookie: 'session=abc',
      authorization: 'Bearer abc',
    });
    assert.equal(withCreds.status, 403);
    assert.equal(((await withCreds.json()) as { payload: { code: string } }).payload.code, 'permissionDenied');

    assert.equal((await fetch(`http://127.0.0.1:${listener.port}${LISTENER_PATH}`)).status, 405);
    assert.equal((await post(listener.port, '{}', { 'content-type': 'application/json' }, '/api/anything')).status, 404);
    assert.equal((await post(listener.port, '{}', { 'content-type': 'text/plain' })).status, 415);
    assert.equal((await post(listener.port, 'x'.repeat(5000))).status, 413);
    const garbage = await post(listener.port, '{not json');
    assert.equal(garbage.status, 400);
    assert.deepEqual(Object.keys(await garbage.json()).sort(), ['code', 'message', 'retryable']);
  });
});

describe('startAgentBoundary wiring', () => {
  it('answers a real request over loopback, signs the reply as the connection DID, holds, and lets the human decide', async () => {
    const adapter = await new VrcBoundaryAdapter({ attested: true, seed: 0x61 }).init();
    cleanup.push(() => adapter.dispose());
    setBoundarySigner(adapter.signer);
    const boundary = await startAgentBoundary({
      ds: adapter.db,
      did: adapter.signer.did,
      passphrase: 'test-passphrase-not-a-default',
      txManager: adapter.txManager,
      receive: adapter.receive,
      witnessShare: adapter.witnessShare,
      verifier: adapter.verifier,
      config: { host: '127.0.0.1', port: 0, tier: 2, proposePolicy: 'hold' },
    });
    cleanup.push(() => boundary.stop());
    const id = 'urn:uuid:eeeeeeee-eeee-4eee-8eee-000000000010';
    const res = await post(boundary.listener.port, proposeBytes(adapter.signer.did, id));
    assert.equal(res.status, 200);
    const reply = (await res.json()) as Record<string, unknown>;
    assert.equal(reply.type, 'https://trusttasks.org/spec/trust-task-next-step/0.1');
    assert.equal(reply.issuer, adapter.signer.did);
    assert.equal((await adapter.verifier.verify(reply, { nowMs: Date.now() })).valid, true, 'the reply is signed');
    assert.equal((await boundary.propose.listHeld()).map((r) => r.exchangeId).join(), id);

    // Unsigned at Tier 2: proofRequired, nothing recorded as a held proposal.
    const unsigned = await post(boundary.listener.port, proposeBytes(adapter.signer.did, 'urn:uuid:eeeeeeee-eeee-4eee-8eee-000000000011', false));
    assert.equal(((await unsigned.json()) as { payload: { code: string } }).payload.code, 'proofRequired');
    assert.equal((await boundary.propose.listHeld()).length, 1);

    await boundary.propose.decide(id, 'accept');
    assert.equal((await exchangeDids.findByExchangeId(adapter.db, id))!.state, 'accepted');
    // The proposer resubmits (fresh id, same thread) and now gets the acceptance.
    const again = await post(boundary.listener.port, proposeBytes(adapter.signer.did, 'urn:uuid:eeeeeeee-eeee-4eee-8eee-000000000012', true, id));
    assert.equal(((await again.clone().json()) as { type: string }).type, `${PROPOSE}#response`);
    assert.equal(again.status, 200);
  });

  it('serves the witness share over loopback: stored, receipted, and signed by the connection DID (conformance P7)', async () => {
    const adapter = await new VrcBoundaryAdapter({ attested: true, seed: 0x63, witness: true }).init();
    cleanup.push(() => adapter.dispose());
    setBoundarySigner(adapter.signer);
    useClock(nowIso());
    const boundary = await startAgentBoundary({
      ds: adapter.db,
      did: adapter.signer.did,
      passphrase: 'test-passphrase-not-a-default',
      txManager: adapter.txManager,
      receive: adapter.receive,
      witnessShare: adapter.witnessShare,
      verifier: adapter.verifier,
      config: { host: '127.0.0.1', port: 0, tier: 2, proposePolicy: 'hold' },
    });
    cleanup.push(() => boundary.stop());
    const thread = uid(1);
    const propose = sign(A, { id: thread, threadId: thread, type: PROPOSE, issuer: A.did, recipient: adapter.signer.did, issuedAt: clock.iso, payload: { relationshipDid: R.did } });
    await post(boundary.listener.port, text(propose));
    await boundary.propose.decide(thread, 'accept');
    const resubmit = sign(A, { id: uid(2), threadId: thread, type: PROPOSE, issuer: A.did, recipient: adapter.signer.did, issuedAt: clock.iso, payload: { relationshipDid: R.did } });
    const accepted = (await (await post(boundary.listener.port, text(resubmit))).json()) as { payload: { relationshipDid: string } };
    const res = await post(boundary.listener.port, text(shareDoc(adapter, uid(3), thread, bundle(accepted.payload.relationshipDid))));
    assert.equal(res.status, 200);
    const receipt = (await res.json()) as { type: string; issuer: string; payload: { vwcDigestMultibase: string } };
    assert.equal(receipt.type, `${WS}#response`);
    assert.equal(receipt.issuer, adapter.signer.did);
    assert.equal((await adapter.verifier.verify(receipt, { nowMs: Date.now() })).valid, true, 'the receipt is signed');
    assert.equal((await witnessShares.findByExchange(adapter.db, thread))!.id, receipt.payload.vwcDigestMultibase);
    useClock('2026-11-12T10:00:00Z');
  });

  it('refuses to start without a boundary signer for the connection DID (replies could not be signed)', async () => {
    const adapter = await new VrcBoundaryAdapter({ attested: true, seed: 0x62 }).init();
    cleanup.push(() => adapter.dispose());
    setBoundarySigner(undefined);
    await assert.rejects(
      () => startAgentBoundary({ ds: adapter.db, did: adapter.signer.did, passphrase: 'x', txManager: adapter.txManager, receive: adapter.receive, witnessShare: adapter.witnessShare, verifier: adapter.verifier, config: { host: '127.0.0.1', port: 0, tier: 2, proposePolicy: 'hold' } }),
      /no boundary signer/,
    );
  });
});
