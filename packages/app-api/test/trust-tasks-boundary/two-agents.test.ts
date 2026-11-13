// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P6: an in-process two-agent exchange. Agent A proposes, B holds and answers with a
 * next-step, B's human accepts, A resubmits and learns the acceptance, A issues its VRC and gets a
 * receipt, then B issues its own VRC back. Both sides run the real pipeline (Tier 2: every document
 * signed and proof-authenticated, no transport sender), the real mapping table, per-exchange
 * did:peer:4 relationship DIDs and real VRC mints. Temp directories only.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { VrcBoundaryAdapter, PASSPHRASE } from './vrc-adapter.ts';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { mintExchangeRelationshipDid } from '@p2p-trust-stack/core/relationship/exchange-dids.js';
import { findExchangeVrc } from '@p2p-trust-stack/core/relationship/exchange-vrc.js';
import { mintExchangeVrc } from '@p2p-trust-stack/core/relationship/vrc-mint.js';
import { digestMultibaseOf } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/digest.js';
import { signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { ensureRemoteIdentity } from '../../src/runtime/trust-tasks-boundary/vrc-propose.ts';

const PROPOSE = 'https://trusttasks.org/spec/vrc/relationships/propose/0.1';
const ISSUE = 'https://trusttasks.org/spec/vrc/relationships/issue/0.1';
const NEXT_STEP = 'https://trusttasks.org/spec/trust-task-next-step/0.1';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));

const nowIso = () => new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z');
let n = 0;
const uid = () => `urn:uuid:dddddddd-dddd-4ddd-8ddd-${String(n++).padStart(12, '0')}`;

class Peer {
  readonly agent: VrcBoundaryAdapter;
  constructor(agent: VrcBoundaryAdapter) {
    this.agent = agent;
  }
  get did() {
    return this.agent.signer.did;
  }
  /** Build, sign and deliver a document to `to` (proof-only: the carrier authenticates nobody). */
  async deliver(to: Peer, type: string, payload: Record<string, unknown>, ids: { id?: string; threadId: string }) {
    const doc = { id: ids.id ?? uid(), threadId: ids.threadId, type, issuer: this.did, recipient: to.did, issuedAt: nowIso(), payload };
    const raw = JSON.stringify(signDocument(doc, this.agent.signer, { created: Date.now() }));
    const result = await to.agent.pipeline.process({ raw, sender: undefined });
    assert.ok(result.document !== undefined, `no reply (status ${result.status})`);
    const reply = result.document as Record<string, unknown>;
    // Every reply verifies under the recipient's connection DID, as the issuer.
    const verdict = await this.agent.verifier.verify(reply, { nowMs: Date.now() });
    assert.equal(verdict.valid, true, `reply is not validly signed: ${JSON.stringify(verdict)}`);
    assert.equal(verdict.signer, to.did);
    assert.equal(reply.issuer, to.did);
    assert.equal(reply.recipient, this.did);
    return { reply, doc };
  }
}

describe('two agents, in process', () => {
  it('propose with a hold, accept, issue both ways: distinct did:peer:4 relationship DIDs, stored credentials, receipts over what is stored', async () => {
    const A = new Peer(await new VrcBoundaryAdapter({ attested: true, seed: 0x51 }).init());
    const B = new Peer(await new VrcBoundaryAdapter({ attested: true, seed: 0x52 }).init());
    adapters.push(A.agent, B.agent);
    const thread = uid();

    // A: a relationship DID for this exchange, recorded before it is sent.
    const aUuid = (await identitiesRepo.findByRealDid(A.agent.db, A.did))!.uuid;
    const bInA = await ensureRemoteIdentity(A.agent.db, B.did);
    const aRow = await mintExchangeRelationshipDid(A.agent.db, { exchangeId: thread, role: 'proposer', localIdentityUuid: aUuid, localConnectionDid: A.did, remoteConnectionDid: B.did, remoteIdentityUuid: bInA, passphrase: PASSPHRASE });
    assert.match(aRow.localRelationshipDid, /^did:peer:4/);

    // B's human has not decided: the proposal is held and A is told to resubmit.
    await B.agent.trigger('policy', { propose: 'hold' });
    const held = await A.deliver(B, PROPOSE, { relationshipDid: aRow.localRelationshipDid }, { id: thread, threadId: thread });
    assert.equal(held.reply.type, NEXT_STEP);
    assert.equal((held.reply.payload as { continuation: string }).continuation, 'resubmit');
    assert.equal((held.reply.payload as { inResponseTo: { id: string } }).inResponseTo.id, thread);
    assert.equal(held.reply.threadId, thread);

    // The human accepts; A's resubmission (fresh id, same thread) gets the acceptance.
    await B.agent.propose.decide(thread, 'accept');
    const accepted = await A.deliver(B, PROPOSE, { relationshipDid: aRow.localRelationshipDid }, { threadId: thread });
    assert.equal(accepted.reply.type, `${PROPOSE}#response`);
    const bRel = (accepted.reply.payload as { relationshipDid: string }).relationshipDid;
    assert.match(bRel, /^did:peer:4/);
    assert.notEqual(bRel, aRow.localRelationshipDid);
    assert.notEqual(bRel, B.did);
    await exchangeDids.setRemoteRelationshipDid(A.agent.db, thread, bRel);
    await exchangeDids.setState(A.agent.db, thread, 'accepted');

    // A issues its VRC to B (relationship DID to relationship DID; the envelope is connection DID to connection DID).
    const aVrc = await mintExchangeVrc({ dataSource: A.agent.db, exchangeId: thread, passphrase: PASSPHRASE });
    assert.ok(aVrc.success);
    const aVc = JSON.parse((aVrc as { w3cVcJson: string }).w3cVcJson);
    const receipt = await A.deliver(B, ISSUE, { vrc: aVc }, { threadId: thread });
    assert.equal(receipt.reply.type, `${ISSUE}#response`);
    assert.equal((receipt.reply.payload as { vrcDigestMultibase: string }).vrcDigestMultibase, digestMultibaseOf(aVc));
    assert.equal(aVc.issuer, aRow.localRelationshipDid);
    assert.equal(aVc.credentialSubject.id, bRel);
    assert.equal(await B.agent.storedCount(), 1);

    // B issues its own VRC back on the same exchange; A (the proposer) receives it.
    const bVrc = await mintExchangeVrc({ dataSource: B.agent.db, exchangeId: thread, passphrase: PASSPHRASE });
    assert.ok(bVrc.success, JSON.stringify(bVrc));
    const bVc = JSON.parse((bVrc as { w3cVcJson: string }).w3cVcJson);
    const back = await B.deliver(A, ISSUE, { vrc: bVc }, { threadId: thread });
    assert.equal(back.reply.type, `${ISSUE}#response`);
    assert.equal((back.reply.payload as { vrcDigestMultibase: string }).vrcDigestMultibase, digestMultibaseOf(bVc));
    // A's table holds the credential it minted itself and the one it received.
    assert.equal(await A.agent.storedCount(), 2);
    const aReceived = (await findExchangeVrc(A.agent.db, (await exchangeDids.findByExchangeId(A.agent.db, thread))!, 'received'))!;
    assert.equal(digestMultibaseOf(JSON.parse(aReceived.w3cVcJson)), digestMultibaseOf(bVc));

    // Neither connection DID is in either credential; nothing links the two relationship DIDs to them.
    for (const vc of [aVc, bVc]) {
      const text = JSON.stringify(vc);
      assert.equal(text.includes(A.did), false);
      assert.equal(text.includes(B.did), false);
    }

    // A second exchange between the same parties is a new exchange: fresh DIDs on both sides, a second credential.
    const t2 = uid();
    const aRow2 = await mintExchangeRelationshipDid(A.agent.db, { exchangeId: t2, role: 'proposer', localIdentityUuid: aUuid, localConnectionDid: A.did, remoteConnectionDid: B.did, remoteIdentityUuid: bInA, passphrase: PASSPHRASE });
    await B.agent.trigger('policy', { propose: 'accept' });
    const acc2 = await A.deliver(B, PROPOSE, { relationshipDid: aRow2.localRelationshipDid }, { id: t2, threadId: t2 });
    const bRel2 = (acc2.reply.payload as { relationshipDid: string }).relationshipDid;
    assert.notEqual(aRow2.localRelationshipDid, aRow.localRelationshipDid);
    assert.notEqual(bRel2, bRel);
    await exchangeDids.setRemoteRelationshipDid(A.agent.db, t2, bRel2);
    await exchangeDids.setState(A.agent.db, t2, 'accepted');
    const aVrc2 = await mintExchangeVrc({ dataSource: A.agent.db, exchangeId: t2, passphrase: PASSPHRASE });
    assert.ok(aVrc2.success);
    const receipt2 = await A.deliver(B, ISSUE, { vrc: JSON.parse((aVrc2 as { w3cVcJson: string }).w3cVcJson) }, { threadId: t2 });
    assert.equal(receipt2.reply.type, `${ISSUE}#response`);
    const bSecond = await findExchangeVrc(B.agent.db, (await exchangeDids.findByExchangeId(B.agent.db, t2))!, 'received');
    assert.notEqual(bSecond, null);
    assert.equal(await B.agent.storedCount(), 3, 'its own mint plus two received');
  });

  it('a delivery for an exchange B never accepted is refused even though A is a known, properly signed sender', async () => {
    const A = new Peer(await new VrcBoundaryAdapter({ attested: true, seed: 0x53 }).init());
    const B = new Peer(await new VrcBoundaryAdapter({ attested: true, seed: 0x54 }).init());
    adapters.push(A.agent, B.agent);
    const out = await A.deliver(B, ISSUE, { vrc: { issuer: 'did:peer:4zA', credentialSubject: { id: 'did:peer:4zB' } } }, { threadId: uid() });
    assert.equal((out.reply.payload as { code: string }).code, 'vrc/relationships/issue:notAccepted');
    assert.equal(await B.agent.storedCount(), 0);
  });
});
