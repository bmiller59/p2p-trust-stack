// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P7: the agent's suite-local `vrc/relationships/witness-share/0.1` handler. The suite has
 * no WSH vector files yet ("Not built"), so the vectors are driven by id from the profile's outline
 * (docs/10-witness-share-profile.md section 11, WSH-001..021) against the REAL pipeline, the durable
 * duplicate record, the transaction coordinator, the witness share participant and the new tables;
 * the outline as JSON is in the P7 report. Design-named tests cover what the profile leaves open.
 * Temp directories only.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, describe, it } from 'node:test';
import { base58btc } from 'multiformats/bases/base58';
import { VrcBoundaryAdapter } from './vrc-adapter.ts';
import * as witnessShares from '@p2p-trust-stack/core/db/repositories/witness-shares-repo.js';
import { digestMultibaseOf, taskDigestMultibase } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/digest.js';
import { WITNESS_SHARE_DOMAIN } from '@p2p-trust-stack/core/services/trust-tasks/boundary/witness-share-spec.js';
import { A, ERROR_TYPE, PROPOSE, R, S, SESSION, W, WS, WS_URN, X, Y, accepted, bundle, clock, shareDoc, sign, text, uid } from './witness-bundle.ts';
import type { Party } from './witness-bundle.ts';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));
const NOW = clock.iso;
const created = clock.ms;
const make = async (attested = false) => {
  const a = await new VrcBoundaryAdapter({ attested, witness: true }).init();
  adapters.push(a);
  return a;
};

const send = async (adapter: VrcBoundaryAdapter, doc: unknown, from: Party = A) => JSON.parse((await adapter.send({ from: { kind: 'actor', vid: from.did }, bytes: typeof doc === 'string' ? doc : text(doc) })).replies[0]!);
const NOT_ACCEPTED = 'vrc/relationships/witness-share:notAccepted';

/** A refused share: the extended code, and nothing stored. */
async function assertRefused(adapter: VrcBoundaryAdapter, reply: { type: string; payload: { code?: string } }, code = NOT_ACCEPTED) {
  assert.equal(reply.payload.code, code);
  assert.equal(await adapter.witnessCount(), 0, 'nothing stored');
}

describe('WSH vectors against the agent boundary (profile section 11, tier 1)', () => {
  it('WSH-001 happy path: stored, receipted over the stored credential, evidence kept verbatim', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const reply = await send(adapter, shareDoc(adapter, uid(10), uid(1), b));
    assert.equal(reply.type, `${WS}#response`);
    assert.equal(await adapter.witnessCount(), 1);
    const row = (await witnessShares.findByExchange(adapter.db, uid(1)))!;
    assert.equal(row.kind, 'vwc');
    assert.equal(row.witnessVerified, true);
    assert.equal(row.subjectDid, R.did);
    assert.equal(row.witnessDid, W.did);
    assert.equal(reply.payload.vwcDigestMultibase, digestMultibaseOf(JSON.parse(row.w3cVcJson)), 'receipt = digest of the credential as stored, read back');
    assert.equal(reply.payload.vwcDigestMultibase, digestMultibaseOf(b.vwc));
    assert.equal(row.id, reply.payload.vwcDigestMultibase);
    const ev = (await witnessShares.findEvidence(adapter.db, row.id))!;
    assert.equal(ev.initiatingJson, text(b.initiating), 'initiating stored verbatim');
    assert.equal(ev.terminalJson, text(b.terminal), 'terminal stored verbatim');
    assert.equal(ev.presentationJson, text(b.presentation));
    // The stored initiating document still reproduces the credential's citation: the pairing can be re-shown later.
    assert.equal(taskDigestMultibase(JSON.parse(ev.initiatingJson)), (b.vwc as { taskDigestMultibase: string }).taskDigestMultibase);
    assert.equal((await adapter.db.all("SELECT uuid FROM credentials WHERE vc_type = 'vrc'")).length, 0, 'no VRC row is created by a share');
  });

  it('WSH-002 presentation challenge differs from the share threadId (replay across exchanges)', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { challenge: uid(77) }))));
  });

  it('WSH-003 presentation domain is not vrc:witness-share', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { domain: 'other:domain' }))));
  });

  it('WSH-004 credential subject is not the sender relationship DID (own VWC bounced back)', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { subject: mine }))));
  });

  it('WSH-005 parties do not name both relationship DIDs (credential subject; and the cited session document)', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { parties: [R.did] }))));
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(11), uid(1), bundle(mine, { parties: [R.did, S.did] }))));
    // newer credential shape: no parties on the subject, they are in the session document: a session naming only one party fails
    const lone = bundle(mine);
    const initiating = sign(R, { ...(lone.initiating as Record<string, unknown>), payload: { parties: [R.did] } });
    const vwc = sign(W, { ...(lone.vwc as Record<string, unknown>), taskDigestMultibase: taskDigestMultibase(initiating) }, { purpose: 'assertionMethod' });
    const terminal = sign(W, { ...(lone.terminal as Record<string, unknown>), payload: { vwc } }, { purpose: 'assertionMethod' });
    const presentation = sign(R, { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiablePresentation'], holder: R.did, verifiableCredential: [vwc] }, { challenge: uid(1), domain: WITNESS_SHARE_DOMAIN, allowIssuerMismatch: true });
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(12), uid(1), { vwc, presentation, initiating, terminal })));
  });

  it('WSH-006 foreign terminal: another thread; and a terminal that is an error response', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { terminal: (t) => ({ ...t, threadId: uid(88) }) }))));
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(11), uid(1), bundle(mine, { terminal: (t) => ({ ...t, type: ERROR_TYPE }) }))));
  });

  it('WSH-007 task digest does not reproduce over the initiating document (initiating altered; citation altered)', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { alterInitiating: (d) => { (d.payload as { note?: string }).note = 'x'; } }))));
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(11), uid(1), bundle(mine, { citation: (c) => ({ ...c, taskDigestMultibase: digestMultibaseOf({ other: 1 }) }) }))));
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(12), uid(1), bundle(mine, { citation: (c) => ({ ...c, taskContext: uid(404) }) }))));
  });

  it('WSH-008 terminal signed by a non-recipient: a valid proof by the terminal issuer who is not the initiating recipient', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    // Y issues AND signs the terminal; the signature is valid, but Y is not the initiating document's recipient (W).
    const b = bundle(mine, { terminal: (t) => ({ ...t, issuer: Y.did }), terminalSigner: Y });
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), b)));
  });

  it('WSH-009 wrong terminal type: a non-error response of a type the initiating specification does not declare', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { terminal: (t) => ({ ...t, type: 'https://trusttasks.org/spec/vrc/relationships/issue/0.1#response' }) }))));
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(11), uid(1), bundle(mine, { terminal: (t) => ({ ...t, type: SESSION + '#response' }) }))));
  });

  it('WSH-010 stripped proof: terminal with its proof removed', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { terminalProof: false }))));
  });

  it('WSH-011 decoded-bytes compare: the same digest in another multibase encoding (u for z) is accepted', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const reply = await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { citation: (c) => ({ ...c, taskDigestMultibase: `u${Buffer.from(base58btc.decode(c.taskDigestMultibase)).toString('base64url')}` }) })));
    assert.equal(reply.type, `${WS}#response`);
    assert.equal(await adapter.witnessCount(), 1);
  });

  it('WSH-012 unknown multihash: a digest of an algorithm the verifier does not implement does not evidence completion', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const sha512 = (c: { taskContext: string }) => {
      const raw = new Uint8Array(66);
      raw.set([0x13, 64]);
      raw.set(createHash('sha512').update(c.taskContext).digest(), 2);
      return base58btc.encode(raw);
    };
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { citation: (c) => ({ ...c, taskDigestMultibase: sha512(c) }) }))));
  });

  it('WSH-013 unsolicited share (no accepted exchange with the sender): notAccepted, not proofInvalid', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    // A well-formed, correctly signed share from a peer that has no exchange, and one on an unknown thread.
    const stranger = sign(X, { id: uid(10), threadId: uid(1), type: WS, issuer: X.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { presentation: b.presentation, outcomeEvidence: { initiating: b.initiating, terminal: b.terminal } } });
    const r1 = await send(adapter, stranger, X);
    await assertRefused(adapter, r1);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(11), uid(99), b)));
    // a peer whose exchange is only held (not accepted) is also unsolicited
    await adapter.trigger('policy', { propose: 'hold' });
    await send(adapter, sign(X, { id: uid(12), threadId: uid(3), type: PROPOSE, issuer: X.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { relationshipDid: S.did } }), X);
    const held = bundle(mine, { sharer: S, thread: uid(3) });
    const r3 = await send(adapter, sign(X, { id: uid(13), threadId: uid(3), type: WS, issuer: X.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { presentation: held.presentation, outcomeEvidence: { initiating: held.initiating, terminal: held.terminal } } }), X);
    await assertRefused(adapter, r3);
  });

  it('WSH-014 request proof missing: proofRequired', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const doc = shareDoc(adapter, uid(10), uid(1), bundle(mine)) as Record<string, unknown>;
    delete doc.proof;
    await assertRefused(adapter, await send(adapter, doc), 'proofRequired');
  });

  it('WSH-015 request proof signed by a key that is not the sender\'s: proofInvalid / identityMismatch, nothing stored', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const doc = sign(X, { id: uid(10), threadId: uid(1), type: WS, issuer: A.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { presentation: bundle(mine).presentation, outcomeEvidence: { initiating: bundle(mine).initiating, terminal: bundle(mine).terminal } } }, { allowIssuerMismatch: true });
    const reply = await send(adapter, doc, A);
    assert.ok(['proofInvalid', 'identityMismatch'].includes(reply.payload.code), reply.payload.code);
    assert.equal(await adapter.witnessCount(), 0);
  });

  it('WSH-016 unknown payload member, or a missing presentation or evidence member: malformedRequest', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const base = { id: uid(10), threadId: uid(1), type: WS, issuer: A.did, recipient: adapter.signer.did, issuedAt: NOW };
    const cases: Array<Record<string, unknown>> = [
      { presentation: b.presentation, outcomeEvidence: { initiating: b.initiating, terminal: b.terminal }, surprise: 1 },
      { outcomeEvidence: { initiating: b.initiating, terminal: b.terminal } },
      { presentation: b.presentation, outcomeEvidence: { terminal: b.terminal } },
      { presentation: b.presentation, outcomeEvidence: { initiating: b.initiating } },
      { presentation: b.presentation, outcomeEvidence: { initiating: b.initiating, terminal: b.terminal, extra: 1 } },
      { presentation: 'text', outcomeEvidence: { initiating: b.initiating, terminal: b.terminal } },
    ];
    for (const [i, payload] of cases.entries()) {
      const reply = await send(adapter, sign(A, { ...base, id: uid(20 + i), payload }));
      assert.equal(reply.payload.code, 'malformedRequest', `case ${i}`);
    }
    assert.equal(await adapter.witnessCount(), 0);
  });

  it('WSH-017 redelivery of an identical share: one stored credential, a receipt each time with the same digest', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const first = await send(adapter, shareDoc(adapter, uid(10), uid(1), b));
    // a fresh document id carrying the same credential
    const second = await send(adapter, shareDoc(adapter, uid(11), uid(1), b));
    assert.equal(second.type, `${WS}#response`);
    assert.equal(second.payload.vwcDigestMultibase, first.payload.vwcDigestMultibase);
    // the very same document again: the duplicate record answers (the prior response or an absorbed 204)
    const again = await adapter.send({ from: { kind: 'actor', vid: A.did }, bytes: text(shareDoc(adapter, uid(10), uid(1), b)) });
    if (again.replies.length > 0) assert.equal(JSON.parse(again.replies[0]!).payload.vwcDigestMultibase, first.payload.vwcDigestMultibase);
    assert.equal(await adapter.witnessCount(), 1);
    assert.equal(Number((await adapter.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM witness_share_evidence'))!.n), 1);
  });

  it('WSH-018 same id, changed content: idConflict, and the first stays as it was', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    await send(adapter, shareDoc(adapter, uid(10), uid(1), b));
    const changed = sign(A, { id: uid(10), threadId: uid(1), type: WS, issuer: A.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { presentation: b.presentation, outcomeEvidence: { initiating: b.initiating, terminal: b.terminal }, ext: { 'org.example.note': { n: 1 } } } });
    const reply = await send(adapter, changed);
    assert.equal(reply.payload.code, 'idConflict');
    assert.equal(await adapter.witnessCount(), 1);
  });

  it('WSH-019 (CLARIFY O7) no order is enforced: accepted before, and after, the counterparty\'s issue', async () => {
    const adapter = await make();
    // exchange 1: share first, no issue received at all
    const mine1 = await accepted(adapter, uid(1), R);
    assert.equal((await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine1)))).type, `${WS}#response`);
    // exchange 2: the counterparty's VRC arrives first, the share after it
    const mine2 = await accepted(adapter, uid(2), S);
    const vrc = sign(S, { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'VerifiableRelationshipCredential'], issuer: S.did, validFrom: NOW, issuerScope: 'pairwise', credentialSubject: { id: mine2 } }, { purpose: 'assertionMethod' });
    const issued = await send(adapter, sign(A, { id: uid(30), threadId: uid(2), type: 'https://trusttasks.org/spec/vrc/relationships/issue/0.1', issuer: A.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { vrc } }));
    assert.equal(issued.type, 'https://trusttasks.org/spec/vrc/relationships/issue/0.1#response');
    assert.equal((await send(adapter, shareDoc(adapter, uid(11), uid(2), bundle(mine2, { sharer: S, thread: uid(2) })))).type, `${WS}#response`);
    assert.equal(await adapter.witnessCount(), 2);
  });
});

describe('WSH vectors, tier 2 (profile:attested)', () => {
  it('WSH-020 the receipt is signed and verifies under the request recipient', async () => {
    const adapter = await make(true);
    const mine = await accepted(adapter);
    const reply = await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine)));
    assert.equal(reply.type, `${WS}#response`);
    assert.ok(reply.proof, 'signed');
    const verdict = await adapter.verifier.verify(reply, { nowMs: created });
    assert.equal(verdict.valid, true);
    assert.equal(verdict.signer, adapter.signer.did, 'the request recipient');
    assert.equal(reply.issuer, adapter.signer.did);
  });

  it('WSH-021 the envelope is under the connection DID: accepted; a relationship-DID-signed envelope is refused', async () => {
    const adapter = await make(true);
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const bad = sign(R, { id: uid(10), threadId: uid(1), type: WS, issuer: A.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { presentation: b.presentation, outcomeEvidence: { initiating: b.initiating, terminal: b.terminal } } }, { allowIssuerMismatch: true });
    const refused = await send(adapter, bad);
    assert.ok(['proofInvalid', 'identityMismatch'].includes(refused.payload.code), refused.payload.code);
    assert.equal(await adapter.witnessCount(), 0);
    const ok = await send(adapter, shareDoc(adapter, uid(11), uid(1), b));
    assert.equal(ok.type, `${WS}#response`);
  });
});

describe('design: choices where the profile is silent, and the shape of what is stored', () => {
  it('the task is served under its URN codec form as well as the registry-style URI', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const reply = await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine), A, {}, WS_URN));
    assert.equal(reply.type, `${WS_URN}#response`);
    assert.equal(await adapter.witnessCount(), 1);
  });

  it('the citation may sit in the credential subject (the older placement) instead of the top level', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    assert.equal((await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { nested: true })))).type, `${WS}#response`);
  });

  it('parties are read from the session document when the credential subject carries none', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    assert.equal((await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine)))).type, `${WS}#response`);
    const row = (await witnessShares.findByExchange(adapter.db, uid(1)))!;
    assert.equal(JSON.parse(row.w3cVcJson).credentialSubject.parties, undefined);
  });

  it('a second, different share on the same exchange is refused (one share per party per exchange); the first stays', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const first = await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine)));
    const other = bundle(mine, { alterInitiating: undefined, witness: Y, terminalSigner: Y });
    const second = await send(adapter, shareDoc(adapter, uid(11), uid(1), other));
    assert.equal(second.payload.code, NOT_ACCEPTED);
    assert.equal(await adapter.witnessCount(), 1);
    assert.equal((await witnessShares.findByExchange(adapter.db, uid(1)))!.id, first.payload.vwcDigestMultibase);
  });

  it('the presentation must be held by the sender\'s relationship DID, wrap exactly one credential', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { holder: S.did }))));
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(11), uid(1), bundle(mine, { extraPresented: true }))));
  });

  it('a party cannot witness its own exchange (the witness is neither relationship DID nor connection DID)', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { witness: R, terminalSigner: R }))));
  });

  it('the credential\'s own proof must verify, independently of the evidence', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine, { tamperVwc: (v) => { v.validFrom = '2026-11-12T10:00:01Z'; } }))));
    // signed by a key the credential's issuer does not hold
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(11), uid(1), bundle(mine, { tamperVwc: (v) => { v.issuer = Y.did; } }))));
  });

  it('the terminal\'s delivered credential, where it carries one, must be the presented credential', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine, { terminal: (t) => ({ ...t, payload: { vwc: { other: true } } }) });
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), b)));
    // absent: accepted (the profile states no rule)
    const noVwc = bundle(mine, { terminal: (t) => ({ ...t, payload: {} }) });
    assert.equal((await send(adapter, shareDoc(adapter, uid(11), uid(1), noVwc))).type, `${WS}#response`);
  });

  it('KNOWN-LIMIT: a Linked Data (Ed25519Signature2018) presentation proof is refused: no JSON-LD canonicalisation exists in this tree', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const ld = { ...(b.presentation as Record<string, unknown>), proof: { type: 'Ed25519Signature2018', created: NOW, verificationMethod: `${R.did}#${R.did.slice(8)}`, proofPurpose: 'authentication', challenge: uid(1), domain: WITNESS_SHARE_DOMAIN, jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..AAAA' } };
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), { ...b, presentation: ld })));
  });

  it('a share on an ended exchange is not accepted', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    await adapter.db.run("UPDATE vrc_exchange_relationship_dids SET state = 'ended' WHERE exchange_id = ?", uid(1));
    await assertRefused(adapter, await send(adapter, shareDoc(adapter, uid(10), uid(1), bundle(mine))));
  });

  it('AUTHZ: a verified third party on someone else\'s accepted thread gets the very answer an unknown thread gets', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const doc = (id: string, thread: string) => sign(X, { id, threadId: thread, type: WS, issuer: X.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { presentation: b.presentation, outcomeEvidence: { initiating: b.initiating, terminal: b.terminal } } });
    const foreign = await send(adapter, doc(uid(10), uid(1)), X);
    const unknown = await send(adapter, doc(uid(11), uid(99)), X);
    const strip = (d: { payload: Record<string, unknown> }) => ({ ...d.payload, inResponseTo: undefined });
    assert.deepEqual(strip(foreign), strip(unknown), 'no existence oracle');
    assert.equal(await adapter.witnessCount(), 0);
  });

  it('participant: no verifier installed means no vote and nothing stored; abort removes what its transaction wrote', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const params = { exchangeId: uid(1), presentationJson: text(b.presentation), initiatingJson: text(b.initiating), terminalJson: text(b.terminal), senderConnectionDid: A.did };
    const bare = new (adapter.witnessShare.constructor as new (pid: string, a: unknown, t: unknown) => typeof adapter.witnessShare)('peer:x', adapter.db, adapter.txDb);
    assert.equal(await bare.prepare('tx-1', [{ op: 'store_witness_share', params } as never]), 'no');
    assert.equal(await adapter.witnessCount(), 0);
    assert.equal(await adapter.witnessShare.prepare('tx-2', [{ op: 'store_witness_share', params } as never]), 'yes');
    assert.equal(await adapter.witnessCount(), 0, 'nothing is stored while the transaction is undecided');
    await adapter.witnessShare.abort('tx-2');
    assert.equal(await adapter.witnessCount(), 0);
    assert.equal(Number((await adapter.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM witness_share_evidence'))!.n), 0);
  });

  it('participant: prepare, restart, abort leaves nothing; prepare, restart, commit stores once; a second commit adds nothing', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const params = { exchangeId: uid(1), presentationJson: text(b.presentation), initiatingJson: text(b.initiating), terminalJson: text(b.terminal), senderConnectionDid: A.did };
    const op = [{ op: 'store_witness_share', params } as never];
    assert.equal(await adapter.witnessShare.prepare('tx-a', op), 'yes');
    await adapter.restart();
    await adapter.witnessShare.abort('tx-a');
    assert.equal(await adapter.witnessCount(), 0, 'an abort after a restart leaves no row');
    assert.equal(await adapter.witnessShare.inquiry('tx-a'), 'aborted');

    assert.equal(await adapter.witnessShare.prepare('tx-b', op), 'yes');
    await adapter.restart();
    assert.equal(await adapter.witnessCount(), 0);
    await adapter.witnessShare.commit('tx-b');
    assert.equal(await adapter.witnessCount(), 1, 'a commit by the restarted participant applies the recorded effect');
    await adapter.witnessShare.commit('tx-b');
    assert.equal(await adapter.witnessCount(), 1);
    assert.equal(Number((await adapter.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM witness_share_evidence'))!.n), 1);
    assert.equal(await adapter.witnessShare.inquiry('tx-b'), 'committed');
  });

  it('participant: a second transaction for the same share is idempotent at commit', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const params = { exchangeId: uid(1), presentationJson: text(b.presentation), initiatingJson: text(b.initiating), terminalJson: text(b.terminal), senderConnectionDid: A.did };
    const op = [{ op: 'store_witness_share', params } as never];
    for (const tx of ['tx-1', 'tx-2']) {
      assert.equal(await adapter.witnessShare.prepare(tx, op), 'yes');
      await adapter.witnessShare.commit(tx);
    }
    assert.equal(await adapter.witnessCount(), 1);
  });

  it('restart: the stored credential and the duplicate record survive; the redelivery after restart is still one credential', async () => {
    const adapter = await make();
    const mine = await accepted(adapter);
    const b = bundle(mine);
    const first = await send(adapter, shareDoc(adapter, uid(10), uid(1), b));
    await adapter.restart();
    const second = await send(adapter, shareDoc(adapter, uid(11), uid(1), b));
    assert.equal(second.payload.vwcDigestMultibase, first.payload.vwcDigestMultibase);
    assert.equal(await adapter.witnessCount(), 1);
  });
});
