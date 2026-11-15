// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P5b: the layer 3b-DTG adapters behind the REAL pipeline (Tier 2, signed replies), the durable duplicate
 * record, the coordinator and the participants: `task-consent/{request,decision}` over the ceremony hold and
 * `credential-exchange/{issue,present}` over credential delivery and the new presentation store. The suite has no
 * vectors for these groups ("Not built"), so cases are named by the required behaviours of plan 06 section 5 (P5b):
 * purpose pin, double approve, non-admin indistinguishable from not-found, expiry `deadlineLapsed`, issue idempotent by digest.
 * Temp directories only; one injected clock.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_PROPOSE_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-spec.js';
import { CREDENTIAL_ISSUE_TYPE, CREDENTIAL_PRESENT_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/credential-exchange.js';
import { NEXT_STEP_TYPE_URI } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { TASK_CONSENT_DECISION_TYPE, TASK_CONSENT_REQUEST_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/task-consent.js';
import * as presentations from '@p2p-trust-stack/core/db/repositories/credential-presentations-repo.js';
import { VrcBoundaryAdapter } from './vrc-adapter.ts';
import { A, W, X, Y, clock, mk, sign, text, uid, useClock } from './witness-bundle.ts';
import type { Party } from './witness-bundle.ts';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));
const START = '2026-11-12T10:00:00Z';
const DAY = 24 * 60 * 60 * 1000;
const make = async () => {
  useClock(START);
  const a = await new VrcBoundaryAdapter({ attested: true }).init();
  await a.setClock(START);
  adapters.push(a);
  return a;
};
let seq = 400;
const fresh = () => uid(seq++);
type Reply = { type: string; threadId?: string; payload: Record<string, any> };
type Sent = { reply: Reply | undefined; status: number | undefined };
const send = async (a: VrcBoundaryAdapter, doc: unknown): Promise<Reply> => (await sendRaw(a, doc)).reply!;
const sendRaw = async (a: VrcBoundaryAdapter, doc: unknown): Promise<Sent> => {
  const r = await a.send({ from: { kind: 'actor', vid: (doc as { issuer: string }).issuer }, bytes: text(doc) });
  return { reply: r.replies[0] === undefined ? undefined : (JSON.parse(r.replies[0]) as Reply), status: r.transport.status };
};
const base = (a: VrcBoundaryAdapter, who: Party, type: string, thread: string, payload: unknown, id = fresh()) =>
  ({ id, threadId: thread, type, issuer: who.did, recipient: a.signer.did, issuedAt: clock.iso, payload });
const reasonOf = (r: Reply) => (r.payload.details as { reason?: string } | undefined)?.reason;
const moveTo = async (a: VrcBoundaryAdapter, ms: number) => {
  useClock(new Date(ms).toISOString().replace('.000Z', 'Z'));
  await a.setClock(clock.iso);
};

// ── task-consent ────
const body = (_a: VrcBoundaryAdapter, over: Record<string, unknown> = {}) => ({
  challenge: 'c'.repeat(24), taskType: 'https://trusttasks.org/spec/did/rotate/0.1', payloadDigest: 'zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR', sideEffects: 'mutating',
  exposure: { discloses: 'none', actsAsSubject: false }, effects: [{ kind: 'documentChange', summary: 'rotates a key' }], requester: X.did, approverSet: 'admins', minApprovals: 1,
  excludeRequester: true, expiresAt: new Date(clock.ms + 3600_000).toISOString().replace('.000Z', 'Z'), ...over,
});
const begin = (a: VrcBoundaryAdapter, who: Party, thread: string, admins: Party[] = [A, X]) =>
  sign(who, base(a, who, CEREMONY_PROPOSE_WIRE_TYPE, thread, { name: 'Founders', kind: 'vtc', threshold: 2, adminDids: admins.map((p) => p.did) }));
const held = async (a: VrcBoundaryAdapter, thread: string) => {
  const r = await send(a, begin(a, A, thread));
  assert.equal(r.type, NEXT_STEP_TYPE_URI);
  return r.payload.ext['p2pts.consent'] as { challenge: string; payloadDigest: string; taskType: string };
};
const decision = (a: VrcBoundaryAdapter, who: Party, thread: string, b: { challenge: string; payloadDigest: string }, over: Record<string, unknown> = {}, opts: Record<string, unknown> = { purpose: 'assertionMethod' }, type = TASK_CONSENT_DECISION_TYPE) =>
  sign(who, base(a, who, type, thread, { challenge: b.challenge, payloadDigest: b.payloadDigest, decision: 'approve', ...over }), opts);

describe('task-consent/decision over the ceremony hold', () => {
  it('approve is recorded under assertionMethod: a held ceremony answers next-step, the last approval is #response granted with the quorum', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    assert.equal(b.taskType, CEREMONY_PROPOSE_WIRE_TYPE);
    const first = await send(a, decision(a, A, t, b));
    assert.equal(first.type, NEXT_STEP_TYPE_URI, 'a hold follows decision 32, not the spec status pending');
    assert.deepEqual(first.payload.ext.quorum, { required: 2, received: 1 });
    assert.equal(await a.communityCount(), 0);
    const last = await send(a, decision(a, X, t, b));
    assert.equal(last.type, `${TASK_CONSENT_DECISION_TYPE}#response`);
    assert.deepEqual(last.payload, { status: 'granted', payloadDigest: b.payloadDigest, approvals: 2 });
    assert.equal(await a.communityCount(), 1);
    // The approval keeps its stored signature: the proof value of the decision document.
    const rows = await a.txDb.all<{ approver_did: string; signature: string }>('SELECT approver_did, signature FROM ceremony_approvals WHERE proposal_id = ?', t);
    assert.equal(rows.length, 2);
    assert.ok(rows.every((r) => typeof r.signature === 'string' && r.signature.startsWith('z')));
    assert.ok((last as unknown as { proof?: { proofPurpose?: string } }).proof, 'the reply is signed at tier 2');
  });

  it('purpose pin: a decision proven under authentication is refused at tier 2 and records nothing; assertionMethod is refused on the other tasks', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    const wrong = await send(a, decision(a, A, t, b, {}, { purpose: 'authentication' }));
    assert.equal(wrong.payload.code, 'proofInvalid');
    assert.equal((await a.ceremony.store.getApprovals(t)).length, 0);
    const request = sign(A, base(a, A, TASK_CONSENT_REQUEST_TYPE, fresh(), body(a)), { purpose: 'assertionMethod' });
    assert.equal((await send(a, request)).payload.code, 'proofInvalid');
    const issue = sign(A, base(a, A, CREDENTIAL_ISSUE_TYPE, fresh(), { sealed: 'x' }), { purpose: 'assertionMethod' });
    assert.equal((await send(a, issue)).payload.code, 'proofInvalid');
  });

  it('double approve: the same approver twice counts once, also after commit, with the same receipt', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    await send(a, decision(a, A, t, b));
    const again = await send(a, decision(a, A, t, b));
    assert.equal(again.type, NEXT_STEP_TYPE_URI);
    assert.equal((await a.ceremony.store.getApprovals(t)).length, 1);
    await send(a, decision(a, X, t, b));
    const after = await send(a, decision(a, X, t, b));
    assert.equal(after.type, `${TASK_CONSENT_DECISION_TYPE}#response`);
    assert.equal(after.payload.status, 'granted');
    assert.equal((await a.ceremony.store.getApprovals(t)).length, 2);
    assert.equal(await a.communityCount(), 1);
  });

  it('at Tier 1 (no attested pin) a decision under authentication is still refused (consumer 1), records nothing, and the reply to an unthreaded decision is on its own id', async () => {
    useClock(START);
    const a = await new VrcBoundaryAdapter({}).init();
    await a.setClock(START);
    adapters.push(a);
    const t = fresh();
    const b = await held(a, t);
    const bad = await send(a, decision(a, A, t, b, {}, { purpose: 'authentication' }));
    assert.equal(bad.payload.code, 'proofInvalid');
    assert.equal((await a.ceremony.store.getApprovals(t)).length, 0);
    const bare = (who: Party) => { const d = sign(who, { id: fresh(), type: TASK_CONSENT_DECISION_TYPE, issuer: who.did, recipient: a.signer.did, issuedAt: clock.iso, payload: { challenge: b.challenge, payloadDigest: b.payloadDigest, decision: 'approve' } }, { purpose: 'assertionMethod' }); return d; };
    const first = bare(A);
    const second = bare(X);
    assert.equal((await send(a, first)).threadId, (first as { id: string }).id);
    const last = await send(a, second);
    assert.equal(last.type, `${TASK_CONSENT_DECISION_TYPE}#response`);
    assert.equal(last.threadId, (second as { id: string }).id);
  });

  it('a signer outside the approver set is task-consent/decision:notAnApprover (consumer 5, after the binding checks) and records nothing; an unknown digest is noPending first', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    const snap = await a.snapshot();
    const outsider = await send(a, decision(a, Y, t, b));
    assert.equal(outsider.payload.code, 'task-consent/decision:notAnApprover');
    // Without a thread the pending request is found by its digest alone, and the outsider is still refused the same way.
    const noThread = await send(a, sign(Y, { id: fresh(), type: TASK_CONSENT_DECISION_TYPE, issuer: Y.did, recipient: a.signer.did, issuedAt: clock.iso, payload: { challenge: b.challenge, payloadDigest: b.payloadDigest, decision: 'approve' } }, { purpose: 'assertionMethod' }));
    assert.equal(noThread.payload.code, 'task-consent/decision:notAnApprover');
    const unknown = await send(a, decision(a, Y, fresh(), b));
    assert.equal(unknown.payload.code, 'task-consent/decision:notAnApprover', 'an unknown thread falls back to the digest, which names the held ceremony');
    const badDigest = await send(a, decision(a, Y, t, { challenge: 'x'.repeat(20), payloadDigest: 'zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR' }));
    assert.equal(badDigest.payload.code, 'task-consent/decision:noPending');
    const badChallenge = await send(a, decision(a, Y, t, { challenge: 'x'.repeat(20), payloadDigest: b.payloadDigest }));
    assert.equal(badChallenge.payload.code, 'task-consent/decision:challengeMismatch', 'binding errors come before the approver check');
    assert.equal((await a.diff(snap)).changed, false);
    const denyByOutsider = await send(a, decision(a, Y, t, b, { decision: 'deny' }));
    assert.equal(denyByOutsider.payload.code, 'task-consent/decision:notAnApprover');
    assert.equal((await a.ceremony.store.getProposal(t))!.status, 'pending');
  });

  it('a decision with no thread is matched to the pending request by payloadDigest and completes the quorum', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    const bare = (who: Party) => sign(who, { id: fresh(), type: TASK_CONSENT_DECISION_TYPE, issuer: who.did, recipient: a.signer.did, issuedAt: clock.iso, payload: { challenge: b.challenge, payloadDigest: b.payloadDigest, decision: 'approve' } }, { purpose: 'assertionMethod' });
    assert.equal((await send(a, bare(A))).type, NEXT_STEP_TYPE_URI);
    const last = await send(a, bare(X));
    assert.equal(last.type, `${TASK_CONSENT_DECISION_TYPE}#response`);
    assert.equal(last.payload.status, 'granted');
    assert.equal(await a.communityCount(), 1);
  });

  it('expiry: a decision at or after the deadline is taskFailed deadlineLapsed, the ceremony is stored expired and nothing is recorded', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    await moveTo(a, Date.parse(START) + 7 * DAY);
    const late = await send(a, decision(a, A, t, b));
    assert.equal(late.payload.code, 'taskFailed');
    assert.equal(reasonOf(late), 'deadlineLapsed');
    assert.equal((await a.ceremony.store.getProposal(t))!.status, 'expired');
    assert.equal((await a.ceremony.store.getApprovals(t)).length, 0);
    const lateDeny = await send(a, decision(a, X, t, b, { decision: 'deny' }));
    assert.equal(reasonOf(lateDeny), 'deadlineLapsed');
  });

  it('deny closes the ceremony for every approver: denied, stored aborted, a later approval is refused, a repeat deny is the same answer, after commit it is alreadyCommitted', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    await send(a, decision(a, A, t, b));
    const denied = await send(a, decision(a, X, t, b, { decision: 'deny', reason: 'not now' }));
    assert.equal(denied.type, `${TASK_CONSENT_DECISION_TYPE}#response`);
    assert.deepEqual(denied.payload, { status: 'denied', payloadDigest: b.payloadDigest });
    assert.equal((await a.ceremony.store.getProposal(t))!.status, 'aborted');
    assert.equal((await send(a, decision(a, X, t, b, { decision: 'deny' }))).payload.status, 'denied');
    const after = await send(a, decision(a, X, t, b));
    assert.equal(after.payload.code, 'taskFailed');
    assert.equal(await a.communityCount(), 0);

    const t2 = fresh();
    const b2 = await held(a, t2);
    await send(a, decision(a, A, t2, b2));
    await send(a, decision(a, X, t2, b2));
    const lateDeny = await send(a, decision(a, A, t2, b2, { decision: 'deny' }));
    assert.equal(reasonOf(lateDeny), 'alreadyCommitted');
  });

  it('binding: wrong digest is noPending, wrong challenge is challengeMismatch, a foreign actionId is actionMismatch, evidence is evidenceInvalid; nothing is recorded', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    const code = async (over: Record<string, unknown>) => (await send(a, decision(a, A, t, b, over))).payload.code;
    assert.equal(await code({ payloadDigest: 'zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR' }), 'task-consent/decision:noPending');
    assert.equal(await code({ challenge: 'y'.repeat(32) }), 'task-consent/decision:challengeMismatch');
    assert.equal(await code({ actionId: 'another' }), 'task-consent/decision:actionMismatch');
    assert.equal(await code({ evidence: { kind: 'webauthn', assertion: { id: 'a', rawId: 'a', type: 'public-key', response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA' } } } }), 'task-consent/decision:evidenceInvalid');
    assert.equal(await code({ evidence: { kind: 'didSigned', statement: {} } }), 'malformedRequest');
    assert.equal(await code({ challenge: 'short' }), 'malformedRequest');
    assert.equal(await code({ decision: 'maybe' }), 'malformedRequest');
    assert.equal((await a.ceremony.store.getApprovals(t)).length, 0);
    assert.equal((await send(a, decision(a, A, t, b, { actionId: t }))).type, NEXT_STEP_TYPE_URI, 'actionId naming this ceremony is accepted');
  });

  it('version choice: 0.2 is served, 0.1 (superseded) is unsupportedVersion naming 0.2; discovery lists the served types from the registry', async () => {
    const a = await make();
    const old = await send(a, decision(a, A, fresh(), { challenge: 'c'.repeat(20), payloadDigest: 'zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR' }, {}, { purpose: 'assertionMethod' }, 'https://trusttasks.org/spec/task-consent/decision/0.1'));
    assert.equal(old.payload.code, 'unsupportedVersion');
    assert.deepEqual(old.payload.details.servedVersions, ['0.2']);
    const supported = (await a.capabilities()).supportedTypes;
    for (const t of [TASK_CONSENT_DECISION_TYPE, TASK_CONSENT_REQUEST_TYPE, CREDENTIAL_ISSUE_TYPE, CREDENTIAL_PRESENT_TYPE]) assert.ok(supported.includes(t), t);
    assert.ok(!supported.includes('https://trusttasks.org/spec/task-consent/decision/0.1'));
    assert.ok(!supported.some((t) => /credential-exchange\/(offer|request)|\/revoke/.test(t)), 'offer, request and revoke verbs are out');
  });
});

describe('task-consent/request as the approver device', () => {
  it('before enrolExecutor the device has no enrolled executor (untrustedIssuer, no prompt); a prompt counts as handled', async () => {
    const a = await make();
    const doc = () => sign(A, base(a, A, TASK_CONSENT_REQUEST_TYPE, fresh(), body(a)));
    assert.equal((await send(a, doc())).payload.code, 'task-consent/request:untrustedIssuer');
    assert.equal(a.consentPrompts.length, 0);
    assert.deepEqual(await a.trigger('enrolExecutor', { vid: A.did }), { documents: [] });
    const handled = (await a.observe({ query: 'handled' })).value;
    assert.equal((await send(a, doc())).payload.status, 'prompted');
    assert.equal((await a.observe({ query: 'handled' })).value, Number(handled) + 1);
    await a.reset();
    await a.setClock(START);
    assert.equal(a.consentPrompts.length, 0);
    assert.equal((await send(a, doc())).payload.code, 'task-consent/request:untrustedIssuer', 'reset forgets the enrolment');
  });
  it('a verified request from an enrolled executor raises one prompt and is acknowledged prompted; a replay of the same document raises none', async () => {
    const a = await make();
    await a.trigger('enrolExecutor', { vid: A.did });
    const doc = sign(A, base(a, A, TASK_CONSENT_REQUEST_TYPE, fresh(), body(a, { note: 'please' })));
    const r = await send(a, doc);
    assert.equal(r.type, `${TASK_CONSENT_REQUEST_TYPE}#response`);
    assert.deepEqual(r.payload, { status: 'prompted' });
    assert.equal(a.consentPrompts.length, 1);
    assert.equal(a.consentPrompts[0]!.executor, A.did);
    assert.equal(a.consentPrompts[0]!.note, 'please');
    await send(a, doc);
    assert.equal(a.consentPrompts.length, 1);
  });
  it('refuses without prompting: this device as the requester when excluded (notEligible), a lapsed request (deadlineLapsed), malformed members; an unsigned request is proofRequired', async () => {
    const a = await make();
    await a.trigger('enrolExecutor', { vid: A.did });
    const q = async (over: Record<string, unknown>) => send(a, sign(A, base(a, A, TASK_CONSENT_REQUEST_TYPE, fresh(), body(a, over))));
    assert.equal((await q({ requester: a.signer.did })).payload.code, 'task-consent/request:notEligible');
    assert.equal((await q({ requester: a.signer.did, excludeRequester: false })).payload.status, 'prompted');
    a.consentPrompts.length = 0;
    const lapsed = await q({ expiresAt: new Date(clock.ms - 1000).toISOString().replace('.000Z', 'Z') });
    assert.equal(reasonOf(lapsed), 'deadlineLapsed');
    assert.equal((await q({ minApprovals: 0 })).payload.code, 'malformedRequest');
    assert.equal((await q({ challenge: 'short' })).payload.code, 'malformedRequest');
    const unsigned = await send(a, base(a, A, TASK_CONSENT_REQUEST_TYPE, fresh(), body(a)));
    assert.equal(unsigned.payload.code, 'proofRequired');
    assert.equal(a.consentPrompts.length, 0);
  });
});

// ── credential-exchange ─────────────────────────────────────────────
const credential = (issuer: Party, subject: string, over: Record<string, unknown> = {}, signOpts: Record<string, unknown> = {}) =>
  sign(issuer, { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'MembershipCredential'], issuer: issuer.did, credentialSubject: { id: subject, memberOf: 'did:example:community' }, ...over }, { purpose: 'assertionMethod', ...signOpts });
const credentialRows = async (a: VrcBoundaryAdapter) => a.db.all<{ uuid: string; vc_type: string; credential_digest: string; subject_identity_uuid: string }>("SELECT uuid, vc_type, credential_digest, subject_identity_uuid FROM credentials WHERE vc_type <> 'vrc'");
const issue = (a: VrcBoundaryAdapter, from: Party, payload: unknown, thread = fresh()) => sign(from, base(a, from, CREDENTIAL_ISSUE_TYPE, thread, payload));

describe('credential-exchange/issue over the existing credential delivery', () => {
  it('a credential delivered by its issuer about us is stored once (204, no response document); the same credential again, in a new document, adds no row (idempotent by digest)', async () => {
    const a = await make();
    const vc = credential(A, a.signer.did);
    const first = await sendRaw(a, issue(a, A, { credential_response: { credential: vc } }));
    assert.equal(first.status, 204);
    const rows = await credentialRows(a);
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.vc_type, 'vmc');
    const second = await sendRaw(a, issue(a, A, { credential_response: { credential: JSON.parse(JSON.stringify(vc)) } }));
    assert.equal(second.status, 204);
    assert.equal((await credentialRows(a)).length, 1);
    assert.equal((await credentialRows(a))[0]!.credential_digest, rows[0]!.credential_digest);
    const other = credential(A, a.signer.did, { credentialSubject: { id: a.signer.did, memberOf: 'did:example:other' } });
    await sendRaw(a, issue(a, A, { credential_response: { credential: other } }));
    assert.equal((await credentialRows(a)).length, 2, 'a different credential is a different row');
  });

  it('refusals store nothing: a relayed delivery, a credential about someone else, a tampered one, an expired one, sealed, SD-JWT, both members, a relationship credential', async () => {
    const a = await make();
    const deliver = async (payload: unknown, from: Party = A) => (await sendRaw(a, issue(a, from, payload))).reply!;
    const tampered = credential(A, a.signer.did);
    (tampered.credentialSubject as { memberOf: string }).memberOf = 'evil';
    const relayed = await deliver({ credential_response: { credential: credential(A, a.signer.did) } }, X);
    assert.equal(relayed.payload.code, 'permissionDenied');
    assert.equal((await deliver({ credential_response: { credential: credential(A, X.did) } })).payload.code, 'permissionDenied');
    const bad = await deliver({ credential_response: { credential: tampered } });
    assert.equal(bad.payload.code, 'taskFailed');
    assert.equal(reasonOf(bad), 'vcInvalid');
    assert.equal(reasonOf(await deliver({ credential_response: { credential: credential(A, a.signer.did, { validUntil: '2026-11-12T09:00:00Z' }) } })), 'vcInvalid');
    assert.equal((await deliver({ sealed: 'armored-bundle' })).payload.code, 'credential-exchange/issue:unsupportedFormat');
    assert.equal((await deliver({ credential_response: { credential: 'eyJhbGciOi.payload.sig' } })).payload.code, 'credential-exchange/issue:unsupportedFormat');
    assert.equal((await deliver({ credential_response: { credential: credential(A, a.signer.did) }, sealed: 'x' })).payload.code, 'malformedRequest');
    assert.equal((await deliver({ credential_response: { credential: credential(A, a.signer.did, { type: ['VerifiableCredential', 'RelationshipCredential'] }) } })).payload.code, 'credential-exchange/issue:unsupportedFormat');
    assert.equal((await credentialRows(a)).length, 0);
  });
});

const vp = (a: VrcBoundaryAdapter, holder: Party, credentials: unknown[], thread: string, over: Record<string, unknown> = {}, signOpts: Record<string, unknown> = {}) =>
  sign(holder, { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiablePresentation'], holder: holder.did, verifiableCredential: credentials, ...over }, { purpose: 'authentication', challenge: thread, domain: a.signer.did, allowIssuerMismatch: true, ...signOpts });
const present = (a: VrcBoundaryAdapter, from: Party, token: unknown, thread: string) => sign(from, base(a, from, CREDENTIAL_PRESENT_TYPE, thread, { vp_token: token }));

describe('credential-exchange/present (new: the verifier keeps the presentation as evidence)', () => {
  it('a holder-bound presentation for our nonce and audience is stored once (204); the same presentation again adds nothing', async () => {
    const a = await make();
    const t = fresh();
    const token = vp(a, A, [credential(W, A.did)], t);
    assert.equal((await sendRaw(a, present(a, A, token, t))).status, 204);
    const row = (await presentations.findByThread(a.db, t))!;
    assert.equal(row.holderDid, A.did);
    assert.equal(row.verifierDid, a.signer.did);
    assert.deepEqual(row.issuers, [W.did]);
    assert.equal((await sendRaw(a, present(a, A, token, t))).status, 204);
    assert.equal(await presentations.count(a.db), 1);
  });

  it('a nonce is single use (staleNonce), the wrong nonce is staleNonce, the wrong audience is audienceMismatch; nothing is stored for a refusal', async () => {
    const a = await make();
    const t = fresh();
    await sendRaw(a, present(a, A, vp(a, A, [credential(W, A.did)], t), t));
    const second = (await sendRaw(a, present(a, A, vp(a, A, [credential(W, A.did, { credentialSubject: { id: A.did, memberOf: 'other' } })], t), t))).reply!;
    assert.equal(second.payload.code, 'credential-exchange/present:staleNonce');
    const t2 = fresh();
    const wrongNonce = (await sendRaw(a, present(a, A, vp(a, A, [credential(W, A.did)], t2, {}, { challenge: 'someone-elses' }), t2))).reply!;
    assert.equal(wrongNonce.payload.code, 'credential-exchange/present:staleNonce');
    const wrongAudience = (await sendRaw(a, present(a, A, vp(a, A, [credential(W, A.did)], t2, {}, { domain: X.did }), t2))).reply!;
    assert.equal(wrongAudience.payload.code, 'credential-exchange/present:audienceMismatch');
    assert.equal(await presentations.count(a.db), 1);
  });

  it('refuses a presentation by someone other than the holder, a credential about another subject, a forged credential, an SD-JWT string and a missing vp_token', async () => {
    const a = await make();
    const t = fresh();
    const code = async (token: unknown, from: Party = A, thread = fresh()) => (await sendRaw(a, present(a, from, token, thread))).reply!.payload.code;
    // A relays a presentation whose holder is X: the holder must be the verified sender.
    assert.equal(await code(vp(a, X, [credential(W, X.did)], t), A, t), 'permissionDenied');
    const t3 = fresh();
    assert.equal(await code(vp(a, A, [credential(W, X.did)], t3), A, t3), 'taskFailed');
    const forged = credential(W, A.did);
    (forged.credentialSubject as { memberOf: string }).memberOf = 'evil';
    const t4 = fresh();
    assert.equal(await code(vp(a, A, [forged], t4), A, t4), 'taskFailed');
    assert.equal(await code('eyJhbGciOi.vp.sig'), 'malformedRequest');
    const missing = (await sendRaw(a, sign(A, base(a, A, CREDENTIAL_PRESENT_TYPE, fresh(), {})))).reply!;
    assert.equal(missing.payload.code, 'malformedRequest');
    assert.equal(await presentations.count(a.db), 0);
  });
});

void mk;

describe('helper trigger actions of the 3b-DTG groups (suite docs/04 section 4.4)', () => {
  it('are declared as optional capabilities only when the types are served (consentBinding also needs the ceremony)', async () => {
    const a = await make();
    const optional = (await a.capabilities()).optional;
    for (const c of ['trigger.consentEnrol', 'trigger.consentBinding', 'trigger.presentationNonce']) assert.ok(optional.includes(c), c);
    useClock(START);
    const bare = await new VrcBoundaryAdapter({ attested: true, dtg: false }).init();
    adapters.push(bare);
    const off = (await bare.capabilities()).optional;
    for (const c of ['trigger.consentEnrol', 'trigger.consentBinding', 'trigger.presentationNonce']) assert.ok(!off.includes(c), c);
    const noCeremony = await new VrcBoundaryAdapter({ attested: true, ceremony: false }).init();
    adapters.push(noCeremony);
    const partial = (await noCeremony.capabilities()).optional;
    assert.ok(partial.includes('trigger.consentEnrol') && !partial.includes('trigger.consentBinding'));
  });

  it('consentBinding returns, in documents[0], the stack-computed challenge and digest of the held proposal; a decision echoing them completes the quorum', async () => {
    const a = await make();
    const t = fresh();
    const b = await held(a, t);
    const r = await a.trigger('consentBinding', { thread: t });
    assert.equal(r.documents.length, 1);
    assert.deepEqual(JSON.parse(r.documents[0]!), { challenge: b.challenge, payloadDigest: b.payloadDigest });
    const got = JSON.parse(r.documents[0]!) as { challenge: string; payloadDigest: string };
    await send(a, decision(a, A, t, got));
    assert.equal((await send(a, decision(a, X, t, got))).payload.status, 'granted');
    await assert.rejects(() => a.trigger('consentBinding', { thread: fresh() }), /no held consent/);
  });

  it('presentationNonce returns a fresh single-use {nonce, threadId}; observe stored counts credentials and presentations', async () => {
    const a = await make();
    const one = JSON.parse((await a.trigger('presentationNonce', {})).documents[0]!) as { nonce: string; threadId: string };
    const two = JSON.parse((await a.trigger('presentationNonce', {})).documents[0]!) as { nonce: string; threadId: string };
    assert.equal(one.nonce, one.threadId);
    assert.notEqual(one.nonce, two.nonce);
    assert.equal((await a.observe({ query: 'stored', kind: 'presentation' })).value, 0);
    assert.equal((await a.observe({ query: 'stored', kind: 'credential' })).value, 0);
    const before = Number((await a.observe({ query: 'handled' })).value);
    await sendRaw(a, issue(a, A, { credential_response: { credential: credential(A, a.signer.did) } }));
    assert.equal((await a.observe({ query: 'stored', kind: 'credential' })).value, 1);
    assert.equal(Number((await a.observe({ query: 'handled' })).value), before + 1, 'an accepted issue counts as handled');
    assert.equal((await a.observe({ query: 'stored', kind: 'vrc' })).value, 0);
  });
});
