// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P8c: the `ceremony-doc` handlers (founding ceremony) behind the REAL pipeline, the
 * durable duplicate record, the transaction coordinator, the ceremony participant and store, and the
 * trust-task recorder. The suite has no 2PC vector files yet ("Not built"), so the cases are named by
 * the design (docs/04 section 12, docs/06 sections 2.2 and 3.9, section 13 negative categories).
 * Temp directories only; one injected clock drives the pipeline, the deadline and the signer.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_PROPOSE_WIRE_TYPE, CEREMONY_RESET_WIRE_TYPE, CEREMONY_STATUS_WIRE_TYPE, CEREMONY_WIRE_TYPES } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-spec.js';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { HandlerContext } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { NEXT_STEP_TYPE_URI } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import type { TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { createCeremonyDocHandlers } from '../../src/runtime/trust-tasks-boundary/ceremony-doc.ts';
import { VrcBoundaryAdapter } from './vrc-adapter.ts';
import { A, X, Y, clock, sign, text, uid, useClock } from './witness-bundle.ts';
import type { Party } from './witness-bundle.ts';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));
const START = '2026-11-12T10:00:00Z';
const DAY = 24 * 60 * 60 * 1000;
const make = async (attested = true) => {
  useClock(START);
  const a = await new VrcBoundaryAdapter({ attested }).init();
  await a.setClock(START);
  adapters.push(a);
  return a;
};
const moveTo = async (a: VrcBoundaryAdapter, ms: number) => {
  useClock(new Date(ms).toISOString().replace('.000Z', 'Z'));
  await a.setClock(clock.iso);
};

let seq = 100;
const fresh = () => uid(seq++);
type Reply = { type: string; threadId?: string; issuer?: string; recipient?: string; payload: Record<string, any> };

/** Delivered by the document's own issuer (the carrier-authenticated sender), unless a sender is given. */
const send = async (a: VrcBoundaryAdapter, doc: unknown, from?: Party): Promise<Reply> => {
  const issuer = from?.did ?? (typeof doc === 'object' && doc !== null ? (doc as { issuer?: string }).issuer : undefined) ?? A.did;
  return JSON.parse((await a.send({ from: { kind: 'actor', vid: issuer }, bytes: typeof doc === 'string' ? doc : text(doc) })).replies[0]!);
};

const base = (a: VrcBoundaryAdapter, who: Party, type: string, thread: string, payload: Record<string, unknown>, id = fresh()) =>
  ({ id, threadId: thread, type, issuer: who.did, recipient: a.signer.did, issuedAt: clock.iso, payload });
const begin = (a: VrcBoundaryAdapter, who: Party, thread: string, o: { name?: string; admins?: Party[]; threshold?: number } = {}) =>
  sign(who, base(a, who, CEREMONY_PROPOSE_WIRE_TYPE, thread, { name: o.name ?? 'Founders', kind: 'vtc', threshold: o.threshold ?? 2, adminDids: (o.admins ?? [A, X]).map((p) => p.did) }));
const cosign = (a: VrcBoundaryAdapter, who: Party, thread: string, extra: Record<string, unknown> = {}) => sign(who, base(a, who, CEREMONY_CO_SIGN_WIRE_TYPE, thread, extra));
const status = (a: VrcBoundaryAdapter, who: Party, thread: string) => sign(who, base(a, who, CEREMONY_STATUS_WIRE_TYPE, thread, {}));
const reset = (a: VrcBoundaryAdapter, who: Party, thread: string) => sign(who, base(a, who, CEREMONY_RESET_WIRE_TYPE, thread, {}));

const approvalsOf = async (a: VrcBoundaryAdapter, id: string) => (await a.ceremony.store.getApprovals(id)).length;
const reasonOf = (r: Reply) => (r.payload.details as { reason?: string } | undefined)?.reason;

describe('ceremony-doc: begin and approve (founding)', () => {
  it('begin is answered with a signed next-step: proceed, quorum in ext, nothing committed yet', async () => {
    const a = await make();
    const t = fresh();
    const r = await send(a, begin(a, A, t));
    assert.equal(r.type, NEXT_STEP_TYPE_URI);
    assert.equal(r.payload.continuation, 'proceed');
    assert.deepEqual(r.payload.ext, { quorum: { required: 2, received: 0 } });
    assert.deepEqual(r.payload.expects.map((e: { typeUri: string }) => e.typeUri), [CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_STATUS_WIRE_TYPE]);
    assert.equal(r.threadId, t);
    assert.equal(r.recipient, A.did);
    assert.ok((r as unknown as { proof?: unknown }).proof, 'signed at tier 2');
    assert.equal(await a.communityCount(), 0);
    assert.equal((await a.observe({ query: 'documentState', id: t })).value, 'accepted');
  });

  it('the quorum commits: pending co-sign is a next-step, the last one is a #response read after the effect exists', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t));
    const first = await send(a, cosign(a, A, t));
    assert.equal(first.type, NEXT_STEP_TYPE_URI);
    assert.deepEqual(first.payload.ext, { quorum: { required: 2, received: 1 } });
    assert.equal(await a.communityCount(), 0, 'no effect before the quorum');
    const last = await send(a, cosign(a, X, t));
    assert.equal(last.type, `${CEREMONY_CO_SIGN_WIRE_TYPE}#response`);
    assert.equal(last.payload.status, 'crystallized');
    assert.equal(last.payload.approvalCount, 2);
    assert.equal(await a.communityCount(), 1);
    assert.equal((await a.observe({ query: 'documentState', id: t })).value, 'responded');
  });

  it('double approve: the same admin twice counts once and creates no second effect, also after commit', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t));
    await send(a, cosign(a, A, t));
    const again = await send(a, cosign(a, A, t));
    assert.equal(again.type, NEXT_STEP_TYPE_URI);
    assert.equal(await approvalsOf(a, t), 1);
    await send(a, cosign(a, X, t));
    const after = await send(a, cosign(a, X, t));
    assert.equal(after.type, `${CEREMONY_CO_SIGN_WIRE_TYPE}#response`, 'same receipt after commit');
    assert.equal(await approvalsOf(a, t), 2);
    assert.equal(await a.communityCount(), 1);
  });

  it('non-admin approve: permissionDenied notFoundOrNotPermitted, identical to an unknown ceremony, no state change', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t));
    const snap = await a.snapshot();
    const outsider = await send(a, cosign(a, Y, t));
    const unknown = await send(a, cosign(a, Y, fresh()));
    for (const r of [outsider, unknown]) {
      assert.equal(r.payload.code, 'permissionDenied');
      assert.equal(reasonOf(r), 'notFoundOrNotPermitted');
      assert.equal(r.payload.retryable, false);
    }
    assert.equal(outsider.payload.message, unknown.payload.message);
    assert.deepEqual(await a.diff(snap), { changed: false });
    assert.equal(await approvalsOf(a, t), 0);
  });

  it('a late approval is refused as taskFailed deadlineLapsed, flips the ceremony to expired and records nothing (half-open deadline)', async () => {
    const a = await make();
    const t = fresh();
    const start = clock.ms;
    await send(a, begin(a, A, t));
    await send(a, cosign(a, A, t));
    // one second before the deadline is still open
    await moveTo(a, start + 7 * DAY - 1000);
    const lateButOpen = await send(a, cosign(a, X, t));
    assert.equal(lateButOpen.payload.status, 'crystallized', 'inside the deadline the approval commits');

    const b = await make();
    const u = fresh();
    await send(b, begin(b, A, u));
    await send(b, cosign(b, A, u));
    await moveTo(b, start + 7 * DAY); // exactly at expiresAt: lapsed
    const late = await send(b, cosign(b, X, u));
    assert.equal(late.payload.code, 'taskFailed');
    assert.equal(reasonOf(late), 'deadlineLapsed');
    assert.equal(await approvalsOf(b, u), 1, 'the late approval is not recorded');
    assert.equal(await b.communityCount(), 0, 'no late effect');
    assert.equal((await b.ceremony.store.getProposal(u))!.status, 'expired');
  });

  it('an expired ceremony: every later document reports deadlineLapsed; the status query reports expired as data', async () => {
    const a = await make();
    const t = fresh();
    const start = clock.ms;
    await send(a, begin(a, A, t));
    await moveTo(a, start + 8 * DAY);
    const q = await send(a, status(a, A, t));
    assert.equal(q.type, `${CEREMONY_STATUS_WIRE_TYPE}#response`);
    assert.equal(q.payload.status, 'expired');
    const co = await send(a, cosign(a, A, t));
    assert.equal(reasonOf(co), 'deadlineLapsed');
    const again = await send(a, begin(a, A, t));
    assert.equal(reasonOf(again), 'deadlineLapsed');
  });

  it('a refused effect fails the ceremony with the closed reason and the same answer on every later read (nameTaken)', async () => {
    const a = await make();
    const t1 = fresh();
    await send(a, begin(a, A, t1, { admins: [A] }));
    const done = await send(a, cosign(a, A, t1));
    assert.equal(done.payload.status, 'crystallized');
    const t2 = fresh();
    await send(a, begin(a, A, t2, { admins: [A] }));
    const refused = await send(a, cosign(a, A, t2));
    assert.equal(refused.payload.code, 'taskFailed');
    assert.equal(reasonOf(refused), 'nameTaken');
    assert.equal((await a.ceremony.store.getProposal(t2))!.status, 'failed');
    assert.equal(await a.communityCount(), 1);
    const again = await send(a, cosign(a, A, t2));
    assert.equal(reasonOf(again), 'nameTaken', 'a failed ceremony reports its recorded reason');
    assert.equal((await send(a, status(a, A, t2))).payload.status, 'failed');
  });

  it('begin: same content again is the same state, other content is idConflict, a proposer who is not a named admin is refused', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t));
    const same = await send(a, begin(a, A, t));
    assert.equal(same.type, NEXT_STEP_TYPE_URI);
    assert.equal((await a.txDb.all('SELECT proposal_id FROM ceremony_proposals')).length, 1);
    const other = await send(a, begin(a, A, t, { name: 'Different' }));
    assert.equal(other.payload.code, 'idConflict');
    const notNamed = await send(a, begin(a, Y, fresh(), { admins: [A, X] }));
    assert.equal(notNamed.payload.code, 'permissionDenied');
    assert.equal(reasonOf(notNamed), 'notAdmin');
    // somebody else beginning on an existing thread learns nothing
    const hijack = await send(a, begin(a, Y, t, { admins: [Y] }));
    assert.equal(reasonOf(hijack), 'notFoundOrNotPermitted');
  });

  it('a begin without a proof is refused (proofRequired) and nothing is created', async () => {
    const a = await make(false);
    const doc = base(a, A, CEREMONY_PROPOSE_WIRE_TYPE, fresh(), { name: 'x', kind: 'vtc', threshold: 1, adminDids: [A.did] });
    const r = await send(a, doc);
    assert.equal(r.payload.code, 'proofRequired');
    assert.equal((await a.txDb.all('SELECT proposal_id FROM ceremony_proposals')).length, 0);
  });

  it('an approval naming another proposal hash is refused without effect; the right hash is accepted', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t, { admins: [A] }));
    const wrong = await send(a, cosign(a, A, t, { proposalHash: 'not-the-hash' }));
    assert.equal(wrong.payload.code, 'malformedRequest');
    assert.equal(await approvalsOf(a, t), 0);
    const hash = (await a.ceremony.store.getProposal(t))!.proposalHash;
    assert.equal((await send(a, cosign(a, A, t, { proposalHash: hash }))).payload.status, 'crystallized');
  });
});

describe('ceremony-doc: query and reset', () => {
  it('status is readable by an admin, and is the same refusal for an outsider and for an unknown ceremony', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t));
    const ok = await send(a, status(a, X, t));
    assert.deepEqual({ ...ok.payload, expiresAt: undefined }, { ceremonyId: t, status: 'pending', approvalCount: 0, required: 2, threshold: 2, expiresAt: undefined });
    assert.equal(reasonOf(await send(a, status(a, Y, t))), 'notFoundOrNotPermitted');
    assert.equal(reasonOf(await send(a, status(a, A, fresh()))), 'notFoundOrNotPermitted');
  });

  it('reset after commit is refused (alreadyCommitted) and the ceremony and its effect stay', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t, { admins: [A] }));
    await send(a, cosign(a, A, t));
    const snap = await a.snapshot();
    const r = await send(a, reset(a, A, t));
    assert.equal(r.payload.code, 'taskFailed');
    assert.equal(reasonOf(r), 'alreadyCommitted');
    assert.deepEqual(await a.diff(snap), { changed: false });
    assert.equal((await a.ceremony.store.getProposal(t))!.status, 'crystallized');
  });

  it('reset: refused while pending, allowed from expired, never by an outsider, and not repeatable once aborted', async () => {
    const a = await make();
    const t = fresh();
    const start = clock.ms;
    await send(a, begin(a, A, t));
    const pending = await send(a, reset(a, A, t));
    assert.equal(pending.payload.code, 'taskFailed');
    assert.equal((await a.ceremony.store.getProposal(t))!.status, 'pending');
    assert.equal(reasonOf(await send(a, reset(a, Y, t))), 'notFoundOrNotPermitted');
    await moveTo(a, start + 8 * DAY);
    const ok = await send(a, reset(a, A, t));
    assert.equal(ok.type, `${CEREMONY_RESET_WIRE_TYPE}#response`);
    assert.equal(ok.payload.status, 'aborted');
    assert.equal((await send(a, reset(a, A, t))).payload.code, 'taskFailed', 'a second reset of an aborted ceremony is refused');
  });

  it('reset from failed is allowed', async () => {
    const a = await make();
    const t1 = fresh();
    await send(a, begin(a, A, t1, { admins: [A] }));
    await send(a, cosign(a, A, t1));
    const t2 = fresh();
    await send(a, begin(a, A, t2, { admins: [A] }));
    await send(a, cosign(a, A, t2)); // nameTaken: failed
    assert.equal((await send(a, reset(a, A, t2))).payload.status, 'aborted');
  });

  it('a first approval after commit by a named admin who had not approved is alreadyCommitted; an outsider learns nothing', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t, { admins: [A, X] }));
    await a.ceremony.store.updateStatus(t, 'crystallized', clock.ms); // committed by other means: X never approved
    const r = await send(a, cosign(a, X, t));
    assert.equal(reasonOf(r), 'alreadyCommitted');
    assert.equal(await approvalsOf(a, t), 0);
    assert.equal(reasonOf(await send(a, cosign(a, Y, t))), 'notFoundOrNotPermitted');
  });
});

describe('ceremony-doc: outcomes are read from the coordinator, never guessed', () => {
  const ctxFor = (a: VrcBoundaryAdapter, who: Party): HandlerContext => ({
    parties: { issuer: who.did, recipient: a.signer.did },
    sender: who.did,
    verifiedSigner: who.did,
    myVid: a.signer.did,
    now: clock.ms,
    clock: () => clock.iso,
    newId: () => fresh(),
  });
  const handlersWith = (a: VrcBoundaryAdapter, outcome: 'unknown' | 'inFlight') => {
    const real = a.txManager;
    const manager = { run: real.run.bind(real), getOutcome: async () => outcome } as never;
    return createCeremonyDocHandlers({ txManager: manager, participant: a.ceremony });
  };
  const handle = (handlers: ReturnType<typeof createCeremonyDocHandlers>, type: string, doc: Record<string, unknown>, ctx: HandlerContext) =>
    Promise.resolve(handlers.find((h) => h.types.includes(type))!.handle(doc as unknown as TrustTaskDocument<unknown>, ctx));

  it('an unresolved outcome on an open ceremony is indeterminate (retryable), and so is a met quorum whose outcome is unknown', async () => {
    const a = await make();
    const t = fresh();
    const h = handlersWith(a, 'unknown');
    const beginDoc = base(a, A, CEREMONY_PROPOSE_WIRE_TYPE, t, { name: 'Solo', kind: 'vtc', threshold: 1, adminDids: [A.did] });
    await assert.rejects(handle(h, CEREMONY_PROPOSE_WIRE_TYPE, beginDoc, ctxFor(a, A)), (e: unknown) => e instanceof TaskError && e.code === 'indeterminate' && e.retryable === true);
    await assert.rejects(handle(h, CEREMONY_CO_SIGN_WIRE_TYPE, base(a, A, CEREMONY_CO_SIGN_WIRE_TYPE, t, {}), ctxFor(a, A)), (e: unknown) => e instanceof TaskError && e.code === 'indeterminate');
    assert.equal((await a.ceremony.store.getProposal(t))!.status, 'crystallized');
  });

  it('an in-flight transaction on a pending ceremony is still a hold (next-step), not an error', async () => {
    const a = await make();
    const h = handlersWith(a, 'inFlight');
    const r = await handle(h, CEREMONY_PROPOSE_WIRE_TYPE, base(a, A, CEREMONY_PROPOSE_WIRE_TYPE, fresh(), { name: 'Pair', kind: 'vtc', threshold: 2, adminDids: [A.did, X.did] }), ctxFor(a, A));
    assert.equal((r as { type: string }).type, NEXT_STEP_TYPE_URI);
  });
});

describe('ceremony-doc: retained documents and registration', () => {
  it('the request is kept verbatim with the verified signer, and the signed reply as sent', async () => {
    const a = await make();
    const t = fresh();
    const signed = begin(a, A, t) as Record<string, unknown>;
    // The same document with different whitespace and member order than any re-serialisation would give.
    const verbatim = `{ "payload" : ${JSON.stringify(signed.payload)} ,\n "proof": ${JSON.stringify(signed.proof)},\n "id":${JSON.stringify(signed.id)}, "threadId":${JSON.stringify(t)}, "type":${JSON.stringify(signed.type)}, "issuer":${JSON.stringify(signed.issuer)}, "recipient":${JSON.stringify(signed.recipient)}, "issuedAt":${JSON.stringify(signed.issuedAt)} }`;
    assert.notEqual(verbatim, JSON.stringify(signed));
    const reply = await send(a, verbatim);
    assert.equal(reply.type, NEXT_STEP_TYPE_URI);
    const kept = (await a.retained.byId(signed.id as string))!;
    assert.equal(kept.verbatim, verbatim, 'the bytes received, not a re-serialisation');
    assert.equal(kept.verifiedSigner, A.did);
    assert.equal(kept.direction, 'request');
    assert.equal(kept.threadId, t);
    const out = (await a.retained.replyTo(signed.id as string))!;
    assert.equal(out.direction, 'response');
    assert.equal(out.inReplyTo, signed.id);
    assert.deepEqual(JSON.parse(out.verbatim!), reply, 'the reply exactly as sent, proof included');
    const thread = await a.retained.byThread(t);
    // rows of one second order by id, so compare as a set
    assert.deepEqual(thread.map((d) => d.direction).sort(), ['request', 'response']);
    assert.equal(await a.retained.byId(uid(99999)), null);
  });

  it('declares exactly the four ceremony wire types, and none with ceremony off; no trigger action was added', async () => {
    const a = await make();
    const caps = await a.capabilities();
    for (const t of CEREMONY_WIRE_TYPES) assert.ok(caps.supportedTypes.includes(t), t);
    assert.equal(CEREMONY_WIRE_TYPES.length, 4);
    const off = await new VrcBoundaryAdapter({ ceremony: false, attested: true }).init();
    adapters.push(off);
    await off.setClock(START);
    for (const t of CEREMONY_WIRE_TYPES) assert.ok(!(await off.capabilities()).supportedTypes.includes(t));
    await assert.rejects(a.trigger('ceremony', {}), /unknown trigger/);
    const unserved = await send(off, begin(off, A, fresh()));
    assert.equal(unserved.payload.code, 'unsupportedType');
  });
});
