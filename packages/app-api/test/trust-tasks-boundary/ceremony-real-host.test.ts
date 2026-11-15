// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Item 1 (D1.1 to D1.3) through the REAL pipeline: the ceremony documents run against the production host effect
 * (`ceremonyHost: 'real'`: the real `createVtc`, the crystallization policy, check at prepare, apply at commit) instead of
 * the fixture. A boundary co-sign counts as an approval by its pipeline-verified document proof; a forged one never reaches
 * the ceremony; the legacy path is a different participant and is not touched here.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_PROPOSE_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-spec.js';
import { NEXT_STEP_TYPE_URI } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { VrcBoundaryAdapter } from './vrc-adapter.ts';
import { A, X, clock, sign, text, uid, useClock } from './witness-bundle.ts';
import type { Party } from './witness-bundle.ts';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));
const START = '2026-11-12T10:00:00Z';
const make = async () => {
  useClock(START);
  const a = await new VrcBoundaryAdapter({ attested: true, ceremonyHost: 'real' }).init();
  await a.setClock(START);
  adapters.push(a);
  return a;
};
let seq = 500;
const fresh = () => uid(seq++);
type Reply = { type: string; payload: Record<string, any> };
const send = async (a: VrcBoundaryAdapter, doc: unknown, from: Party): Promise<Reply> =>
  JSON.parse((await a.send({ from: { kind: 'actor', vid: from.did }, bytes: text(doc) })).replies[0]!);
const base = (a: VrcBoundaryAdapter, who: Party, type: string, thread: string, payload: Record<string, unknown>, id = fresh()) =>
  ({ id, threadId: thread, type, issuer: who.did, recipient: a.signer.did, issuedAt: clock.iso, payload });
const begin = (a: VrcBoundaryAdapter, who: Party, thread: string, name = 'Real Founders') =>
  sign(who, base(a, who, CEREMONY_PROPOSE_WIRE_TYPE, thread, { name, kind: 'vtc', threshold: 2, adminDids: [A.did, X.did] }));
const cosign = (a: VrcBoundaryAdapter, who: Party, thread: string, id = fresh()) => sign(who, base(a, who, CEREMONY_CO_SIGN_WIRE_TYPE, thread, {}, id));
const approvals = async (a: VrcBoundaryAdapter, id: string) => (await a.ceremony.store.getApprovals(id)).length;
const rows = (a: VrcBoundaryAdapter, sql: string) => a.db.all<Record<string, unknown>>(sql);

describe('ceremony documents against the real host effect', () => {
  it('a quorum of co-sign documents creates exactly one real community with both founding admins and their VMCs', async () => {
    const a = await make();
    const t = fresh();
    assert.equal((await send(a, begin(a, A, t), A)).type, NEXT_STEP_TYPE_URI);
    assert.equal((await send(a, cosign(a, A, t), A)).type, NEXT_STEP_TYPE_URI);
    assert.equal(await a.communityCount(), 0);
    const last = await send(a, cosign(a, X, t), X);
    assert.equal(last.type, `${CEREMONY_CO_SIGN_WIRE_TYPE}#response`);
    assert.equal(last.payload.status, 'crystallized');
    assert.equal(await a.communityCount(), 1);
    const founders = await rows(a, "SELECT m.role AS role, m.membership_credential_uuid AS vmc FROM memberships m JOIN identities c ON c.uuid = m.community_identity_uuid WHERE c.role = 'vtc'");
    assert.equal(founders.length, 2);
    assert.ok(founders.every((f) => f.role === 'founding_admin' && f.vmc !== null));
    assert.equal(await approvals(a, t), 2);
  });

  it('D1.1: the approval is the pipeline-verified document proof; a co-sign whose proof does not verify never counts', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t), A);
    await send(a, cosign(a, A, t), A);
    // X's co-sign with its id changed after signing (a valid document otherwise): the pipeline refuses it, the ceremony never sees it.
    const forged = await send(a, { ...cosign(a, X, t), id: fresh() }, X);
    assert.equal(forged.payload.code, 'proofInvalid');
    assert.equal(await approvals(a, t), 1);
    assert.equal(await a.communityCount(), 0);
    // A co-sign signed by A and re-addressed as issued by X is refused too: the proof covers the issuer.
    const impostor = await send(a, { ...cosign(a, A, t), issuer: X.did }, X);
    assert.equal(impostor.payload.code, 'proofInvalid');
    assert.equal(await approvals(a, t), 1);
    // The genuine one counts, and the stored approval is that document's proof value.
    assert.equal((await send(a, cosign(a, X, t), X)).payload.status, 'crystallized');
    const stored = await a.ceremony.store.getApprovals(t);
    assert.equal(stored.length, 2);
    assert.ok(stored.every((s) => s.signature.length > 0));
    assert.equal(await a.communityCount(), 1);
  });

  it('replay: the same co-sign delivered again and a second approval by the same admin create nothing more', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t), A);
    await send(a, cosign(a, A, t), A);
    const doc = cosign(a, X, t);
    const first = await send(a, doc, X);
    const again = await send(a, doc, X);
    assert.equal(again.type, first.type);
    await send(a, cosign(a, X, t), X);
    assert.equal(await a.communityCount(), 1);
    assert.equal(await approvals(a, t), 2);
  });

  it('a name that is taken refuses the second ceremony (nameTaken), leaves one community and a failed ceremony', async () => {
    const a = await make();
    const t1 = fresh();
    await send(a, begin(a, A, t1, 'Same Name'), A);
    await send(a, cosign(a, A, t1), A);
    await send(a, cosign(a, X, t1), X);
    const t2 = fresh();
    await send(a, begin(a, A, t2, 'same name'), A);
    await send(a, cosign(a, A, t2), A);
    const refused = await send(a, cosign(a, X, t2), X);
    assert.equal(refused.payload.details?.reason, 'nameTaken');
    assert.equal(await a.communityCount(), 1);
    assert.equal((await a.ceremony.store.getProposal(t2))!.status, 'failed');
  });

  it('a restart between the co-signs loses nothing: the ceremony finishes on the new process and creates one community', async () => {
    const a = await make();
    const t = fresh();
    await send(a, begin(a, A, t), A);
    await send(a, cosign(a, A, t), A);
    await a.restart();
    assert.equal((await send(a, cosign(a, X, t), X)).payload.status, 'crystallized');
    assert.equal(await a.communityCount(), 1);
  });
});
