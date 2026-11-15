// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Item 2A (decisions 68, 37): who may see and decide a held proposal. Only the participant the proposal was
 * addressed to (the local identity that holds the exchange row) lists it or decides it; any other service over
 * the same database, and any id that is not theirs, gets exactly the answer an unknown id gets, so nothing
 * leaks the existence of a proposal. The held list also carries the lapse deadline (seven days from the first
 * hold; decision 37) so a screen can show it.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { VrcBoundaryAdapter, PASSPHRASE } from './vrc-adapter.ts';
import { VrcProposeService } from '../../src/runtime/trust-tasks-boundary/vrc-propose.ts';
import { signDocument, createEd25519BoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { ed25519 } from '@noble/curves/ed25519.js';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));

const PROPOSE = 'https://trusttasks.org/spec/vrc/relationships/propose/0.1';
const NOW = '2026-11-12T10:00:00Z';
const DAY = 24 * 60 * 60 * 1000;
const actor = (seedByte: number) => {
  const seed = new Uint8Array(32).fill(seedByte);
  const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
  return { did, signer: createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) }) };
};
const A = actor(0x0a), R = actor(0x0c);
const id = 'urn:uuid:dddddddd-dddd-4ddd-8ddd-000000000001';

async function held() {
  const adapter = await new VrcBoundaryAdapter({ attested: false }).init();
  adapters.push(adapter);
  await adapter.setClock(NOW);
  await adapter.trigger('policy', { propose: 'hold' });
  const doc = signDocument({ id, threadId: id, type: PROPOSE, issuer: A.did, recipient: adapter.signer.did, issuedAt: NOW, payload: { relationshipDid: R.did } }, A.signer, { created: Date.parse(NOW) });
  await adapter.send({ from: { kind: 'actor', vid: A.did }, bytes: JSON.stringify(doc) });
  return adapter;
}
const rejection = async (p: Promise<unknown>): Promise<string> => {
  try { await p; } catch (e) { return `${(e as { reason?: string }).reason}|${(e as Error).message}`; }
  return 'resolved';
};

describe('held proposals: authorisation and deadline (item 2A)', () => {
  it('the participant the proposal was addressed to lists it, with a deadline seven days after the first hold', async () => {
    const adapter = await held();
    const [row] = await adapter.propose.listHeld();
    assert.equal(row?.exchangeId, id);
    assert.equal(adapter.propose.lapsePeriodMs, 7 * DAY);
    assert.equal(row!.createdAt + adapter.propose.lapsePeriodMs, Date.parse(NOW) + 7 * DAY);
  });

  it('another local identity over the same database lists nothing and decides nothing, with the unknown-id answer', async () => {
    const adapter = await held();
    const other = new VrcProposeService({ db: adapter.db, localIdentityUuid: 'not-the-recipient', passphrase: PASSPHRASE, now: () => Date.parse(NOW) });
    assert.deepEqual(await other.listHeld(), []);
    const unknown = await rejection(other.decide('urn:uuid:00000000-0000-4000-8000-000000000000', 'accept'));
    const foreign = await rejection(other.decide(id, 'accept'));
    assert.equal(foreign, unknown, 'a proposal that is not yours answers exactly as an unknown id');
    assert.match(foreign, /notFound/);
    // and it was not decided: the owner still sees it held
    assert.equal((await adapter.propose.listHeld()).length, 1);
  });
});
