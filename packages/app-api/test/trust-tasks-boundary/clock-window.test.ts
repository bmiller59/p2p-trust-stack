// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Suite increment I1 contract (docs/04 sections 6 and 7): the adapter declares exactly one clock capability
 * (`clock`, it has an injectable clock) and the acceptance window it enforces (`capabilities.window`), which must equal
 * the pins, the window the discovery answer states and the window the pipeline really applies. The run salt is
 * a runner-side matter (it is mixed into the ids of the documents the harness builds); the adapter needs nothing for it.
 */
import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { ACCEPTANCE_WINDOW } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pins.js';
import { windowSeconds } from '@p2p-trust-stack/core/services/trust-tasks/boundary/discovery.js';
import { VrcBoundaryAdapter } from './vrc-adapter.ts';
import { X, clock, sign, text, uid, useClock } from './witness-bundle.ts';

const adapters: VrcBoundaryAdapter[] = [];
after(() => adapters.forEach((a) => a.dispose()));
const START = '2026-11-12T10:00:00Z';
const make = async (opts: ConstructorParameters<typeof VrcBoundaryAdapter>[0] = {}) => {
  useClock(START);
  const a = await new VrcBoundaryAdapter({ attested: true, ...opts }).init();
  await a.setClock(START);
  adapters.push(a);
  return a;
};
const iso = (ms: number): string => new Date(ms).toISOString().replace('.000Z', 'Z');
let seq = 900;
/** A consequential carrier document with the given age at the current clock. */
const aged = async (a: VrcBoundaryAdapter, ageMs: number) => {
  const carrier = (await a.capabilities()).carriers[0]!;
  return sign(X, { id: uid(seq++), threadId: uid(seq++), type: carrier.typeUri, issuer: X.did, recipient: a.signer.did, issuedAt: iso(clock.ms - ageMs), payload: carrier.validPayload });
};
const codeOf = async (a: VrcBoundaryAdapter, doc: unknown): Promise<string | undefined> => {
  const r = await a.send({ from: { kind: 'actor', vid: X.did }, bytes: text(doc) });
  const reply = r.replies[0] === undefined ? undefined : (JSON.parse(r.replies[0]) as { type: string; payload: { code?: string } });
  return reply?.payload.code;
};

describe('capabilities: clock and window (suite I1 contract)', () => {
  it('declares clock, never clockFree, in either server mode', async () => {
    for (const attested of [true, false]) {
      const caps = await (await make({ attested })).capabilities();
      assert.ok(caps.optional.includes('clock'));
      assert.ok(!caps.optional.includes('clockFree'));
    }
  });

  it('declares the window the pins state: 300 s maximum age, 60 s skew, 30 days horizon', async () => {
    const caps = await (await make()).capabilities();
    assert.deepEqual(caps.window, { maxAgeSeconds: 300, clockSkewSeconds: 60, expiryHorizonSeconds: 30 * 24 * 3600 });
  });

  it('the declared window is the discovery answer\'s window (one source, never wider than enforced)', async () => {
    const caps = await (await make()).capabilities();
    assert.deepEqual(caps.window, windowSeconds(ACCEPTANCE_WINDOW));
  });

  it('the pipeline enforces the declared window: documents up to maximum age plus skew are accepted, one second past it is expired', async () => {
    const a = await make({ carrier: 'widget' });
    const w = (await a.capabilities()).window!;
    const max = w.maxAgeSeconds * 1000;
    const got = [];
    const skew = w.clockSkewSeconds * 1000;
    for (const age of [max, max + skew - 1000, max + skew + 1000]) got.push(await codeOf(a, await aged(a, age)));
    assert.deepEqual(got, [undefined, undefined, 'expired']);
  });
});
