// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/** HttpRotationLogSource bounds (conformance P4): a timeout on the fetch and a cap on the body. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpRotationLogSource } from '../../src/did/rotation-log-source.js';

const DID = 'did:scid:vh:1:zQmExample';

test('passes an abort signal that fires after timeoutMs', async () => {
  let signal: AbortSignal | undefined;
  const fetchFn = (async (_url: unknown, init?: RequestInit) => {
    signal = init?.signal ?? undefined;
    return new Response('[]', { status: 200 });
  }) as typeof fetch;
  await new HttpRotationLogSource({ endpoint: 'http://x', fetchFn, timeoutMs: 50 }).getLog(DID);
  assert.ok(signal, 'a signal is passed');
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(signal!.aborted, true);
});

test('a response over maxBytes is refused, by declared length and by actual size', async () => {
  const declared = (async () => new Response('[]', { status: 200, headers: { 'content-length': '5000' } })) as unknown as typeof fetch;
  await assert.rejects(new HttpRotationLogSource({ endpoint: 'http://x', fetchFn: declared, maxBytes: 1000 }).getLog(DID), /exceeds/);
  const actual = (async () => new Response(JSON.stringify({ log: [], pad: 'x'.repeat(2000) }), { status: 200 })) as unknown as typeof fetch;
  await assert.rejects(new HttpRotationLogSource({ endpoint: 'http://x', fetchFn: actual, maxBytes: 1000 }).getLog(DID), /exceeds/);
  const fine = (async () => new Response('[]', { status: 200 })) as unknown as typeof fetch;
  assert.deepEqual(await new HttpRotationLogSource({ endpoint: 'http://x', fetchFn: fine, maxBytes: 1000 }).getLog(DID), []);
});
