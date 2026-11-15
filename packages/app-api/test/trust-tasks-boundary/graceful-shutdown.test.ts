// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers


/** The listener's close is graceful: a request being answered finishes, new connections are refused afterwards. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startBoundaryListener } from '../../src/runtime/trust-tasks-boundary/listener.ts';

test('close() lets an in-flight request finish, then refuses new connections', async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const listener = await startBoundaryListener({
    host: '127.0.0.1', port: 0,
    process: async () => { await gate; return { status: 200, document: { ok: true } } as never; },
  });
  const url = `http://127.0.0.1:${listener.port}/trust-tasks`;
  const inflight = fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  await new Promise((r) => setTimeout(r, 100));
  const closing = listener.close();
  await new Promise((r) => setTimeout(r, 100));
  release();
  const res = await inflight;
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
  await closing;
  await assert.rejects(() => fetch(url, { method: 'POST', body: '{}' }), /fetch failed/);
});

test('close() cuts a request that outlives the grace period', async () => {
  const listener = await startBoundaryListener({
    host: '127.0.0.1', port: 0, graceMs: 100,
    process: () => new Promise(() => undefined),
  });
  const inflight = fetch(`http://127.0.0.1:${listener.port}/trust-tasks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  inflight.catch(() => undefined);
  await new Promise((r) => setTimeout(r, 50));
  const t0 = Date.now();
  await listener.close();
  assert.ok(Date.now() - t0 < 3_000);
});
