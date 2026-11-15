// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * K8 (decision 68, D6.2): a NEW did:peer:4 agent gets the dedicated `#key-boundary` key at creation, opt-in
 * (`dedicatedBoundaryKey`); with the option off nothing changes. Which class an agent is: no `didMethod` means
 * `ScidVhAgent` (did:scid:vh), so a did:peer:4 agent exists only when a non-rotating method is passed.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, afterEach, test } from 'node:test';
import { DidPeer4Method } from '@p2p-trust-stack/core/did/did-peer4-method.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { loadBoundaryKey } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import { getBoundarySigner, setBoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { Agent } from '../../src/runtime/agent.js';
import { Peer4Agent } from '../../src/runtime/peer4-agent.js';
import { AgentRegistry } from '../../src/runtime/agent-registry.js';

const PASS = 'test-pass-k8-peer4';
const dirs: string[] = [];
const saved = { key: process.env.TRUST_TASKS_BOUNDARY_KEY, cut: process.env.BOUNDARY_KEY_CUTOVER_AT };
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));
afterEach(() => {
  for (const [k, v] of [['TRUST_TASKS_BOUNDARY_KEY', saved.key], ['BOUNDARY_KEY_CUTOVER_AT', saved.cut]] as const) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  setBoundarySigner(undefined);
});
const registry = (): AgentRegistry => { const d = mkdtempSync(join(tmpdir(), 'k8-agent-')); dirs.push(d); return new AgentRegistry(undefined, undefined, d); };
const freePort = (): Promise<number> => new Promise((res, rej) => { const s = createServer(); s.once('error', rej); s.listen(0, '127.0.0.1', () => { const { port } = s.address() as { port: number }; s.close(() => res(port)); }); });
const ids = (a: { getDidDocument?: () => unknown } | { identity?: unknown }): string[] => ((a as unknown as { identity: { didDocument: { verificationMethod: Array<{ id: string }> } } }).identity.didDocument.verificationMethod).map((v) => v.id);

test('no didMethod is a did:scid:vh agent (ScidVhAgent), not did:peer:4: peer:4 needs a non-rotating method passed in', async () => {
  const a = await Agent.create({ name: 'k8-default', passphrase: PASS }, registry());
  assert.match(a.getDid(), /^did:scid:vh:/);
  assert.ok(!(a instanceof Peer4Agent));
  await a.stop();
});

test('DEFAULT OFF: a did:peer:4 agent has no #key-boundary and the keystore holds no boundary key', async () => {
  const reg = registry();
  const a = await Agent.create({ name: 'k8-off', passphrase: PASS, didMethod: new DidPeer4Method() }, reg);
  assert.match(a.getDid(), /^did:peer:4/);
  assert.ok(!ids(a as never).includes('#key-boundary'));
  const ks = new SqliteKeyStore(reg.getKeystorePath('k8-off'));
  try { await assert.rejects(() => loadBoundaryKey({ store: ks, vid: a.getDid(), passphrase: PASS, generation: 1 }), /missing/); } finally { ks.close(); }
  await a.stop();
});

test('OPT IN: the new did:peer:4 agent publishes #key-boundary from creation, holds the key in custody, and keeps it in the transport copy', async () => {
  const reg = registry();
  const a = await Agent.create({ name: 'k8-on', passphrase: PASS, didMethod: new DidPeer4Method(), dedicatedBoundaryKey: true }, reg);
  assert.ok(a instanceof Peer4Agent);
  assert.deepEqual(ids(a as never).slice(0, 2), ['#key-1', '#key-2']);
  assert.ok(ids(a as never).includes('#key-boundary'));
  const ks = new SqliteKeyStore(reg.getKeystorePath('k8-on'));
  let pub: Uint8Array;
  try { pub = (await loadBoundaryKey({ store: ks, vid: a.getDid(), passphrase: PASS, generation: 1 })).publicKey; } finally { ks.close(); }
  assert.equal(pub.length, 32);
  const withTransport = (a as unknown as { buildDidDocumentWithTransport(p: { peerId: string; multiaddrs: string[] }): { verificationMethod: Array<{ id: string }>; authentication: string[] } }).buildDidDocumentWithTransport({ peerId: 'p', multiaddrs: [] });
  assert.ok(withTransport.verificationMethod.some((v) => v.id === '#key-boundary'), 'a rebuild must not drop the key');
  assert.ok(withTransport.authentication.includes('#key-boundary'));
  // the key is part of the hashed identifier, so an unlock (which resolves the DID offline) sees it too
  assert.ok(new DidPeer4Method().resolve(a.getDid()).verificationMethod.some((v) => v.id === '#key-boundary'));
});

test('OPT IN, dedicated mode: the listener of a new did:peer:4 agent signs with #key-boundary', { timeout: 120_000 }, async () => {
  process.env.TRUST_TASKS_BOUNDARY_KEY = 'dedicated';
  process.env.BOUNDARY_KEY_CUTOVER_AT = new Date(Date.now() - 60_000).toISOString();
  const port = await freePort();
  const a = await Agent.create({ name: 'k8-live', passphrase: PASS, didMethod: new DidPeer4Method(), dedicatedBoundaryKey: true, trustTasksListener: { enabled: true, port, host: '127.0.0.1' } }, registry());
  await a.start();
  try {
    assert.ok(getBoundarySigner(), 'the dedicated signer is installed: the document publishes the key we hold');
    assert.ok(typeof getBoundarySigner()!.at === 'function', 'cutover signer present');
  } finally {
    await a.stop();
  }
});
