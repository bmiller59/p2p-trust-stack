// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers


/**
 * Gate G2 wiring in the agent runtime. Default off: with the gate unset the listener signs as #key-1
 * exactly as before. Dedicated mode: fails closed (no listener, no signer) when the key is missing or
 * unpublished or the identifier is a did:peer:4, and signs with #key-boundary once provisioned and
 * published through the document-update path.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, afterEach, test } from 'node:test';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { getBoundarySigner, setBoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { Agent } from '../../src/runtime/agent.js';
import { AgentRegistry } from '../../src/runtime/agent-registry.js';

const dirs: string[] = [];
const saved = { key: process.env.TRUST_TASKS_BOUNDARY_KEY, cut: process.env.BOUNDARY_KEY_CUTOVER_AT, gen: process.env.BOUNDARY_KEY_GENERATION };
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));
afterEach(() => {
  for (const [k, v] of [['TRUST_TASKS_BOUNDARY_KEY', saved.key], ['BOUNDARY_KEY_CUTOVER_AT', saved.cut], ['BOUNDARY_KEY_GENERATION', saved.gen]] as const) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  setBoundarySigner(undefined);
});

function registry(): AgentRegistry {
  const dir = mkdtempSync(join(tmpdir(), 'g2-agent-'));
  dirs.push(dir);
  return new AgentRegistry(undefined, undefined, dir);
}
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });
}
const post = (port: number, body: unknown) =>
  fetch(`http://127.0.0.1:${port}/trust-tasks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
const unsigned = (recipient: string) => ({
  id: 'urn:uuid:ffffffff-ffff-4fff-8fff-000000000001', threadId: 'urn:uuid:ffffffff-ffff-4fff-8fff-000000000001',
  type: 'https://trusttasks.org/spec/vrc/relationships/propose/0.1', issuer: 'did:key:z6MkUnknownPeer', recipient,
  issuedAt: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z'),
  payload: { relationshipDid: 'did:key:z6MkTheirRelationship' },
});
async function replyVm(port: number): Promise<string> {
  const probe = (await (await post(port, unsigned('did:key:z6MkNotThisAgent'))).json()) as { issuer: string; proof?: { verificationMethod: string } };
  assert.ok(probe.proof, 'the refusal is signed');
  return probe.proof.verificationMethod;
}
const dedicatedEnv = () => {
  process.env.TRUST_TASKS_BOUNDARY_KEY = 'dedicated';
  process.env.BOUNDARY_KEY_CUTOVER_AT = new Date(Date.now() - 60_000).toISOString();
};

test('DEFAULT OFF: with the gate unset the listener signs as #key-1, and the keystore holds no boundary key', { timeout: 120_000 }, async () => {
  delete process.env.TRUST_TASKS_BOUNDARY_KEY;
  const port = await freePort();
  const agent = await Agent.create({ name: 'g2-off', passphrase: 'test-pass-g2', trustTasksListener: { enabled: true, port, host: '127.0.0.1' } }, registry());
  await agent.start();
  try {
    assert.match(await replyVm(port), /#key-1$/);
    assert.equal(getBoundarySigner()?.at, undefined, 'the plain #key-1 signer, no cutover hook');
  } finally {
    await agent.stop();
  }
});

test('FAILS CLOSED: dedicated mode with no provisioned key starts no listener and installs no signer', { timeout: 120_000 }, async () => {
  const port = await freePort();
  dedicatedEnv();
  const agent = await Agent.create({ name: 'g2-nokey', passphrase: 'test-pass-g2', didMethod: new ScidVhMethod({}), trustTasksListener: { enabled: true, port, host: '127.0.0.1' } }, registry());
  await agent.start();
  try {
    await assert.rejects(() => post(port, {}), /fetch failed/);
    assert.equal(getBoundarySigner(), undefined, 'no #key-1 fallback signer');
  } finally {
    await agent.stop();
  }
});

test('FAILS CLOSED: a did:peer:4 agent cannot gain the key in place, so dedicated mode refuses it', { timeout: 120_000 }, async () => {
  const port = await freePort();
  dedicatedEnv();
  const agent = await Agent.create({ name: 'g2-peer4', passphrase: 'test-pass-g2', trustTasksListener: { enabled: true, port, host: '127.0.0.1' } }, registry());
  await agent.start();
  try {
    await assert.rejects(() => post(port, {}), /fetch failed/);
    assert.equal(getBoundarySigner(), undefined);
  } finally {
    await agent.stop();
  }
});

test('FAILS CLOSED: a bad gate value (typo, missing cutover) refuses the listener instead of running on #key-1', { timeout: 120_000 }, async () => {
  const port = await freePort();
  process.env.TRUST_TASKS_BOUNDARY_KEY = 'dedicate';
  delete process.env.BOUNDARY_KEY_CUTOVER_AT;
  const agent = await Agent.create({ name: 'g2-typo', passphrase: 'test-pass-g2', didMethod: new ScidVhMethod({}), trustTasksListener: { enabled: true, port, host: '127.0.0.1' } }, registry());
  await agent.start();
  try {
    await assert.rejects(() => post(port, {}), /fetch failed/);
    assert.equal(getBoundarySigner(), undefined);
  } finally {
    await agent.stop();
  }
});

test('provision, publish, then dedicated mode signs with #key-boundary; a rotation not yet moved to fails closed; moving the generation recovers', { timeout: 240_000 }, async () => {
  const reg = registry();
  const cfg = (port: number) => ({ name: 'g2-live', passphrase: 'test-pass-g2', didMethod: new ScidVhMethod({}), trustTasksListener: { enabled: true, port, host: '127.0.0.1' } });
  let port = await freePort();
  delete process.env.TRUST_TASKS_BOUNDARY_KEY;
  let agent = await Agent.create(cfg(port), reg) as unknown as import('../../src/runtime/scid-vh-agent.js').ScidVhAgent;
  await agent.start();
  const first = await agent.provisionBoundaryKey(1);
  await assert.rejects(() => agent.provisionBoundaryKey(1), /exists/);
  const entry = await agent.publishBoundaryKey(1);
  assert.ok(entry.didDocument.verificationMethod.some((v) => v.id === '#key-boundary'));
  assert.match(await replyVm(port), /#key-1$/, 'gate still off: still #key-1 even though the key is published');
  await agent.stop();

  dedicatedEnv();
  port = await freePort();
  agent = await Agent.unlock(cfg(port), reg) as unknown as typeof agent;
  await agent.start();
  assert.match(await replyVm(port), /#key-boundary$/);
  // Rotate: publish generation 2, but the process still selects generation 1 on its next start.
  await agent.provisionBoundaryKey(2);
  await agent.publishBoundaryKey(2);
  await agent.stop();
  port = await freePort();
  agent = await Agent.unlock(cfg(port), reg) as unknown as typeof agent;
  await agent.start();
  await assert.rejects(() => post(port, {}), /fetch failed/, 'published key is generation 2, process holds generation 1: refused');
  await agent.stop();
  process.env.BOUNDARY_KEY_GENERATION = '2';
  port = await freePort();
  agent = await Agent.unlock(cfg(port), reg) as unknown as typeof agent;
  await agent.start();
  try {
    assert.match(await replyVm(port), /#key-boundary$/);
    assert.notEqual(first.fingerprint, undefined);
  } finally {
    await agent.stop();
  }
});
