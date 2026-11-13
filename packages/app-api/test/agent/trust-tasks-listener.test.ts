// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P6c: a real agent (real libp2p start, temp registry) runs the Trust Task listener only
 * when opted in, on its own loopback port, answers as its connection DID, and takes the listener down
 * with the agent. Without the option nothing listens.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { Agent } from '../../src/runtime/agent.js';
import { AgentRegistry } from '../../src/runtime/agent-registry.js';

const dirs: string[] = [];
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

function registry(): AgentRegistry {
  const dir = mkdtempSync(join(tmpdir(), 'p6-agent-'));
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

test('the agent serves no Trust Task listener unless opted in', { timeout: 120_000 }, async () => {
  assert.equal(process.env.TRUST_TASKS_LISTENER, undefined);
  const port = await freePort();
  const agent = await Agent.create({ name: 'p6-off', passphrase: 'test-pass-off' }, registry());
  await agent.start();
  try {
    await assert.rejects(() => post(port, {}), /fetch failed/);
  } finally {
    await agent.stop();
  }
});

test('opted in: the agent listens on its own port, answers as its connection DID, and stops with the agent', { timeout: 120_000 }, async () => {
  const port = await freePort();
  const agent = await Agent.create({ name: 'p6-on', passphrase: 'test-pass-on', trustTasksListener: { enabled: true, port, host: '127.0.0.1' } }, registry());
  await agent.start();
  let stopped = false;
  try {
    const doc = (recipient: string) => ({
      id: 'urn:uuid:ffffffff-ffff-4fff-8fff-000000000001', threadId: 'urn:uuid:ffffffff-ffff-4fff-8fff-000000000001',
      type: 'https://trusttasks.org/spec/vrc/relationships/propose/0.1', issuer: 'did:key:z6MkUnknownPeer', recipient,
      issuedAt: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z'),
      payload: { relationshipDid: 'did:key:z6MkTheirRelationship' },
    });
    // Addressed to somebody else: the agent says so, and in doing so names the identifier it answers as.
    const probe = (await (await post(port, doc('did:key:z6MkNotThisAgent'))).json()) as { issuer: string; payload: { code: string } };
    assert.equal(probe.payload.code, 'wrongRecipient');
    const did = probe.issuer;
    assert.match(did, /^did:/);
    // An unsigned document at the attested tier: refused for want of a proof, by the agent, as the agent.
    const res = await post(port, doc(did));
    const reply = (await res.json()) as { issuer: string; payload: { code: string }; proof?: unknown };
    assert.equal(reply.payload.code, 'proofRequired');
    assert.equal(reply.issuer, did);
    assert.ok(reply.proof, 'the refusal is signed by the agent');
    // Not on any other path.
    assert.equal((await fetch(`http://127.0.0.1:${port}/api/agents`)).status, 404);
    await agent.stop();
    stopped = true;
    await assert.rejects(() => post(port, {}), /fetch failed/);
  } finally {
    if (!stopped) await agent.stop();
  }
});
