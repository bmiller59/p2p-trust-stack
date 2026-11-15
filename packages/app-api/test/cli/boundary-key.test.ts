// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The agent-side operator CLI for the dedicated #key-boundary key: provision, publish, rotate, retire,
 * destroy, status, over real did:scid:vh agents (real keystore and rotation log in a temp P2PTS_HOME).
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { Agent } from '../../src/runtime/agent.js';
import { Peer4Agent } from '../../src/runtime/peer4-agent.js';
import { AgentRegistry } from '../../src/runtime/agent-registry.js';
import { parseAgentArgs, runAgentCli } from '../../src/cli/boundary-key.js';

const PASS = 'test-pass-cli-not-a-secret';
const dirs: string[] = [];
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

async function setup(name: string, scid = true) {
  const dir = mkdtempSync(join(tmpdir(), 'g2-cli-'));
  dirs.push(dir);
  const registry = new AgentRegistry(undefined, undefined, dir);
  const config = { name, passphrase: PASS, trustTasksListener: { enabled: false } };
  const agent = scid ? await Agent.create({ ...config, didMethod: new ScidVhMethod({}) }, registry) : await Peer4Agent.create(config, registry);
  await agent.start();
  await agent.stop();
  const run = async (argv: string[], env: Record<string, string | undefined> = { P2PTS_AGENT_PASSPHRASE: PASS }) => {
    const out: string[] = []; const err: string[] = [];
    const code = await runAgentCli(argv, env, (l) => out.push(l), (l) => err.push(l), { registry });
    return { code, out, err, json: out.length > 0 ? JSON.parse(out[0]!) : undefined };
  };
  return { registry, run };
}

test('argument parsing is strict; the passphrase is never an argument', () => {
  assert.deepEqual(parseAgentArgs(['publish', '--agent', 'a', '--generation', '2', '--execute']), { command: 'publish', agent: 'a', generation: 2, execute: true });
  assert.deepEqual(parseAgentArgs(['status', '--agent', 'a']), { command: 'status', agent: 'a', execute: false });
  for (const bad of [[], ['nope'], ['status'], ['publish', '--agent', 'a'], ['status', '--agent', 'a', '--generation', '1'], ['publish', '--agent', 'a', '--generation', '0'], ['provision', '--agent', 'a', '--generation', '1', '--passphrase', 'x'], ['status', '--agent']]) {
    assert.throws(() => parseAgentArgs(bad), Error, JSON.stringify(bad));
  }
});

test('refuses without the passphrase, for an unknown agent, and for a did:peer:4 agent', { timeout: 120_000 }, async () => {
  const s = await setup('cli-pass');
  const none = await s.run(['status', '--agent', 'cli-pass'], {});
  assert.equal(none.code, 1);
  assert.match(none.err[0]!, /P2PTS_AGENT_PASSPHRASE is required/);
  assert.deepEqual(none.out, []);
  const unknown = await s.run(['status', '--agent', 'nobody']);
  assert.equal(unknown.code, 1);
  assert.match(unknown.err[0]!, /not found/);
  const wrong = await s.run(['status', '--agent', 'cli-pass'], { P2PTS_AGENT_PASSPHRASE: 'wrong-passphrase' });
  assert.equal(wrong.code, 1, 'a wrong passphrase fails closed');
  const peer = await setup('cli-peer4', false);
  for (const cmd of [['provision', '--generation', '1', '--execute'], ['publish', '--generation', '1', '--execute'], ['status']]) {
    const r = await peer.run([...cmd, '--agent', 'cli-peer4']);
    assert.equal(r.code, 1, cmd[0]);
    assert.match(r.err[0]!, /^refused: /);
    assert.deepEqual(r.out, []);
  }
});

test('dry run is the default; provision never overwrites; publish, rotate, retire, destroy follow the runbook', { timeout: 240_000 }, async () => {
  const s = await setup('cli-live');
  const A = ['--agent', 'cli-live'];
  const st0 = await s.run(['status', ...A]);
  assert.equal(st0.json.published, null);
  assert.deepEqual(st0.json.generationsHeld, []);

  assert.equal((await s.run(['provision', ...A, '--generation', '1'])).json.executed, false);
  assert.deepEqual((await s.run(['status', ...A])).json.generationsHeld, [], 'a dry run provisions nothing');
  const prov1 = await s.run(['provision', ...A, '--generation', '1', '--execute']);
  assert.equal(prov1.code, 0, prov1.err.join('\n'));
  assert.match(prov1.json.fingerprint, /^[0-9a-f]{16}$/);
  assert.equal((await s.run(['provision', ...A, '--generation', '1', '--execute'])).code, 1, 'never overwritten');
  assert.equal((await s.run(['provision', ...A, '--generation', '1'])).code, 1);
  assert.equal((await s.run(['provision', ...A, '--generation', '2', '--execute'])).code, 0);

  assert.equal((await s.run(['rotate', ...A, '--generation', '2', '--execute'])).code, 1, 'rotate needs a first publication');
  const dry = await s.run(['publish', ...A, '--generation', '1']);
  assert.equal(dry.code, 0, dry.err.join('\n'));
  assert.equal(dry.json.executed, false);
  assert.equal((await s.run(['status', ...A])).json.published, null, 'a dry run publishes nothing');
  const pub = await s.run(['publish', ...A, '--generation', '1', '--execute']);
  assert.equal(pub.code, 0, pub.err.join('\n'));
  const st1 = (await s.run(['status', ...A])).json;
  assert.equal(st1.published.generation, 1);
  assert.equal(st1.published.fingerprint, prov1.json.fingerprint);
  assert.equal((await s.run(['publish', ...A, '--generation', '2', '--execute'])).code, 1, 'publish is the first publication only');
  assert.equal((await s.run(['rotate', ...A, '--generation', '1', '--execute'])).code, 1, 'same generation is never re-published');
  assert.equal((await s.run(['rotate', ...A, '--generation', '3', '--execute'])).code, 1, 'an unprovisioned generation is missing');
  assert.equal((await s.run(['destroy', ...A, '--generation', '1', '--execute'])).code, 1, 'the published generation is not destroyed');

  assert.equal((await s.run(['rotate', ...A, '--generation', '2'])).json.executed, false);
  assert.equal((await s.run(['status', ...A])).json.published.generation, 1);
  const rot = await s.run(['rotate', ...A, '--generation', '2', '--execute']);
  assert.equal(rot.code, 0, rot.err.join('\n'));
  assert.match(rot.json.note, /BOUNDARY_KEY_GENERATION=2/);
  assert.equal((await s.run(['status', ...A])).json.published.generation, 2);

  assert.equal((await s.run(['retire', ...A])).json.executed, false);
  assert.equal((await s.run(['status', ...A])).json.published.generation, 2);
  assert.equal((await s.run(['retire', ...A, '--execute'])).code, 0);
  assert.equal((await s.run(['status', ...A])).json.published, null);
  assert.equal((await s.run(['retire', ...A, '--execute'])).code, 1, 'nothing left to retire');

  assert.equal((await s.run(['destroy', ...A, '--generation', '1'])).json.executed, false);
  assert.deepEqual((await s.run(['status', ...A])).json.generationsHeld, [1, 2]);
  assert.equal((await s.run(['destroy', ...A, '--generation', '1', '--execute'])).code, 0);
  assert.deepEqual((await s.run(['status', ...A])).json.generationsHeld, [2]);
});

test('no output carries key material, and the listener stays off whatever the environment says', { timeout: 120_000 }, async () => {
  const s = await setup('cli-quiet');
  const saved = process.env.TRUST_TASKS_LISTENER;
  process.env.TRUST_TASKS_LISTENER = '1';
  try {
    const A = ['--agent', 'cli-quiet'];
    const all: string[] = [];
    for (const argv of [['provision', ...A, '--generation', '1', '--execute'], ['publish', ...A, '--generation', '1', '--execute'], ['status', ...A]]) {
      const r = await s.run(argv);
      assert.equal(r.code, 0, r.err.join('\n'));
      all.push(...r.out, ...r.err);
    }
    const text = all.join('\n');
    assert.equal(text.includes(PASS), false);
    assert.equal(/secret|seed|mnemonic|privateKey/i.test(text), false);
    assert.equal(process.env.TRUST_TASKS_LISTENER, undefined, 'the CLI removes the switch from its own process');
  } finally {
    if (saved === undefined) delete process.env.TRUST_TASKS_LISTENER; else process.env.TRUST_TASKS_LISTENER = saved;
  }
});
