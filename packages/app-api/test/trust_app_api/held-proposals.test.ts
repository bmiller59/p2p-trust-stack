// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Item 2A (decisions 68, 37): the `relationships` domain's held-proposal list and decision (poll route plus an
 * SSE event, no push to the proposer), over a stub agent. Authorisation lives below this (see
 * `trust-tasks-boundary/held-proposals-authz.test.ts`); here: the DTO, the deadline, the events, the errors
 * (unknown, someone else's and not-held are one answer), and that a scoped context can neither read nor
 * subscribe.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRelationshipsApi } from '../../src/domains/relationships.ts';
import { EventBus } from '../../src/client/events.ts';
import { STACK_EVENTS } from '../../src/events/catalog.ts';
import { METHOD_CLASSIFICATION } from '../../src/client/scope.ts';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';

const DAY = 24 * 60 * 60 * 1000;
function fixture(agent: Record<string, unknown> | null) {
  const bus = new EventBus();
  const ctx = { host: {}, registry: {}, bus, getAgent: () => agent, setAgent: async () => {} } as never;
  const events: Array<[string, unknown]> = [];
  for (const e of ['proposal.held', 'proposal.changed'] as const) bus.on(e, (p: unknown) => events.push([e, p]));
  return { api: createRelationshipsApi(ctx), bus, events };
}
const row = (n: number, t: number) => ({ exchangeId: `ex-${n}`, peer: `did:key:peer${n}`, relationshipDid: `did:peer:4zrel${n}`, receivedAt: t, deadlineAt: t + 7 * DAY });

test('the catalogue declares proposal.held and proposal.changed', () => {
  assert.ok(STACK_EVENTS.includes('proposal.held' as never));
  assert.ok(STACK_EVENTS.includes('proposal.changed' as never));
});

test('heldProposals maps the agent rows to DTOs and carries the seven-day deadline', async () => {
  const { api } = fixture({ listHeldVrcProposals: async () => [row(1, 1000), row(2, 2000)] });
  const list = await api.heldProposals();
  assert.deepEqual(list[0], { exchangeId: 'ex-1', peerDid: 'did:key:peer1', relationshipDid: 'did:peer:4zrel1', receivedAt: 1000, deadlineAt: 1000 + 7 * DAY });
  assert.equal(list.length, 2);
});

test('heldProposals is empty when the agent has no listener surface', async () => {
  assert.deepEqual(await fixture({}).api.heldProposals(), []);
});

test('with no active agent both methods fail closed', async () => {
  const { api } = fixture(null);
  await assert.rejects(() => api.heldProposals(), /No active VTA/);
  await assert.rejects(() => api.decideProposal('ex-1', 'accept'), /No active VTA/);
});

test('decideProposal accepts or declines, and announces proposal.changed (no peer in the payload)', async () => {
  const calls: unknown[] = [];
  const { api, events } = fixture({ decideVrcProposal: async (...a: unknown[]) => { calls.push(a); } });
  assert.deepEqual(await api.decideProposal('ex-1', 'accept'), { exchangeId: 'ex-1', status: 'accepted' });
  assert.deepEqual(await api.decideProposal('ex-2', 'decline'), { exchangeId: 'ex-2', status: 'declined' });
  assert.deepEqual(calls, [['ex-1', 'accept'], ['ex-2', 'decline']]);
  assert.deepEqual(events.map(([n, p]) => [n, (p as { exchangeId: string; status: string }).exchangeId, (p as { status: string }).status]), [['proposal.changed', 'ex-1', 'accepted'], ['proposal.changed', 'ex-2', 'declined']]);
  for (const [, p] of events) assert.deepEqual(Object.keys(p as object).sort(), ['at', 'exchangeId', 'status']);
});

test('an unknown, foreign or already-decided id is one not_found answer; a lapsed one is proposal_lapsed; a bad decision is refused', async () => {
  const { api, events } = fixture({
    decideVrcProposal: async (id: string) => {
      if (id === 'lapsed') throw new TaskError({ reason: 'deadlineLapsed' });
      throw new TaskError({ reason: 'notFound', internalMessage: 'no held proposal for that exchange' });
    },
  });
  const a = await api.decideProposal('nope', 'accept').catch((e) => e);
  const b = await api.decideProposal('someone-elses', 'accept').catch((e) => e);
  assert.equal(a.code, 'not_found');
  assert.equal(a.message, b.message);
  assert.equal((await api.decideProposal('lapsed', 'accept').catch((e) => e)).code, 'proposal_lapsed');
  assert.equal((await api.decideProposal('', 'accept').catch((e) => e)).code, 'invalid_input');
  assert.equal((await api.decideProposal('x', 'maybe' as never).catch((e) => e)).code, 'invalid_input');
  assert.deepEqual(events, [], 'a failed decision announces nothing');
});

test('a scoped context can neither call the methods nor subscribe to the events (existence stays with the owner)', () => {
  const denied = METHOD_CLASSIFICATION.denied.relationships;
  assert.ok(denied.includes('heldProposals'));
  assert.ok(denied.includes('decideProposal'));
  for (const m of ['heldProposals', 'decideProposal']) {
    assert.ok(!METHOD_CLASSIFICATION.read.relationships.includes(m));
    assert.ok(!METHOD_CLASSIFICATION.write.relationships.includes(m));
  }
});

test('an adopted agent that reports a held proposal makes the stack emit proposal.held (exchange id only)', async () => {
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { createAgentStack } = await import('../../src/index.ts');
  const home = mkdtempSync(join(tmpdir(), 'api-held-'));
  const stack = await createAgentStack({ home, agent: { name: 'held-ev', passphrase: 'correct horse battery', port: 24071 } });
  try {
    assert.equal(stack.host.home, home);
    let fire: ((id: string) => void) | undefined;
    const real = (stack as unknown as { adopt(h: unknown): Promise<void> });
    const seen: unknown[] = [];
    stack.on('proposal.held' as never, ((p: unknown) => seen.push(p)) as never);
    const stub = new Proxy({ onVrcProposalHeld: (h: (id: string) => void) => { fire = h; }, getName: () => 'held-ev' }, {
      get: (t, k) => (k in t ? (t as never)[k] : () => {}),
    });
    await real.adopt(stub).catch(() => { /* store attach may need a real agent; the wiring ran first */ });
    assert.equal(typeof fire, 'function', 'the stack registers for the agent hold hook');
    fire!('ex-9');
    await stack.stop();
    assert.equal(seen.length, 1);
    assert.deepEqual(Object.keys(seen[0] as object).sort(), ['at', 'exchangeId']);
    assert.equal((seen[0] as { exchangeId: string }).exchangeId, 'ex-9');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
