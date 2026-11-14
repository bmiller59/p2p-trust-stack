// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P8d: the two-phase trigger actions on the REAL coordinator. A recording stand-in plays the participant's effect;
 * the coordinator, its durable log and `getOutcome` are the production ones. Temp directory only.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { CompensationExecutor, DataSourceLogSink, TransactionCoordinator, TransactionLog, TransactionManager, TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/index.js';
import { getAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { Operation, Outcome, Participant, Vote } from '@p2p-trust-stack/core/tx/types.js';
import { FaultableParticipant, TwoPhaseFaults, parseTwoPhase } from '../../conformance/two-phase.ts';

const root = mkdtempSync(join(tmpdir(), 'p8d-2pc-'));
after(() => rmSync(root, { recursive: true, force: true }));

class Effect implements Participant {
  readonly pid = 'peer:test';
  readonly calls: string[] = [];
  stored = 0;
  async prepare(): Promise<Vote> {
    this.calls.push('prepare');
    return 'yes';
  }
  async commit(): Promise<void> {
    this.calls.push('commit');
    this.stored++;
  }
  async abort(): Promise<void> {
    this.calls.push('abort');
  }
  async compensate(): Promise<void> {}
  async inquiry(): Promise<Outcome> {
    return 'unknown';
  }
  handlesOperation(op: Operation): boolean {
    return op.op === 'store_remote_vrc';
  }
}

async function setup(name: string) {
  const txDb = new SqliteDataSource(join(root, `${name}.db`));
  txDb.getRawDb().exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  const manager = new TransactionManager(new TransactionCoordinator(new TransactionLog(new DataSourceLogSink(txDb))), new CompensationExecutor());
  const faults = new TwoPhaseFaults();
  const effect = new Effect();
  const participant = new FaultableParticipant(effect, faults);
  const log = new TransactionLog(new DataSourceLogSink(txDb));
  const run = () => manager.run(async (tx) => tx.enlist(participant, [{ op: 'store_remote_vrc', params: {} }]));
  const lastTxId = async (): Promise<string> => (await log.txIds()).at(-1)!;
  return { manager, faults, effect, run, lastTxId };
}

describe('twoPhase argument parsing', () => {
  it('accepts the five outcomes and refuses anything else, including a reason outside the closed vocabulary', () => {
    assert.deepEqual(parseTwoPhase({ outcome: 'commit' }), { outcome: 'commit', deliver: true });
    assert.deepEqual(parseTwoPhase({ outcome: 'commit', deliver: false }), { outcome: 'commit', deliver: false });
    assert.deepEqual(parseTwoPhase({ outcome: 'abort', reason: 'storeFailed', internal: 'row 42' }), { outcome: 'abort', reason: 'storeFailed', internal: 'row 42' });
    assert.deepEqual(parseTwoPhase({ outcome: 'voteNo' }), { outcome: 'voteNo' });
    assert.deepEqual(parseTwoPhase({ outcome: 'inflight' }), { outcome: 'inflight' });
    assert.deepEqual(parseTwoPhase({ outcome: 'unknown' }), { outcome: 'unknown' });
    assert.throws(() => parseTwoPhase({ outcome: 'explode' }), /outcome must be/);
    assert.throws(() => parseTwoPhase({ outcome: 'abort', reason: 'free text' }), /closed/);
    assert.throws(() => parseTwoPhase({ outcome: 'commit', deliver: 'no' }), /boolean/);
  });
});

describe('the faults on the real coordinator', () => {
  it('commit (the default) commits and applies the effect once', async () => {
    const s = await setup('commit');
    const r = await s.run();
    assert.equal(r.outcome, 'committed');
    assert.equal(await s.manager.getOutcome(r.txId), 'committed');
    assert.equal(s.effect.stored, 1);
  });

  it('commit with deliver false commits and asks the adapter to drop the reply, once', async () => {
    const s = await setup('lost');
    s.faults.arm(parseTwoPhase({ outcome: 'commit', deliver: false }));
    assert.equal((await s.run()).outcome, 'committed');
    assert.equal(s.faults.takeDroppedReply(), true);
    assert.equal(s.faults.takeDroppedReply(), false);
  });

  it('abort: the coordinator logs aborted, the effect is never applied, the reason is the recorded one and the internal text is not', async () => {
    const s = await setup('abort');
    s.faults.arm(parseTwoPhase({ outcome: 'abort', reason: 'storeFailed', internal: 'constraint violation at row 42 secret-ref' }));
    const r = await s.run();
    assert.equal(r.outcome, 'aborted');
    assert.equal(await s.manager.getOutcome(r.txId), 'aborted');
    assert.equal(s.effect.stored, 0);
    assert.ok(s.effect.calls.includes('abort'));
    const why = getAbortReason(r.txId)!;
    assert.deepEqual(why, { code: 'taskFailed', retryable: false, reason: 'storeFailed' });
    assert.ok(!JSON.stringify(why).includes('secret-ref'));
    // One-shot: the next transaction commits.
    assert.equal((await s.run()).outcome, 'committed');
  });

  it('abort without a reason records nothing for the wire', async () => {
    const s = await setup('abort2');
    s.faults.arm(parseTwoPhase({ outcome: 'abort', internal: 'secret-ref' }));
    const r = await s.run();
    assert.equal(r.outcome, 'aborted');
    assert.equal(getAbortReason(r.txId), undefined);
  });

  it('voteNo aborts with the recorded reason', async () => {
    const s = await setup('no');
    s.faults.arm(parseTwoPhase({ outcome: 'voteNo', reason: 'notAccepted' }));
    const r = await s.run();
    assert.equal(r.outcome, 'aborted');
    assert.equal(getAbortReason(r.txId)?.reason, 'notAccepted');
    assert.equal(s.effect.stored, 0);
  });

  for (const outcome of ['inflight', 'unknown'] as const) {
    it(`${outcome}: the transaction has no logged decision and nothing is applied until settle releases it (commit)`, async () => {
      const s = await setup(`park-${outcome}`);
      s.faults.arm({ outcome });
      const parked = s.faults.parkSignal();
      const running = s.run();
      assert.equal(await parked, 'parked');
      assert.equal(s.faults.isParked, true);
      assert.equal(s.effect.stored, 0);
      const mid = await s.manager.getOutcome(await s.lastTxId());
      assert.equal(mid, 'inFlight', 'started, no decision logged');
      s.faults.release('yes');
      const r = await running;
      assert.equal(r.outcome, 'committed');
      assert.equal(await s.manager.getOutcome(r.txId), 'committed');
      assert.equal(s.effect.stored, 1);
      assert.equal(s.faults.isParked, false);
    });

    it(`${outcome}: settle as abort ends aborted with the reason, and nothing is stored`, async () => {
      const s = await setup(`park-abort-${outcome}`);
      s.faults.arm({ outcome });
      const parked = s.faults.parkSignal();
      const running = s.run();
      await parked;
      s.faults.release('no', 'storeFailed');
      const r = await running;
      assert.equal(r.outcome, 'aborted');
      assert.equal(getAbortReason(r.txId)?.reason, 'storeFailed');
      assert.equal(s.effect.stored, 0);
    });
  }

  it('release with nothing parked is an error, and clear() frees a parked transaction as a no vote', async () => {
    const s = await setup('clear');
    assert.throws(() => s.faults.release('yes'), /no transaction is waiting/);
    s.faults.arm({ outcome: 'inflight' });
    const parked = s.faults.parkSignal();
    const running = s.run();
    await parked;
    s.faults.clear();
    assert.equal((await running).outcome, 'aborted');
  });
});
