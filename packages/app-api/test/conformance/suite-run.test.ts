// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P8: the suite's own command line (`--adapter stdio:<command>`) run against the
 * truststackers JSON-RPC adapter, whole vector set, Tier 1 and Tier 2. Skipped, with a message, where
 * the suite folder is absent (TRUST_CONFORMANCE_SUITE overrides its location).
 *
 * The assertions are the standing result: the only FAIL is TD-005 (the suite expects a second, different
 * witnessed credential on one exchange to be stored; this agent refuses it by design, the profile choice
 * recorded in the P7 report and open in docs/10 section 8), no KNOWN-FAIL, and nothing silently skipped
 * that the adapter claims. The did:scid:vh agent passes Tier 2 now that the suite verifies replies from
 * the DID document `provision` returns. When the TD-005 question is settled (vector changed, or the
 * agent's rule), EXPECTED_FAIL goes empty and the exit code assertions follow.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { SKIP, SUITE } from '../trust-tasks-boundary/suite-runner.ts';

const APP_API = new URL('../..', import.meta.url).pathname;
const dirs: string[] = [];
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

interface Result { id: string; group: string; status: string; reason?: string; failures?: string[] }
interface Run { impl: string; tier: number; results: Result[] }

function runSuite(serverArgs: string): { code: number | null; runs: Run[]; out: string } {
  const dir = mkdtempSync(join(tmpdir(), 'p8-suite-'));
  dirs.push(dir);
  const command = `NODE_NO_WARNINGS=1 ${process.execPath} --conditions=development --experimental-strip-types --loader ./test-loader.mjs conformance/server.ts ${serverArgs}`;
  const p = spawnSync(process.execPath, [
    '--experimental-strip-types', '--disable-warning=ExperimentalWarning', join(SUITE, 'src', 'runner', 'cli.ts'),
    '--adapter', `stdio:${command}`, '--timeout', '60000', '--exceptions', join(dir, 'none.json'), '--out', dir,
  ], { cwd: APP_API, encoding: 'utf8', timeout: 240_000 });
  return { code: p.status, runs: JSON.parse(readFileSync(join(dir, 'results.json'), 'utf8')) as Run[], out: p.stdout + p.stderr };
}
/** The documented divergence (see the header). */
const EXPECTED_FAIL = ['TD-005'];
const count = (run: Run, status: string): number => run.results.filter((r) => r.status === status).length;
const ids = (run: Run, status: string): string[] => run.results.filter((r) => r.status === status).map((r) => r.id);

describe('the suite against the truststackers adapter (did:key agent: the harness can verify Tier 2 replies)', { skip: SKIP }, () => {
  it('Tier 1 and Tier 2: only TD-005 fails, no KNOWN-FAIL', () => {
    const { code, runs, out } = runSuite('--attested --identity key');
    assert.equal(code, 1, out);
    assert.deepEqual(runs.map((r) => r.tier), [1, 2]);
    for (const run of runs) {
      assert.deepEqual(ids(run, 'FAIL'), EXPECTED_FAIL);
      assert.equal(count(run, 'KNOWN-FAIL'), 0);
      assert.ok(count(run, 'PASS') >= 100, `tier ${run.tier}: ${count(run, 'PASS')} pass`);
    }
    const tier2 = runs[1]!;
    for (const id of ['VRC-PRO-012', 'VRC-PRO-013', 'VRC-PRO-019', 'VRC-ISS-017', 'VRC-ISS-018', 'VRC-ISS-019', 'RSP-004', 'ERR-003']) {
      assert.ok(ids(tier2, 'PASS').includes(id), `${id} passes at tier 2`);
    }
    // The only skips are things the adapter does not claim: ES256 (PRF-002..005) and tier-gated vectors.
    for (const r of tier2.results.filter((x) => x.status === 'SKIP')) {
      assert.match(r.reason ?? '', /ecdsa-jcs-2019|only runs at tier 1/, `${r.id}: ${r.reason}`);
    }
  });

  it('Tier 1 server (not attested): the Tier 1 only vectors run and pass', () => {
    const { code, runs, out } = runSuite('--identity key');
    assert.equal(code, 1, out);
    assert.equal(runs.length, 1);
    const run = runs[0]!;
    assert.deepEqual(ids(run, 'FAIL'), EXPECTED_FAIL);
    for (let n = 101; n <= 113; n++) assert.ok(ids(run, 'PASS').includes(`DUP-${n}`), `DUP-${n}`);
  });
});

describe('the suite against the truststackers adapter (did:scid:vh agent, as the agent is built)', { skip: SKIP }, () => {
  it('Tier 1: only TD-005 fails', () => {
    const { code, runs, out } = runSuite('');
    assert.equal(code, 1, out);
    assert.deepEqual(ids(runs[0]!, 'FAIL'), EXPECTED_FAIL);
    assert.ok(count(runs[0]!, 'PASS') >= 120);
  });

  it('Tier 2 passes as well: the suite verifies the signed replies from the document provision returns', () => {
    const { runs, out } = runSuite('--attested');
    const tier2 = runs.find((r) => r.tier === 2)!;
    assert.deepEqual(ids(tier2, 'FAIL'), EXPECTED_FAIL, out);
    assert.ok(count(tier2, 'PASS') >= 165, `${count(tier2, 'PASS')} pass`);
    for (const r of tier2.results.filter((x) => x.status === 'SKIP')) assert.match(r.reason ?? '', /ecdsa-jcs-2019|only runs at tier 1/, `${r.id}: ${r.reason}`);
  });

  it('the duplicate-record fault vectors run (fault.claimStore is claimed) and agree with the design rule', () => {
    const { runs } = runSuite('--attested');
    const tier2 = runs.find((r) => r.tier === 2)!;
    for (const id of ['DUP-007', 'DUP-008']) assert.equal(tier2.results.find((r) => r.id === id)?.status, 'CLARIFY', id);
  });
});
