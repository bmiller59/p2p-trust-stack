// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P8: the suite's own command line (`--adapter stdio:<command>`) run against the
 * truststackers JSON-RPC adapter, whole vector set, Tier 1 and Tier 2. Skipped, with a message, where
 * the suite folder is absent (TRUST_CONFORMANCE_SUITE overrides its location).
 *
 * The assertions are the standing result: no FAIL and no KNOWN-FAIL (TD-005, the one divergence of the
 * P8b run, passes since the suite changed that vector), and nothing silently skipped that the adapter
 * claims: a SKIP is allowed only for a capability or type the adapter does not declare (ES256) or a vector that needs the other server mode. The did:scid:vh
 * agent passes Tier 2 now that the suite verifies replies from the DID document `provision` returns.
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
/** No documented divergence is left (see the header). */
const EXPECTED_FAIL: string[] = [];
/** What a SKIP may say: only things the adapter does not declare, or the other server mode. */
const ALLOWED_SKIP = /ecdsa-jcs-2019|only runs at tier 1|type not declared|implementation declares optional attested|implementation declares optional ceremony.status/;
const count = (run: Run, status: string): number => run.results.filter((r) => r.status === status).length;
const ids = (run: Run, status: string): string[] => run.results.filter((r) => r.status === status).map((r) => r.id);

describe('the suite against the truststackers adapter (did:key agent: the harness can verify Tier 2 replies)', { skip: SKIP }, () => {
  it('Tier 1 and Tier 2: no FAIL and no KNOWN-FAIL', () => {
    const { code, runs, out } = runSuite('--attested --identity key');
    assert.equal(code, 0, out);
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
    // The new groups are measured: discovery 0.4 (DIS), the two-phase triggers on the real coordinator (2PC), the HTTPS binding over the agent listener (BND).
    for (const id of ['DIS-001', 'DIS-003', 'DIS-011', 'DIS-012', 'DIS-013', 'DIS-016', 'DIS-017', '2PC-001', '2PC-006', '2PC-007', 'BND-001', 'BND-002', 'BND-003', 'BND-004', 'BND-005', 'BND-006']) {
      assert.ok(ids(tier2, 'PASS').includes(id), `${id} passes at tier 2`);
    }
    // The ceremony documents (CER, 2PC-003..005, TIME-103) are measured: hold, quorum, refusal, indeterminate and settle, retention.
    for (const id of ['CER-001', 'CER-003', 'CER-005', 'CER-006', 'CER-008', 'CER-009', 'CER-010', 'CER-011', 'CER-012', 'CER-013', 'CER-014', 'CER-015', 'CER-016', '2PC-003', '2PC-004', '2PC-005', 'TIME-103']) {
      assert.ok(ids(tier2, 'PASS').includes(id) || ids(tier2, 'CLARIFY').includes(id), `${id} is measured at tier 2`);
    }
    // The only skips are things the adapter does not claim (see ALLOWED_SKIP).
    for (const r of tier2.results.filter((x) => x.status === 'SKIP')) {
      assert.match(r.reason ?? '', ALLOWED_SKIP, `${r.id}: ${r.reason}`);
    }
  });

  it('Tier 1 server (not attested): the Tier 1 only vectors run and pass', () => {
    const { code, runs, out } = runSuite('--identity key');
    assert.equal(code, 0, out);
    assert.equal(runs.length, 1);
    const run = runs[0]!;
    assert.deepEqual(ids(run, 'FAIL'), EXPECTED_FAIL);
    for (let n = 101; n <= 113; n++) assert.ok(ids(run, 'PASS').includes(`DUP-${n}`), `DUP-${n}`);
  });
});

describe('the suite against the truststackers adapter (did:scid:vh agent, as the agent is built)', { skip: SKIP }, () => {
  it('Tier 1: no FAIL', () => {
    const { code, runs, out } = runSuite('');
    assert.equal(code, 0, out);
    assert.deepEqual(ids(runs[0]!, 'FAIL'), EXPECTED_FAIL);
    assert.ok(count(runs[0]!, 'PASS') >= 120);
  });

  it('Tier 2 passes as well: the suite verifies the signed replies from the document provision returns', () => {
    const { runs, out } = runSuite('--attested');
    const tier2 = runs.find((r) => r.tier === 2)!;
    assert.deepEqual(ids(tier2, 'FAIL'), EXPECTED_FAIL, out);
    assert.ok(count(tier2, 'PASS') >= 170, `${count(tier2, 'PASS')} pass`);
    for (const r of tier2.results.filter((x) => x.status === 'SKIP')) assert.match(r.reason ?? '', ALLOWED_SKIP, `${r.id}: ${r.reason}`);
  });

  it('the duplicate-record fault vectors run (fault.claimStore is claimed) and agree with the design rule', () => {
    const { runs } = runSuite('--attested');
    const tier2 = runs.find((r) => r.tier === 2)!;
    for (const id of ['DUP-007', 'DUP-008']) assert.equal(tier2.results.find((r) => r.id === id)?.status, 'CLARIFY', id);
  });
});
