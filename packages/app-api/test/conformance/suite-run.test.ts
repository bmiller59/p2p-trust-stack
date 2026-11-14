// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P8: the suite's own command line (`--adapter stdio:<command>`) run against the
 * truststackers JSON-RPC adapter, whole vector set, Tier 1 and Tier 2. Skipped, with a message, where
 * the suite folder is absent (TRUST_CONFORMANCE_SUITE overrides its location).
 *
 * The assertions are the standing result of the first run: no FAIL, no KNOWN-FAIL, and nothing
 * silently skipped that the adapter claims. The one documented exception is Tier 2 with a did:scid:vh
 * agent: the suite's harness verifies replies only for did:key signers, so every Tier 2 reply check
 * fails on the harness side (suite change S1 in the P8 report). That test expects exactly that reason
 * and will start failing, on purpose, once the suite can resolve the provisioned document.
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
const count = (run: Run, status: string): number => run.results.filter((r) => r.status === status).length;
const ids = (run: Run, status: string): string[] => run.results.filter((r) => r.status === status).map((r) => r.id);

describe('the suite against the truststackers adapter (did:key agent: the harness can verify Tier 2 replies)', { skip: SKIP }, () => {
  it('Tier 1 and Tier 2: no FAIL, no KNOWN-FAIL, exit code 0', () => {
    const { code, runs, out } = runSuite('--attested --identity key');
    assert.equal(code, 0, out);
    assert.deepEqual(runs.map((r) => r.tier), [1, 2]);
    for (const run of runs) {
      assert.equal(count(run, 'FAIL'), 0, ids(run, 'FAIL').join(','));
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

  it('Tier 1 server (not attested): the Tier 1 only vectors run and pass too', () => {
    const { code, runs, out } = runSuite('--identity key');
    assert.equal(code, 0, out);
    assert.equal(runs.length, 1);
    const run = runs[0]!;
    assert.equal(count(run, 'FAIL'), 0, ids(run, 'FAIL').join(','));
    for (let n = 101; n <= 113; n++) assert.ok(ids(run, 'PASS').includes(`DUP-${n}`), `DUP-${n}`);
  });
});

describe('the suite against the truststackers adapter (did:scid:vh agent, as the agent is built)', { skip: SKIP }, () => {
  it('Tier 1 passes in full', () => {
    const { code, runs, out } = runSuite('');
    assert.equal(code, 0, out);
    assert.equal(count(runs[0]!, 'FAIL'), 0, ids(runs[0]!, 'FAIL').join(','));
    assert.ok(count(runs[0]!, 'PASS') >= 120);
  });

  it('Tier 2: every failure is the harness being unable to verify a did:scid:vh signer (suite change S1), nothing else', () => {
    const { runs } = runSuite('--attested');
    const tier2 = runs.find((r) => r.tier === 2)!;
    assert.equal(count(tier2, 'FAIL') > 0, true, 'if this is 0 the suite learned to resolve the provisioned document: delete this test and the exception note');
    for (const r of tier2.results.filter((x) => x.status === 'FAIL')) {
      assert.ok((r.failures ?? []).length > 0 && (r.failures ?? []).every((f) => /reply proof invalid \(unsupported verification method\)/.test(f)), `${r.id}: ${(r.failures ?? []).join('; ')}`);
    }
    // And the replies those vectors judge are in fact signed correctly: the same run at Tier 1 shape passes,
    // and the server-side test (rpc-server.test.ts) verifies a did:scid:vh reply against the published document.
  });
});
