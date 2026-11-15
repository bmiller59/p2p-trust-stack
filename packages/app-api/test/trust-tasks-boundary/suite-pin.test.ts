// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { exportSuite, pinnedExportDir, pinnedRevision, resolveSuiteDir } from './suite-pin.ts';

const dirs: string[] = [];
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'suite-pin-'));
  dirs.push(d);
  return d;
};
after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

describe('suite pin', () => {
  it('records a full commit id', () => {
    assert.match(pinnedRevision(), /^[0-9a-f]{40}$/);
  });

  it('rejects a short revision file', () => {
    const f = join(tmp(), 'rev');
    writeFileSync(f, '7cffefb\n');
    assert.throws(() => pinnedRevision(f), /full commit id/);
  });

  it('prefers the env override, then the pinned export, then the fallback', () => {
    const root = tmp();
    const rev = pinnedRevision();
    const opts = { repoRoot: root, fallback: '/nonexistent/live', revision: rev };
    assert.equal(resolveSuiteDir({ ...opts, env: {} }), '/nonexistent/live');
    const pinned = pinnedExportDir(root, rev);
    mkdirSync(join(pinned, 'src', 'runner'), { recursive: true });
    writeFileSync(join(pinned, 'src', 'runner', 'suite.ts'), '');
    assert.equal(resolveSuiteDir({ ...opts, env: {} }), pinned);
    assert.equal(resolveSuiteDir({ ...opts, env: { TRUST_CONFORMANCE_SUITE: '/elsewhere' } }), '/elsewhere');
  });

  it('exports the named revision, not the working tree', () => {
    const repo = tmp();
    const git = (...a: string[]): string => execFileSync('git', ['-C', repo, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' }).trim();
    git('init', '-q');
    mkdirSync(join(repo, 'src'));
    writeFileSync(join(repo, 'src', 'a.txt'), 'pinned');
    git('add', 'src/a.txt');
    git('commit', '-q', '-m', 'one');
    const rev = git('rev-parse', 'HEAD');
    writeFileSync(join(repo, 'src', 'a.txt'), 'moved on');
    const dest = join(tmp(), 'out');
    exportSuite(repo, rev, dest);
    assert.equal(readFileSync(join(dest, 'src', 'a.txt'), 'utf8'), 'pinned');
    assert.ok(!existsSync(join(dest, '.git')));
    assert.throws(() => exportSuite(repo, 'abc', dest), /full commit id/);
  });
});
