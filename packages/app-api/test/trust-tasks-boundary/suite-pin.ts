// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Pins the conformance suite revision the app-api tests run against.
 *
 * The suite (runner code, vectors) lives in its own repository. The revision these tests were
 * written against is recorded in `SUITE_REVISION` beside this file. `exportSuite` writes that
 * revision out with `git archive`, so a test run does not depend on whatever a working tree of the
 * suite holds at the moment. Resolution order for the suite directory used by the tests:
 *
 *   1. `TRUST_CONFORMANCE_SUITE` (explicit override)
 *   2. the pinned export `<repo>/.cache/conformance-suite/<revision>` when it exists
 *   3. the suite repository on the development machine (unpinned; the tests may drift)
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, symlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_SUITE_REPO = '/srv/dev/code/seas/dtgwg-trust-conformance';

/** The pinned suite revision (a full commit id). */
export function pinnedRevision(file = join(HERE, 'SUITE_REVISION')): string {
  const rev = readFileSync(file, 'utf8').trim();
  if (!/^[0-9a-f]{40}$/.test(rev)) throw new Error(`SUITE_REVISION must hold a full commit id, got ${JSON.stringify(rev)}`);
  return rev;
}

/** Where the pinned export lives inside the repository checkout. */
export function pinnedExportDir(repoRoot: string, revision: string): string {
  return join(repoRoot, '.cache', 'conformance-suite', revision);
}

export function resolveSuiteDir(opts: { env?: NodeJS.ProcessEnv; repoRoot?: string; fallback?: string; revision?: string } = {}): string {
  const env = opts.env ?? process.env;
  if (env.TRUST_CONFORMANCE_SUITE) return env.TRUST_CONFORMANCE_SUITE;
  const repoRoot = opts.repoRoot ?? resolve(HERE, '../../../..');
  const pinned = pinnedExportDir(repoRoot, opts.revision ?? pinnedRevision());
  return existsSync(join(pinned, 'src', 'runner', 'suite.ts')) ? pinned : (opts.fallback ?? DEFAULT_SUITE_REPO);
}

/** Exports `revision` of the suite repository `repo` into `dest` (created) and links its node_modules. */
export function exportSuite(repo: string, revision: string, dest: string): void {
  if (!/^[0-9a-f]{40}$/.test(revision)) throw new Error('revision must be a full commit id');
  mkdirSync(dest, { recursive: true });
  const archive = spawnSync('git', ['-c', 'safe.directory=*', '-C', repo, 'archive', '--format=tar', revision], { maxBuffer: 256 * 1024 * 1024 });
  if (archive.status !== 0) throw new Error(`git archive ${revision} failed in ${repo}: ${archive.stderr.toString()}`);
  const untar = spawnSync('tar', ['-x', '-C', dest], { input: archive.stdout });
  if (untar.status !== 0) throw new Error(`tar failed: ${untar.stderr.toString()}`);
  const modules = join(repo, 'node_modules');
  if (existsSync(modules) && !existsSync(join(dest, 'node_modules'))) symlinkSync(modules, join(dest, 'node_modules'));
}
