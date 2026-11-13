// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Loads the conformance suite's own runner from the suite folder (it lives beside this repository on
 * the development machine; override with TRUST_CONFORMANCE_SUITE). Where the folder is absent the
 * vector tests are skipped and say so. The vector files themselves are byte copies kept beside the
 * tests (vectors/PROVENANCE.json); only the runner code comes from the suite folder.
 */
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SUITE = process.env.TRUST_CONFORMANCE_SUITE ?? '/srv/dev/code/seas/dtgwg-trust-conformance';
export const suitePresent = existsSync(join(SUITE, 'src', 'runner', 'suite.ts'));
export const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), 'vectors');
export const SKIP = suitePresent ? false : `conformance suite not found at ${SUITE}`;

export interface VectorResultLike {
  id: string;
  group: string;
  status: 'PASS' | 'FAIL' | 'SKIP' | 'KNOWN-FAIL' | 'CLARIFY';
  reason?: string;
  failures?: string[];
}

export interface SuiteApi {
  loadSuite(dir: string): unknown;
  runSuite(opts: { adapter: unknown; suite: unknown; tier: 1 | 2; today: string; fixtureRoot: string }): Promise<{ results: VectorResultLike[] }>;
}

export async function loadSuiteApi(): Promise<SuiteApi> {
  const load = (await import(join(SUITE, 'src', 'vectors', 'load.ts'))) as { loadSuite(dir: string): unknown };
  const run = (await import(join(SUITE, 'src', 'runner', 'suite.ts'))) as { runSuite: SuiteApi['runSuite'] };
  return { loadSuite: load.loadSuite, runSuite: run.runSuite };
}
