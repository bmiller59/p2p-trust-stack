// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Exports the pinned conformance suite revision for the app-api tests.
 *
 *   node --experimental-strip-types scripts/export-conformance-suite.ts [--repo PATH] [--dest DIR]
 *
 * Prints the directory; the tests use `.cache/conformance-suite/<revision>` automatically, or set
 * `TRUST_CONFORMANCE_SUITE` to the printed path.
 */
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_SUITE_REPO, exportSuite, pinnedExportDir, pinnedRevision } from '../packages/app-api/test/trust-tasks-boundary/suite-pin.ts';

const args = process.argv.slice(2);
const opt = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const revision = pinnedRevision();
const dest = resolve(opt('--dest') ?? pinnedExportDir(root, revision));
exportSuite(resolve(opt('--repo') ?? DEFAULT_SUITE_REPO), revision, dest);
console.log(dest);
