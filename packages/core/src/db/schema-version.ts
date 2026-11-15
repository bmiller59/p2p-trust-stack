// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The schema version is recorded in the `schema_migrations` ledger as a row
 * whose filename is `__schema_version__:<n>`. Both migration runners share
 * this encoding and the rule for reading it back: the recorded version is the
 * numerically largest `<n>` among such rows.
 */

export const SCHEMA_VERSION_PREFIX = '__schema_version__:';

/** The ledger filename that records schema version `version`. */
export function schemaVersionFilename(version: number): string {
  return `${SCHEMA_VERSION_PREFIX}${version}`;
}

/** The highest version found among the given ledger filenames, if any. */
export function maxRecordedVersion(filenames: readonly string[]): number | undefined {
  let max: number | undefined;
  for (const name of filenames) {
    if (!name.startsWith(SCHEMA_VERSION_PREFIX)) continue;
    const v = Number.parseInt(name.slice(SCHEMA_VERSION_PREFIX.length), 10);
    if (Number.isNaN(v)) continue;
    if (max === undefined || v > max) max = v;
  }
  return max;
}
