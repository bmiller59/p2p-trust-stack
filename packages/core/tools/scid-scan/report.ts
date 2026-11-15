// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Report rendering: summary text, JSON and CSV. Reports carry identifiers, counts, classes and
 * reasons only. They never contain signatures, keys, document bodies or raw row cells.
 */

import type { IdentifierReport } from './scan.js';

export const REPORT_VERSION = 1;

export interface Summary {
  total: number;
  accept: number;
  reject: number;
  unverifiable: number;
  newlyBroken: number;
  alreadyBroken: number;
  byClass: Record<string, number>;
  byResolution: Record<string, number>;
  /** True when package A can ship without degrading any scanned identifier. */
  clean: boolean;
}

export function summarize(reports: IdentifierReport[]): Summary {
  const s: Summary = {
    total: reports.length, accept: 0, reject: 0, unverifiable: 0, newlyBroken: 0, alreadyBroken: 0,
    byClass: {}, byResolution: {}, clean: false,
  };
  for (const r of reports) {
    s[r.verdict]++;
    if (r.newlyBroken) s.newlyBroken++;
    if (r.alreadyBroken) s.alreadyBroken++;
    for (const c of r.classes) s.byClass[c] = (s.byClass[c] ?? 0) + 1;
    s.byResolution[r.resolution] = (s.byResolution[r.resolution] ?? 0) + 1;
  }
  s.clean = s.reject === 0 && s.unverifiable === 0 && s.total > 0;
  return s;
}

export interface FullReport {
  reportVersion: number;
  inputs: { mode: 'db-export' | 'list'; notes: string[] };
  summary: Summary;
  identifiers: IdentifierReport[];
}

export function buildReport(
  mode: 'db-export' | 'list',
  identifiers: IdentifierReport[],
  notes: string[] = [],
): FullReport {
  return { reportVersion: REPORT_VERSION, inputs: { mode, notes }, summary: summarize(identifiers), identifiers };
}

const csvCell = (v: unknown): string => {
  const s = v === null || v === undefined ? '' : String(v);
  // Neutralise spreadsheet formula injection from identifier text.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};

export const CSV_COLUMNS = [
  'identifier', 'verdict', 'genesis_check', 'classes', 'resolution', 'newly_broken', 'already_broken',
  'entries', 'valid_entries_new', 'valid_entries_old', 'first_failing_version', 'mldsa_entries',
  'key_order_match', 'created_at_offset_s', 'cached_document', 'reasons',
] as const;

export function toCsv(identifiers: IdentifierReport[]): string {
  const lines = [CSV_COLUMNS.join(',')];
  for (const r of identifiers) {
    lines.push([
      r.did, r.verdict, r.genesisCheck, r.classes.join('|'), r.resolution, r.newlyBroken, r.alreadyBroken,
      r.entries, r.validEntriesNew, r.validEntriesOld, r.firstFailingVersion,
      `${r.mlDsaPerEntry.filter(Boolean).length}/${r.mlDsaPerEntry.length}`,
      r.diagnostics.keyOrderMatch, r.diagnostics.createdAtOffsetSeconds,
      r.cachedDocumentPresent, r.reasons.join(' | '),
    ].map(csvCell).join(','));
  }
  return lines.join('\n') + '\n';
}

export function toSummaryText(report: FullReport): string {
  const s = report.summary;
  const out: string[] = [];
  out.push(`did:scid:vh genesis-check scan (${report.inputs.mode}), ${s.total} identifier(s)`);
  out.push(`  accept ${s.accept}   reject ${s.reject}   unverifiable ${s.unverifiable}`);
  out.push(`  newly broken by the genesis check: ${s.newlyBroken}   already broken before it: ${s.alreadyBroken}`);
  const cls = Object.entries(s.byClass).sort();
  if (cls.length) out.push(`  failure classes: ${cls.map(([k, v]) => `${k}=${v}`).join(', ')}`);
  const res = Object.entries(s.byResolution).sort();
  if (res.length) out.push(`  resolution after package A: ${res.map(([k, v]) => `${k}=${v}`).join(', ')}`);
  for (const n of report.inputs.notes) out.push(`  note: ${n}`);
  out.push(s.clean ? '  RESULT: clean, package A degrades none of the scanned identifiers' : '  RESULT: NOT clean, see the per-identifier lines');
  out.push('');
  for (const r of report.identifiers) {
    out.push(`${r.verdict.toUpperCase().padEnd(12)} ${r.did}`);
    out.push(`  genesis check: ${r.genesisCheck}; resolves as: ${r.resolution}${r.newlyBroken ? '; NEWLY BROKEN' : ''}`);
    for (const reason of r.reasons) out.push(`  - ${reason}`);
  }
  return out.join('\n') + '\n';
}
