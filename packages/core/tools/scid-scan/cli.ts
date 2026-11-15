#!/usr/bin/env -S node --conditions=development --experimental-strip-types
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Offline did:scid:vh genesis-check scan. Reads files only; never connects to a database or a
 * deployed system; writes only inside --out-dir. See tools/scid-scan/README.md.
 */

import { mkdirSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  InputError, readTable, toDidDocumentRows, toRotationLogRows, readIdentifierList, readLogFile,
} from './input.js';
import { scanExport, scanIdentifier, wireToLog, type IdentifierReport } from './scan.js';
import { buildReport, toCsv, toSummaryText, type FullReport } from './report.js';

export const USAGE = `Usage:
  scid-scan --did-documents <file> --rotation-log <file> --out-dir <dir>
  scid-scan --identifiers <list.txt> [--logs <dir>] --out-dir <dir>

Table mode:  --did-documents and --rotation-log are exports (.json, .jsonl or .csv) of the two tables.
List mode:   --identifiers is a text file with one did:scid:vh identifier per line; --logs is a directory
             holding <identifier with ':' replaced by '_'>.jsonl (or .json) wire-format logs.
Output:      scid-scan-report.json, scid-scan-report.csv and scid-scan-summary.txt in --out-dir (created if
             missing; nothing is written anywhere else).
Exit status: 0 every identifier accepted, 1 any rejected or unverifiable, 2 usage or input error.
`;

export interface CliResult { code: number; stdout: string; stderr: string; report?: FullReport }

function parseArgs(argv: string[]): Record<string, string> | string {
  const out: Record<string, string> = {};
  const known = new Set(['did-documents', 'rotation-log', 'identifiers', 'logs', 'out-dir']);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) return `unexpected argument "${a}"`;
    const name = a.slice(2);
    if (!known.has(name)) return `unknown option "${a}"`;
    const v = argv[++i];
    if (v === undefined || v.startsWith('--')) return `option "${a}" needs a value`;
    out[name] = v;
  }
  return out;
}

export function run(argv: string[]): CliResult {
  if (argv.includes('--help') || argv.includes('-h')) return { code: 0, stdout: USAGE, stderr: '' };
  const args = parseArgs(argv);
  if (typeof args === 'string') return { code: 2, stdout: '', stderr: `scid-scan: ${args}\n${USAGE}` };
  const outDir = args['out-dir'];
  const tableMode = 'did-documents' in args || 'rotation-log' in args;
  const listMode = 'identifiers' in args;
  if (!outDir) return { code: 2, stdout: '', stderr: `scid-scan: --out-dir is required\n${USAGE}` };
  if (tableMode === listMode) return { code: 2, stdout: '', stderr: `scid-scan: choose table mode or list mode, not both or neither\n${USAGE}` };
  if (tableMode && !('did-documents' in args && 'rotation-log' in args)) {
    return { code: 2, stdout: '', stderr: 'scid-scan: table mode needs both --did-documents and --rotation-log\n' };
  }
  if ('logs' in args && !listMode) return { code: 2, stdout: '', stderr: 'scid-scan: --logs belongs to list mode\n' };

  let report: FullReport;
  try {
    let reports: IdentifierReport[];
    const notes: string[] = [];
    if (tableMode) {
      const docs = toDidDocumentRows(readTable(args['did-documents']));
      const logs = toRotationLogRows(readTable(args['rotation-log']));
      const scan = scanExport(docs, logs);
      reports = scan.reports;
      notes.push(`${docs.length} did_documents rows, ${logs.length} rotation_log rows read`);
      if (scan.skippedNonScidRows) notes.push(`${scan.skippedNonScidRows} non-scid did_documents rows skipped (e.g. did:peer:4)`);
      if (scan.orphanRotationLogGroups) notes.push(`${scan.orphanRotationLogGroups} rotation_log did_document_uuid value(s) match no did_documents row and were not scanned`);
    } else {
      const ids = readIdentifierList(args.identifiers);
      const logsDir = args.logs;
      if (logsDir && !(existsSync(logsDir) && statSync(logsDir).isDirectory())) throw new InputError('--logs is not a directory');
      reports = ids.map((did) => {
        const wire = logsDir ? readLogFile(logsDir, did) : null;
        const built = wire ? wireToLog(wire) : null;
        return scanIdentifier({
          did, source: 'list', method: null,
          log: built ? built.log : null, logProblem: built?.problem, documentJson: null,
        });
      });
      if (ids.length === 0) notes.push('the identifier list is empty');
    }
    report = buildReport(tableMode ? 'db-export' : 'list', reports, notes);
  } catch (e) {
    if (e instanceof InputError) return { code: 2, stdout: '', stderr: `scid-scan: ${e.message}\n` };
    return { code: 2, stdout: '', stderr: `scid-scan: unexpected ${(e as Error).name} while reading input\n` };
  }

  const dir = resolve(outDir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'scid-scan-report.json'), JSON.stringify(report, null, 2) + '\n');
  writeFileSync(join(dir, 'scid-scan-report.csv'), toCsv(report.identifiers));
  const text = toSummaryText(report);
  writeFileSync(join(dir, 'scid-scan-summary.txt'), text);
  return { code: report.summary.clean ? 0 : 1, stdout: text + `reports written to ${dir}\n`, stderr: '', report };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('scid-scan/cli.ts')) {
  const r = run(process.argv.slice(2));
  process.stdout.write(r.stdout);
  process.stderr.write(r.stderr);
  process.exitCode = r.code;
}
