// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Input parsing for the offline did:scid:vh scan: JSON / JSONL / CSV table
 * exports and identifier lists. Pure functions and local file reads only;
 * nothing here opens a database or a network connection.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { extname, join } from 'node:path';
import type { RotationEntryJson } from '../../src/did/rotation-entry-codec.js';

export type Row = Record<string, unknown>;

/** Raised for input the tool cannot interpret. Messages never quote cell values (they may be key material). */
export class InputError extends Error {}

// ---------------------------------------------------------------------------
// CSV (RFC 4180: quoted fields, doubled quotes, embedded newlines)
// ---------------------------------------------------------------------------

export function parseCsv(text: string): Row[] {
  const records: string[][] = [];
  let field = '';
  let record: string[] = [];
  let inQuotes = false;
  let i = 0;
  if (text.charCodeAt(0) === 0xfeff) i = 1;
  for (; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ',') { record.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      record.push(field); field = '';
      records.push(record); record = [];
    } else field += c;
  }
  if (inQuotes) throw new InputError('CSV: unterminated quoted field');
  if (field !== '' || record.length > 0) { record.push(field); records.push(record); }
  const nonEmpty = records.filter((r) => !(r.length === 1 && r[0] === ''));
  if (nonEmpty.length === 0) return [];
  const header = nonEmpty[0].map((h) => h.trim());
  return nonEmpty.slice(1).map((r, n) => {
    if (r.length !== header.length) throw new InputError(`CSV: data row ${n + 1} has ${r.length} fields, header has ${header.length}`);
    const row: Row = {};
    header.forEach((h, k) => { row[h] = r[k]; });
    return row;
  });
}

/** Read a table export: .json (array, or { rows: [...] }), .jsonl / .ndjson, or .csv. */
export function readTable(path: string): Row[] {
  const text = readFileSync(path, 'utf8');
  const ext = extname(path).toLowerCase();
  if (ext === '.csv') return parseCsv(text);
  if (ext === '.jsonl' || ext === '.ndjson') {
    return text.split(/\r?\n/).filter((l) => l.trim() !== '').map((l, n) => {
      try { return asRow(JSON.parse(l)); } catch { throw new InputError(`JSONL: line ${n + 1} is not a JSON object`); }
    });
  }
  if (ext === '.json') {
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { throw new InputError(`${path}: not valid JSON`); }
    const arr = Array.isArray(parsed) ? parsed : (parsed as { rows?: unknown })?.rows;
    if (!Array.isArray(arr)) throw new InputError(`${path}: expected a JSON array of rows (or { "rows": [...] })`);
    return arr.map(asRow);
  }
  throw new InputError(`${path}: unsupported extension "${ext}" (use .json, .jsonl or .csv)`);
}

function asRow(v: unknown): Row {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new InputError('a row is not a JSON object');
  return v as Row;
}

// ---------------------------------------------------------------------------
// Cell decoding
// ---------------------------------------------------------------------------

/**
 * Decode a binary cell. Accepted: Uint8Array, a JSON Buffer object, `\\x<hex>` / `0x<hex>` / `hex:<hex>`,
 * `base64:<b64>`, or bare base64 (what `encode(col, 'base64')` produces). A bare string is always base64,
 * never hex. Returns null for null / empty / missing.
 */
export function decodeBytes(value: unknown, column: string): Uint8Array | null {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'object' && (value as { type?: string }).type === 'Buffer' && Array.isArray((value as { data?: unknown }).data)) {
    return new Uint8Array((value as { data: number[] }).data);
  }
  if (typeof value !== 'string') throw new InputError(`column ${column}: unsupported binary cell type`);
  const s = value.trim();
  const hex = /^(?:\\x|0x|hex:)([0-9a-fA-F]*)$/.exec(s);
  if (hex) {
    if (hex[1].length % 2 !== 0) throw new InputError(`column ${column}: odd-length hex cell`);
    return new Uint8Array(Buffer.from(hex[1], 'hex'));
  }
  const b64 = s.startsWith('base64:') ? s.slice(7) : s;
  const compact = b64.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 === 1) {
    throw new InputError(`column ${column}: cell is neither prefixed hex nor valid base64`);
  }
  return new Uint8Array(Buffer.from(compact, 'base64'));
}

export function decodeInt(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const n = typeof value === 'number' ? value : Number(String(value).trim());
  return Number.isFinite(n) ? n : null;
}

export function decodeText(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'string') return value;
  // A jsonb / JSON-typed column exported as an object: re-serialise (key order is whatever the export kept).
  return JSON.stringify(value);
}

// ---------------------------------------------------------------------------
// Typed table rows
// ---------------------------------------------------------------------------

export interface DidDocumentRow {
  uuid: string;
  did: string;
  method: string | null;
  documentJson: string | null;
  status: string | null;
}

export interface RotationLogRowIn {
  didDocumentUuid: string;
  version: number;
  previousHash: Uint8Array | null;
  newPublicKey: Uint8Array;
  signedEntry: Uint8Array;
  createdAt: number | null;
}

function need(row: Row, col: string, table: string, n: number): unknown {
  if (!(col in row)) throw new InputError(`${table}: row ${n + 1} lacks required column "${col}"`);
  return row[col];
}

export function toDidDocumentRows(rows: Row[]): DidDocumentRow[] {
  return rows.map((r, n) => ({
    uuid: String(need(r, 'uuid', 'did_documents', n)),
    did: String(need(r, 'did', 'did_documents', n)),
    method: decodeText(r.method),
    documentJson: decodeText(r.document_json),
    status: decodeText(r.status),
  }));
}

export function toRotationLogRows(rows: Row[]): RotationLogRowIn[] {
  return rows.map((r, n) => {
    const version = decodeInt(need(r, 'version', 'rotation_log', n));
    if (version === null) throw new InputError(`rotation_log: row ${n + 1} has a non-numeric version`);
    const signedEntry = decodeBytes(need(r, 'signed_entry', 'rotation_log', n), 'signed_entry');
    const newPublicKey = decodeBytes(need(r, 'new_public_key', 'rotation_log', n), 'new_public_key');
    if (!signedEntry || !newPublicKey) throw new InputError(`rotation_log: row ${n + 1} has an empty signed_entry or new_public_key`);
    return {
      didDocumentUuid: String(need(r, 'did_document_uuid', 'rotation_log', n)),
      version,
      previousHash: decodeBytes(r.previous_hash, 'previous_hash'),
      newPublicKey,
      signedEntry,
      createdAt: decodeInt(r.created_at),
    };
  });
}

// ---------------------------------------------------------------------------
// Identifier list + log files
// ---------------------------------------------------------------------------

/** One identifier per line; blank lines and `#` comments ignored. */
export function readIdentifierList(path: string): string[] {
  const out: string[] = [];
  for (const raw of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (line) out.push(line);
  }
  return [...new Set(out)];
}

/** File-name form of an identifier: every character outside [A-Za-z0-9._-] becomes "_". */
export function logFileStem(did: string): string {
  return did.replace(/[^A-Za-z0-9._-]/g, '_');
}

/**
 * Find and read the log for `did` in `dir`: `<stem>.jsonl` (one wire-JSON entry per line, the format
 * the utility server serves) or `<stem>.json` (an array of the same). Returns null when no file exists.
 */
export function readLogFile(dir: string, did: string): RotationEntryJson[] | null {
  const stem = logFileStem(did);
  const names = new Set(readdirSync(dir));
  for (const ext of ['.jsonl', '.json']) {
    if (!names.has(stem + ext)) continue;
    const path = join(dir, stem + ext);
    if (!existsSync(path)) continue;
    const rows = readTable(path);
    return rows as unknown as RotationEntryJson[];
  }
  return null;
}
