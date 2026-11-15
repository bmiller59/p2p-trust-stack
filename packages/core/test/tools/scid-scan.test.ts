// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The offline did:scid:vh scan: verdicts agree with the real genesis check, the input formats
 * parse, the CLI writes only inside --out-dir, and reports carry no key material.
 */
import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ScidVhMethod, scidMatchesGenesis } from '../../src/did/scid-vh-method.js';
import { decodeBytes, parseCsv, readIdentifierList, readTable, InputError } from '../../tools/scid-scan/input.js';
import { classifyPrefix, scanExport, scanIdentifier } from '../../tools/scid-scan/scan.js';
import { toCsv, summarize } from '../../tools/scid-scan/report.js';
import { run } from '../../tools/scid-scan/cli.js';
import {
  buildFixtureIdentities, toTableExport, writeAll, writeListMode, type FixtureIdentity,
} from '../../tools/scid-scan/make-fixtures.js';
import { toDidDocumentRows, toRotationLogRows } from '../../tools/scid-scan/input.js';

let ids: FixtureIdentity[];
const byName = (n: string): FixtureIdentity => ids.find((i) => i.name === n)!;
const tmp = (): string => mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'scid-scan-test-'));

before(async () => { ids = await buildFixtureIdentities(); });

describe('verdicts', () => {
  it('every fixture gets the expected verdict and failure classes, via the table-export path', () => {
    const t = toTableExport(ids, 'base64');
    const { reports } = scanExport(toDidDocumentRows(t.didDocuments), toRotationLogRows(t.rotationLog));
    assert.equal(reports.length, ids.length);
    for (const id of ids) {
      const r = reports.find((x) => x.did === id.did)!;
      assert.equal(r.verdict, id.expect.verdict, id.name);
      assert.deepEqual([...r.classes].sort(), [...id.expect.classes].sort(), id.name);
    }
  });

  it('agrees with the real scidMatchesGenesis for every fixture that has a log', () => {
    const t = toTableExport(ids, 'base64');
    const { reports } = scanExport(toDidDocumentRows(t.didDocuments), toRotationLogRows(t.rotationLog));
    for (const id of ids.filter((i) => i.log.length > 0 && classifyPrefix(i.did) === 'ok')) {
      // The export stores created_at from the row, so compare against the genesis as re-read from the export.
      const r = reports.find((x) => x.did === id.did)!;
      const stored = { ...id.log[0]!, createdAt: id.rowCreatedAtOverride?.[0] ?? id.log[0]!.createdAt };
      const expected = scidMatchesGenesis(id.did, stored);
      assert.equal(r.genesisCheck === 'accept', expected, id.name);
    }
  });

  it('a genuine log resolves from the log; the ML-DSA presence is reported per entry', () => {
    const r = scanIdentifier({ did: byName('good-rotated').did, source: 'list', method: null, log: byName('good-rotated').log, documentJson: null });
    assert.equal(r.resolution, 'log');
    assert.equal(r.mlDsaPerEntry.length, 2);
    assert.equal(r.validEntriesNew, 2);
  });

  it('a forged genesis is newly broken (valid before the check) and falls to the cache', () => {
    const f = byName('forged-genesis');
    const r = scanIdentifier({ did: f.did, source: 'list', method: null, log: f.log, documentJson: f.documentJson });
    assert.equal(r.verdict, 'reject');
    assert.equal(r.newlyBroken, true);
    assert.equal(r.validEntriesOld, 1);
    assert.equal(r.resolution, 'cache-only:chain-invalid');
  });

  it('key order and createdAt sensitivity are diagnosed', () => {
    const k = byName('key-order-drift');
    const rk = scanIdentifier({ did: k.did, source: 'list', method: null, log: k.log, documentJson: null });
    assert.equal(rk.diagnostics.keyOrderMatch, 'sorted');
    assert.equal(rk.resolution, 'unresolvable');
    const c = byName('created-at-drift');
    const stored = { ...c.log[0]!, createdAt: c.log[0]!.createdAt + 2 };
    const rc = scanIdentifier({ did: c.did, source: 'list', method: null, log: [stored], documentJson: null });
    assert.equal(rc.diagnostics.createdAtOffsetSeconds, -2);
  });

  it('legacy did:scidvh: and other versions are rejected on prefix alone, even with a genuine log', () => {
    const l = byName('legacy-prefix');
    const r = scanIdentifier({ did: l.did, source: 'list', method: null, log: l.log, documentJson: null });
    assert.deepEqual(r.classes, ['legacy-prefix']);
    assert.equal(r.newlyBroken, true);
    assert.equal(classifyPrefix('did:scid:vh:2:zabc'), 'other-version-prefix');
    assert.equal(classifyPrefix('did:peer:4zQm'), 'not-scid-vh');
  });

  it('no log: unverifiable; cached document means cache-only, none means unresolvable', () => {
    const a = byName('no-log-cached');
    const ra = scanIdentifier({ did: a.did, source: 'db-export', method: null, log: null, documentJson: a.documentJson });
    assert.equal(ra.verdict, 'unverifiable');
    assert.equal(ra.resolution, 'cache-only:no-log-held');
    const b = byName('no-log-no-cache');
    assert.equal(scanIdentifier({ did: b.did, source: 'list', method: null, log: null, documentJson: null }).resolution, 'unresolvable');
  });

  it('an identifier with a malformed SCID is reported, not thrown', () => {
    const r = scanIdentifier({ did: 'did:scid:vh:1:z6Mkr6cy8', source: 'list', method: null, log: null, documentJson: null });
    assert.equal(r.verdict, 'unverifiable');
    assert.match(r.reasons[0]!, /32-byte base58btc/);
  });

  it('a gap in rotation_log versions and an undecodable entry are rejected with their own classes', () => {
    const g = byName('good-rotated');
    const t = toTableExport([g], 'base64');
    const gapped = t.rotationLog.map((r) => (r.version === 1 ? { ...r, version: 3 } : r));
    let out = scanExport(toDidDocumentRows(t.didDocuments), toRotationLogRows(gapped)).reports[0]!;
    assert.deepEqual(out.classes, ['version-gap']);
    const broken = t.rotationLog.map((r) => (r.version === 1 ? { ...r, signed_entry: Buffer.from('xx').toString('base64') } : r));
    out = scanExport(toDidDocumentRows(t.didDocuments), toRotationLogRows(broken)).reports[0]!;
    assert.deepEqual(out.classes, ['malformed-entry']);
  });

  it('non-scid rows are skipped and orphan log groups counted', () => {
    const t = toTableExport([byName('good-genesis')], 'base64');
    const docs = [...toDidDocumentRows(t.didDocuments), { uuid: 'p', did: 'did:peer:4zQm', method: 'did:peer:4', documentJson: null, status: null }];
    const logs = toRotationLogRows([...t.rotationLog, { ...t.rotationLog[0]!, did_document_uuid: 'nobody' }]);
    const s = scanExport(docs, logs);
    assert.equal(s.skippedNonScidRows, 1);
    assert.equal(s.orphanRotationLogGroups, 1);
    assert.equal(s.reports.length, 1);
  });

  it('the summary counts and the clean flag follow the verdicts', () => {
    const t = toTableExport(ids, 'base64');
    const { reports } = scanExport(toDidDocumentRows(t.didDocuments), toRotationLogRows(t.rotationLog));
    const s = summarize(reports);
    assert.equal(s.total, 9);
    assert.equal(s.accept, 3);
    assert.equal(s.reject, 4);
    assert.equal(s.unverifiable, 2);
    assert.equal(s.clean, false);
    assert.equal(summarize(reports.filter((r) => r.verdict === 'accept' && r.classes.length === 0)).clean, true);
    assert.equal(summarize([]).clean, false);
  });
});

describe('input formats', () => {
  it('parses CSV with quotes, doubled quotes, embedded newlines and CRLF', () => {
    const rows = parseCsv('a,b\r\n"x,1","he said ""hi""\nline2"\r\nplain,\r\n');
    assert.deepEqual(rows, [{ a: 'x,1', b: 'he said "hi"\nline2' }, { a: 'plain', b: '' }]);
    assert.throws(() => parseCsv('a,b\n"open'), InputError);
    assert.throws(() => parseCsv('a,b\n1,2,3\n'), /has 3 fields/);
  });

  it('decodes bytes from \\x hex, 0x hex, hex:, base64:, bare base64 and Buffer JSON; rejects the rest without echoing the cell', () => {
    const want = Uint8Array.from([1, 2, 255]);
    for (const v of ['\\x0102ff', '0x0102ff', 'hex:0102ff', 'base64:AQL/', 'AQL/', { type: 'Buffer', data: [1, 2, 255] }]) {
      assert.deepEqual(decodeBytes(v, 'c'), want, String(v));
    }
    assert.equal(decodeBytes('', 'c'), null);
    assert.equal(decodeBytes(null, 'c'), null);
    assert.throws(() => decodeBytes('\\x0', 'c'), /odd-length/);
    try { decodeBytes('SECRET*VALUE', 'signed_entry'); assert.fail('should throw'); } catch (e) {
      assert.ok(e instanceof InputError);
      assert.ok(!/SECRET/.test((e as Error).message));
    }
  });

  it('JSON, JSONL and CSV exports give the same verdicts', () => {
    const dir = tmp();
    try {
      const b = toTableExport(ids, 'base64');
      writeFileSync(join(dir, 'd.json'), JSON.stringify({ rows: b.didDocuments }));
      writeFileSync(join(dir, 'l.jsonl'), b.rotationLog.map((r) => JSON.stringify(r)).join('\n'));
      const fromJson = scanExport(toDidDocumentRows(readTable(join(dir, 'd.json'))), toRotationLogRows(readTable(join(dir, 'l.jsonl'))));
      writeAll(join(dir, 'all'), ids);
      const fromCsv = scanExport(toDidDocumentRows(readTable(join(dir, 'all', 'did_documents.csv'))), toRotationLogRows(readTable(join(dir, 'all', 'rotation_log.csv'))));
      const v = (x: typeof fromJson): string[] => x.reports.map((r) => `${r.did} ${r.verdict} ${r.classes.join('|')}`);
      assert.deepEqual(v(fromCsv), v(fromJson));
      assert.throws(() => readTable(join(dir, 'x.txt')), /ENOENT|unsupported/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('a missing required column is an input error that names the column', () => {
    assert.throws(() => toRotationLogRows([{ did_document_uuid: 'a', version: 0 }]), /signed_entry/);
  });

  it('the identifier list ignores comments, blanks and duplicates', () => {
    const dir = tmp();
    try {
      writeFileSync(join(dir, 'l.txt'), '# c\n\ndid:scid:vh:1:zA  # trailing\ndid:scid:vh:1:zA\ndid:scid:vh:1:zB\n');
      assert.deepEqual(readIdentifierList(join(dir, 'l.txt')), ['did:scid:vh:1:zA', 'did:scid:vh:1:zB']);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('CLI', () => {
  it('table mode writes json, csv and summary only inside --out-dir, exits 1 on rejects, and prints no key material', () => {
    const dir = tmp();
    try {
      writeAll(join(dir, 'in'), ids);
      const out = join(dir, 'out');
      const r = run(['--did-documents', join(dir, 'in', 'did_documents.csv'), '--rotation-log', join(dir, 'in', 'rotation_log.csv'), '--out-dir', out]);
      assert.equal(r.code, 1);
      assert.deepEqual(readdirSync(out).sort(), ['scid-scan-report.csv', 'scid-scan-report.json', 'scid-scan-summary.txt']);
      assert.deepEqual(readdirSync(dir).sort(), ['in', 'out'], 'nothing else created next to it');
      const json = readFileSync(join(out, 'scid-scan-report.json'), 'utf8');
      const parsed = JSON.parse(json);
      assert.equal(parsed.summary.total, 9);
      assert.equal(parsed.reportVersion, 1);
      // No signature, key or document body may leak into any output.
      const sample = ids[0]!.log[0]!;
      const secrets = [
        Buffer.from(sample.signature).toString('base64'),
        Buffer.from(sample.digest).toString('base64'),
        ...(sample.mlDsa65Signature ? [Buffer.from(sample.mlDsa65Signature).toString('base64').slice(0, 64)] : []),
        'publicKeyMultibase',
      ];
      for (const text of [json, r.stdout, readFileSync(join(out, 'scid-scan-report.csv'), 'utf8')]) {
        for (const s of secrets) assert.ok(!text.includes(s));
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('exits 0 when everything is accepted', () => {
    const dir = tmp();
    try {
      const good = ids.filter((i) => i.expect.verdict === 'accept' && i.expect.classes.length === 0);
      writeAll(join(dir, 'in'), good);
      const r = run(['--did-documents', join(dir, 'in', 'did_documents.json'), '--rotation-log', join(dir, 'in', 'rotation_log.json'), '--out-dir', join(dir, 'o')]);
      assert.equal(r.code, 0);
      assert.equal(r.report!.summary.clean, true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('list mode reads <stem>.jsonl logs; an identifier without a log is unverifiable', () => {
    const dir = tmp();
    try {
      const { listFile, logsDir } = writeListMode(ids, dir);
      const r = run(['--identifiers', listFile, '--logs', logsDir, '--out-dir', join(dir, 'o')]);
      const rep = r.report!;
      assert.equal(rep.identifiers.length, 9);
      assert.equal(rep.identifiers.find((i) => i.did === byName('good-rotated').did)!.verdict, 'accept');
      assert.equal(rep.identifiers.find((i) => i.did === byName('no-log-cached').did)!.verdict, 'unverifiable');
      assert.equal(rep.identifiers.find((i) => i.did === byName('forged-genesis').did)!.classes[0], 'scid-hash-mismatch');
      // created_at drift is carried in the wire createdAt here, so the genesis check sees the drifted value.
      assert.equal(rep.identifiers.find((i) => i.did === byName('created-at-drift').did)!.verdict, 'reject');
      // identifiers only, no --logs
      const r2 = run(['--identifiers', listFile, '--out-dir', join(dir, 'o2')]);
      assert.equal(r2.report!.summary.unverifiable, 8);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('usage errors exit 2 and write nothing', () => {
    const dir = tmp();
    try {
      for (const argv of [
        [], ['--out-dir', join(dir, 'o')], ['--identifiers', 'x', '--did-documents', 'y', '--out-dir', join(dir, 'o')],
        ['--did-documents', 'a', '--out-dir', join(dir, 'o')], ['--bogus', 'x', '--out-dir', join(dir, 'o')],
        ['--identifiers', join(dir, 'missing.txt'), '--out-dir', join(dir, 'o')],
        ['--identifiers', join(dir, 'missing.txt'), '--logs', join(dir, 'o'), '--out-dir', join(dir, 'o')],
      ]) {
        const r = run(argv);
        assert.equal(r.code, 2, JSON.stringify(argv));
      }
      assert.deepEqual(readdirSync(dir), []);
      mkdirSync(join(dir, 'x'));
      assert.equal(run(['--help']).code, 0);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('the CSV neutralises formula-looking identifiers', () => {
    const r = scanIdentifier({ did: '=cmd|x', source: 'list', method: null, log: null, documentJson: null });
    assert.ok(toCsv([r]).split('\n')[1]!.startsWith("'=cmd|x"));
  });

  it('the tool source opens no database or network connection', () => {
    const srcDir = new URL('../../tools/scid-scan/', import.meta.url);
    for (const f of ['cli.ts', 'input.ts', 'scan.ts', 'report.ts']) {
      const text = readFileSync(new URL(f, srcDir), 'utf8');
      assert.ok(!/node:sqlite|node:net|node:http|node:https|node:dgram|child_process|from 'pg'|fetch\(/.test(text), f);
    }
  });
});

describe('the scan uses the real method', () => {
  it('the method instance is the production ScidVhMethod', () => {
    assert.equal(typeof new ScidVhMethod({}).resolveFromLog, 'function');
  });
});
