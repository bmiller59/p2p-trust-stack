# did:scid:vh genesis-check scan (offline)

Checks, from exported files only, whether the genesis check in `ScidVhMethod.resolveFromLog` (and the
chain validation behind it) accepts each `did:scid:vh` identifier you hold, and why not when it does
not. It calls the real `scidMatchesGenesis`, `resolveFromLog` and chain validation from core. It opens
no database and no network connection, and writes only inside `--out-dir`.

The check requires: the identifier starts `did:scid:vh:1:`; the genesis entry is version 0; its document
`id` is the identifier; and the SCID equals `base58btc(sha256(...))` of the genesis entry with the id set
to `did:scid:vh:1:{SCID}`. The digest is plain `JSON.stringify` (not JCS), so it depends on the stored
key order and on `createdAt`.

## Run

From `packages/core`:

```
npm run scid-scan -- --did-documents did_documents.csv --rotation-log rotation_log.csv --out-dir ./scan-out
npm run scid-scan -- --identifiers ids.txt --logs ./logs --out-dir ./scan-out
node --conditions=development --experimental-strip-types --loader ./test-loader.mjs tools/scid-scan/make-fixtures.ts <dir>   # synthetic sample inputs
```

Exit status: 0 every identifier accepted, 1 any rejected or unverifiable, 2 usage or input error.
Outputs in `--out-dir`: `scid-scan-report.json`, `scid-scan-report.csv`, `scid-scan-summary.txt`.

## Exporting the two tables (operator; read-only)

Work from a backup or a read-only replica, never the live primary. Export only these columns; no key
material is needed. Run as a role with `SELECT` only.

PostgreSQL / YugabyteDB (utility-server), in `psql`:

```sql
BEGIN READ ONLY;
\copy (SELECT uuid, did, method, document_json, status FROM did_documents WHERE did LIKE 'did:scid%' OR method ILIKE '%scid%' ORDER BY did) TO 'did_documents.csv' CSV HEADER
\copy (SELECT uuid, did_document_uuid, version, encode(previous_hash,'base64') AS previous_hash, encode(new_public_key,'base64') AS new_public_key, encode(signed_entry,'base64') AS signed_entry, created_at FROM rotation_log ORDER BY did_document_uuid, version) TO 'rotation_log.csv' CSV HEADER
ROLLBACK;
```

An agent's SQLite database (open a copy with `sqlite3 -readonly`):

```sql
.mode csv
.headers on
.output did_documents.csv
SELECT uuid, did, method, document_json, status FROM did_documents WHERE did LIKE 'did:scid%' OR method LIKE '%scid%';
.output rotation_log.csv
SELECT did_document_uuid, version, '0x' || hex(previous_hash) AS previous_hash, '0x' || hex(new_public_key) AS new_public_key, '0x' || hex(signed_entry) AS signed_entry, created_at, uuid FROM rotation_log;
```

SQLite has no base64 function, so the binary columns are written as `'0x' || hex(col)`: the tool reads a
bare string as base64, never hex, so the `0x` prefix is required.

Table files may be `.csv`, `.json` (array of row objects, or `{"rows": [...]}`) or `.jsonl`. Columns are
matched by name; extra columns are ignored. Binary cells: `encode(col,'base64')` output (bare base64),
`\x<hex>` (psql default), `0x<hex>`, `hex:<hex>`, `base64:<b64>`, or a JSON Buffer object. Keep
`document_json` exactly as stored: re-serialising or re-ordering it changes the result.
Do not export by passing rows through a jsonb or JSON pretty-printer.

### List mode (identifiers plus log files)

`ids.txt`: one identifier per line (`#` comments allowed). `--logs` is a directory with one file per
identifier, named like the identifier with every character outside `[A-Za-z0-9._-]` replaced by `_`
(`did:scid:vh:1:zABC` becomes `did_scid_vh_1_zABC.jsonl`). The file is the log in wire form, as the
utility server serves it: one JSON object per line (or a `.json` array) with `version`, `parameters`,
`didDocument`, `prevHash`, `nextKeyCommitments`, `createdAt`, `digest`, `signature`, `mlDsa65Signature`
(byte fields base64). An identifier without a file is reported as unverifiable. List mode supplies no cached documents, so
`resolution` reads `unresolvable` there where a server may in fact hold a cached document.

## Reading the report

Per identifier:

- `verdict`: `accept` (genesis check passes), `reject` (it would be refused), `unverifiable` (no log
  supplied, so the check cannot be evaluated).
- `genesis_check`: `accept`, `reject` or `not-checkable`.
- `resolution`, what the resolver does after the check ships: `log` (verified replay), `log-truncated`
  (genesis accepted, chain valid only to an earlier version; unchanged by the check),
  `cache-only:chain-invalid` (log refused, cached `document_json` served as `source: cache`),
  `cache-only:no-log-held`, or `unresolvable` (refused and no cached document). Boundary resolvers
  refuse `cache`, so proofs by a cache-only identifier fail.
- `newly_broken` / `already_broken`: rejected only by the genesis check (valid under the previous chain
  validation) versus refused by the previous validation too.
- `classes` and `reasons`:
  - `legacy-prefix`: `did:scidvh:<scid>` form. `other-version-prefix`: `did:scid:vh:<not 1>:`.
    `not-scid-vh`: another method.
  - `no-log`: nothing to check.
  - `scid-hash-mismatch`: the SCID is not the hash of the genesis. Diagnostics: `key_order_match`
    (`sorted` or `jsonb`) means the SCID matches when the stored keys are re-ordered, so the stored
    document or parameters were re-serialised; `created_at_offset_s` means it matches with `createdAt`
    shifted by that many seconds, so the stored `created_at` is not the signed value (e.g. the push
    route's insertion second). If neither is set, treat the log as not belonging to the identifier.
  - `genesis-id-mismatch`, `genesis-version`: the genesis names a different id or is not version 0.
  - `genesis-digest`: the genesis' stored digest no longer matches its fields (altered or
    re-serialised after signing).
  - `genesis-signature`: digest fine, signature, ML-DSA signature or `prevHash` fails.
  - `chain-truncated`: genesis accepted, a later entry fails.
  - `version-gap`, `malformed-entry`: the rows cannot form a log.
- `mldsa_entries`: entries carrying an ML-DSA-65 signature, as `n/total`.

The summary lists counts, failure classes and `RESULT: clean` only when every scanned identifier is
accepted (no rejects and no unverifiable). Rejected identifiers: reissue or alias a prefix/format class;
repair the stored log or the push route for key-order and `createdAt` classes and re-scan; revoke or
ignore a genuine mismatch. Reports contain identifiers, counts and reasons only: no keys, signatures or
document bodies.
