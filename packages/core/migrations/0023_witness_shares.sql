-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0023_witness_shares.sql
-- Storage for the suite-local `vrc/relationships/witness-share` task (conformance plan 06, phase P7).
--
-- A party hands its counterparty the Verifiable Witness Credential (VWC) it earned in a witnessed
-- relationship exchange, together with the pair of documents that evidences the witnessing. The
-- receiver verifies the pairing and only then stores. Two new tables, both additive:
--
-- 1. `witnessed_credentials`: the credential kind `vwc`. It is a table of its own, not a new
--    `credentials.vc_type`, because that column carries a CHECK constraint that SQLite can only
--    change by rebuilding a replicated table. The row exists only after every check passed ("earned
--    by verification, never granted on receipt"). `id` is the multibase digest of the credential
--    AS STORED (the primary key column is named `id` on purpose: the distributed-database data
--    source appends `RETURNING id` to plain inserts). `exchange_id` is UNIQUE: one share per
--    exchange, because the sharing party is fixed by the exchange and has one VWC.
-- 2. `witness_share_evidence`: the initiating and terminal documents and the presentation exactly as
--    received (member order preserved), keyed by the credential digest, so the pairing can be
--    re-shown later. A verifier cannot recompute the task digest without the initiating document.
--
-- Times are epoch MILLISECONDS in BIGINT. No defaults, no DB-side time, no upsert syntax: the file
-- is dialect-neutral. A recorded schema version newer than the code refuses to start, so reverting
-- the code after this lands leaves the (empty or populated) tables in place; they are not read by
-- any other code.

CREATE TABLE IF NOT EXISTS witnessed_credentials (
  id                   TEXT PRIMARY KEY,
  exchange_id          TEXT NOT NULL,
  kind                 TEXT NOT NULL,
  subject_did          TEXT NOT NULL,
  witness_did          TEXT NOT NULL,
  sender_connection_did TEXT NOT NULL,
  w3c_vc_json          TEXT NOT NULL,
  witness_verified     INTEGER NOT NULL,
  share_document_id    TEXT,
  created_at           BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_witnessed_credentials_exchange ON witnessed_credentials(exchange_id);

CREATE TABLE IF NOT EXISTS witness_share_evidence (
  id                TEXT PRIMARY KEY,
  exchange_id       TEXT NOT NULL,
  presentation_json TEXT NOT NULL,
  initiating_json   TEXT NOT NULL,
  terminal_json     TEXT NOT NULL,
  created_at        BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_witness_share_evidence_exchange ON witness_share_evidence(exchange_id);
