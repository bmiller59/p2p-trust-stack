-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0023_credential_presentations.sql
-- Storage for `credential-exchange/present/0.1` received as the verifier (conformance plan 06, phase P5b).
--
-- The registry text says the verifier retains the `vp_token` itself as the evidence that reliance on the
-- presentation was justified, and that the task has no response document. One additive table. `id` is the
-- multibase digest of the presentation as stored (named `id` on purpose: the distributed-database data
-- source appends `RETURNING id` to plain inserts). `thread_id` is the verifier's nonce (the presentation
-- proof's `challenge` equals it) and is UNIQUE: a nonce is single use, so a second DIFFERENT presentation on
-- the same thread is refused as stale. Times are epoch MILLISECONDS in BIGINT; no defaults, no DB-side
-- time, no upsert syntax. Reverting the code leaves the table in place; nothing else reads it.

CREATE TABLE IF NOT EXISTS credential_presentations (
  id                TEXT PRIMARY KEY,
  thread_id         TEXT NOT NULL,
  holder_did        TEXT NOT NULL,
  verifier_did      TEXT NOT NULL,
  vp_json           TEXT NOT NULL,
  issuers_json      TEXT NOT NULL,
  credential_count  INTEGER NOT NULL,
  document_id       TEXT,
  created_at        BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_presentations_thread ON credential_presentations(thread_id);
