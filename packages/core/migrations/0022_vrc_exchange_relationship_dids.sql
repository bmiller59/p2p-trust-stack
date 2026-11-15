-- SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0022_vrc_exchange_relationship_dids.sql
-- The per-VRC relationship-DID mapping of the opt-in Trust Task boundary module (conformance plan 06,
-- decision 35), keyed by the `vrc/relationships/propose` document id (the exchange / thread id).
-- Stores both connection DIDs, both per-exchange relationship DIDs, the role, the exchange state and
-- the root identity. One additive table; deployments that do not run the module never write to it.
--
-- Additive and dialect-neutral (no defaults, no DB-side time). Reverting the code after this lands
-- does not remove the table.

CREATE TABLE IF NOT EXISTS vrc_exchange_relationship_dids (
  exchange_id               TEXT PRIMARY KEY,
  local_connection_did      TEXT NOT NULL,
  remote_connection_did     TEXT NOT NULL,
  local_relationship_did    TEXT NOT NULL,
  remote_relationship_did   TEXT,
  local_identity_uuid       TEXT,
  remote_identity_uuid      TEXT,
  role                      TEXT NOT NULL,
  state                     TEXT NOT NULL,
  recorded_by_node          TEXT,
  created_at                BIGINT NOT NULL,
  updated_at                BIGINT NOT NULL,
  UNIQUE(local_relationship_did),
  UNIQUE(remote_relationship_did)
);

CREATE INDEX IF NOT EXISTS idx_vred_connections ON vrc_exchange_relationship_dids(local_connection_did, remote_connection_did);
