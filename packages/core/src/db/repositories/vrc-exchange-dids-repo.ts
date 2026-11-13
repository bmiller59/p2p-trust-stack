// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: `vrc_exchange_relationship_dids` (migration 0021). The per-VRC relationship-DID mapping
 * of conformance plan 3.10 and decision 35: one row per VRC exchange, keyed by the `propose` document
 * id (the exchange / thread id), holding both connection DIDs, both relationship DIDs, the role and
 * the state, and the root identity each relationship DID belongs to.
 *
 * Schema and access only. There is no minting here (phase P5c): this module stores what it is given and
 * refuses a relationship DID that has already been used, in either direction. The column-level UNIQUE
 * constraints catch reuse in the same column; reuse across columns (a counterparty offering the DID that
 * is ours, or the reverse) is checked here. Portable statements only (no upsert syntax; timestamps from
 * the caller); the check and the insert run in one `db.transaction`.
 */
import type { DataSource } from '../data-source.js';

export type ExchangeRole = 'proposer' | 'acceptor';
export type ExchangeState = 'proposed' | 'accepted' | 'issued-by-me' | 'received' | 'ended';

export interface ExchangeDidRow {
  exchangeId: string;
  localConnectionDid: string;
  remoteConnectionDid: string;
  localRelationshipDid: string;
  remoteRelationshipDid: string | null;
  localIdentityUuid: string | null;
  remoteIdentityUuid: string | null;
  role: ExchangeRole;
  state: ExchangeState;
  recordedByNode: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface CreateExchangeInput {
  exchangeId: string;
  localConnectionDid: string;
  remoteConnectionDid: string;
  localRelationshipDid: string;
  remoteRelationshipDid?: string;
  localIdentityUuid?: string;
  remoteIdentityUuid?: string;
  role: ExchangeRole;
  state?: ExchangeState;
  recordedByNode?: string;
  now?: number;
}

/** A relationship DID was offered that another exchange already holds (either side), or equals a connection DID. */
export class RelationshipDidReuseError extends Error {
  readonly did: string;
  constructor(did: string, reason: string) {
    super(`relationship DID refused: ${reason}`);
    this.name = 'RelationshipDidReuseError';
    this.did = did;
  }
}

interface RawRow {
  exchange_id: string;
  local_connection_did: string;
  remote_connection_did: string;
  local_relationship_did: string;
  remote_relationship_did: string | null;
  local_identity_uuid: string | null;
  remote_identity_uuid: string | null;
  role: string;
  state: string;
  recorded_by_node: string | null;
  created_at: number | string;
  updated_at: number | string;
}

const toRow = (r: RawRow): ExchangeDidRow => ({
  exchangeId: r.exchange_id,
  localConnectionDid: r.local_connection_did,
  remoteConnectionDid: r.remote_connection_did,
  localRelationshipDid: r.local_relationship_did,
  remoteRelationshipDid: r.remote_relationship_did,
  localIdentityUuid: r.local_identity_uuid,
  remoteIdentityUuid: r.remote_identity_uuid,
  role: r.role as ExchangeRole,
  state: r.state as ExchangeState,
  recordedByNode: r.recorded_by_node,
  createdAt: Number(r.created_at),
  updatedAt: Number(r.updated_at),
});

/** The exchange that holds `did` on either side, optionally ignoring one exchange (the row being updated). */
async function holder(db: DataSource, did: string, exceptExchangeId?: string): Promise<ExchangeDidRow | null> {
  const rows = await db.all<RawRow>(
    'SELECT * FROM vrc_exchange_relationship_dids WHERE local_relationship_did = ? OR remote_relationship_did = ?',
    did,
    did,
  );
  const hit = rows.find((r) => r.exchange_id !== exceptExchangeId);
  return hit === undefined ? null : toRow(hit);
}

async function assertUsable(db: DataSource, did: string, connectionDids: readonly string[], exceptExchangeId?: string): Promise<void> {
  if (connectionDids.includes(did)) throw new RelationshipDidReuseError(did, 'it equals a connection DID of the exchange');
  if ((await holder(db, did, exceptExchangeId)) !== null) throw new RelationshipDidReuseError(did, 'it is already held by another exchange');
}

/** Record a new exchange. The mapping is durable when this resolves (it must be, before the DID is sent). */
export async function create(db: DataSource, input: CreateExchangeInput): Promise<ExchangeDidRow> {
  const now = input.now ?? Date.now();
  const connections = [input.localConnectionDid, input.remoteConnectionDid];
  if (input.localRelationshipDid === input.remoteRelationshipDid) {
    throw new RelationshipDidReuseError(input.localRelationshipDid, 'both sides of an exchange name the same DID');
  }
  await db.transaction(async (tx) => {
    await assertUsable(tx, input.localRelationshipDid, connections);
    if (input.remoteRelationshipDid !== undefined) await assertUsable(tx, input.remoteRelationshipDid, connections);
    await tx.run(
      `INSERT INTO vrc_exchange_relationship_dids
         (exchange_id, local_connection_did, remote_connection_did, local_relationship_did,
          remote_relationship_did, local_identity_uuid, remote_identity_uuid, role, state,
          recorded_by_node, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      input.exchangeId,
      input.localConnectionDid,
      input.remoteConnectionDid,
      input.localRelationshipDid,
      input.remoteRelationshipDid ?? null,
      input.localIdentityUuid ?? null,
      input.remoteIdentityUuid ?? null,
      input.role,
      input.state ?? 'proposed',
      input.recordedByNode ?? null,
      now,
      now,
    );
  });
  return (await findByExchangeId(db, input.exchangeId))!;
}

export async function findByExchangeId(db: DataSource, exchangeId: string): Promise<ExchangeDidRow | null> {
  const row = await db.get<RawRow>('SELECT * FROM vrc_exchange_relationship_dids WHERE exchange_id = ?', exchangeId);
  return row === null ? null : toRow(row);
}

/** The exchange that holds `did` as its own or its counterparty's relationship DID. */
export async function findByRelationshipDid(db: DataSource, did: string): Promise<ExchangeDidRow | null> {
  return holder(db, did);
}

/** Every exchange between two connection DIDs, oldest first (a second exchange is a new row). */
export async function listByConnections(db: DataSource, localConnectionDid: string, remoteConnectionDid: string): Promise<ExchangeDidRow[]> {
  const rows = await db.all<RawRow>(
    `SELECT * FROM vrc_exchange_relationship_dids
      WHERE local_connection_did = ? AND remote_connection_did = ? ORDER BY created_at, exchange_id`,
    localConnectionDid,
    remoteConnectionDid,
  );
  return rows.map(toRow);
}

/** Record the counterparty's relationship DID once it is known; refused when reused or already set differently. */
export async function setRemoteRelationshipDid(db: DataSource, exchangeId: string, did: string, now: number = Date.now()): Promise<ExchangeDidRow> {
  await db.transaction(async (tx) => {
    const row = await findByExchangeId(tx, exchangeId);
    if (row === null) throw new Error(`no such exchange: ${exchangeId}`);
    if (row.remoteRelationshipDid !== null && row.remoteRelationshipDid !== did) {
      throw new RelationshipDidReuseError(did, 'the exchange already records a different counterparty DID');
    }
    await assertUsable(tx, did, [row.localConnectionDid, row.remoteConnectionDid], exchangeId);
    if (did === row.localRelationshipDid) throw new RelationshipDidReuseError(did, 'it is our own relationship DID');
    await tx.run('UPDATE vrc_exchange_relationship_dids SET remote_relationship_did = ?, updated_at = ? WHERE exchange_id = ?', did, now, exchangeId);
  });
  return (await findByExchangeId(db, exchangeId))!;
}

export async function setState(db: DataSource, exchangeId: string, state: ExchangeState, now: number = Date.now()): Promise<void> {
  await db.run('UPDATE vrc_exchange_relationship_dids SET state = ?, updated_at = ? WHERE exchange_id = ?', state, now, exchangeId);
}
