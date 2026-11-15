// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Presentations received as a verifier (conformance phase P5b, migration 0024). One row per
 * presentation, keyed by its multibase digest; the thread (the verifier's nonce) is unique.
 * Portable statements only.
 */
import type { DataSource } from '../data-source.js';

export interface PresentationRow {
  id: string;
  threadId: string;
  holderDid: string;
  verifierDid: string;
  /** The presentation as stored (RFC 8785 text). */
  vpJson: string;
  issuers: string[];
  credentialCount: number;
  documentId: string | null;
  createdAt: number;
}

interface Raw {
  id: string;
  thread_id: string;
  holder_did: string;
  verifier_did: string;
  vp_json: string;
  issuers_json: string;
  credential_count: number | string;
  document_id: string | null;
  created_at: number | string;
}

const toRow = (r: Raw): PresentationRow => ({
  id: r.id,
  threadId: r.thread_id,
  holderDid: r.holder_did,
  verifierDid: r.verifier_did,
  vpJson: r.vp_json,
  issuers: JSON.parse(r.issuers_json) as string[],
  credentialCount: Number(r.credential_count),
  documentId: r.document_id,
  createdAt: Number(r.created_at),
});

export async function findByDigest(db: DataSource, id: string): Promise<PresentationRow | null> {
  const r = await db.get<Raw>('SELECT * FROM credential_presentations WHERE id = ?', id);
  return r === null || r === undefined ? null : toRow(r);
}

export async function findByThread(db: DataSource, threadId: string): Promise<PresentationRow | null> {
  const r = await db.get<Raw>('SELECT * FROM credential_presentations WHERE thread_id = ?', threadId);
  return r === null || r === undefined ? null : toRow(r);
}

export async function count(db: DataSource): Promise<number> {
  return Number((await db.get<{ n: number | string }>('SELECT COUNT(*) AS n FROM credential_presentations'))!.n);
}

export async function insert(db: DataSource, row: Omit<PresentationRow, 'createdAt' | 'documentId'> & { documentId?: string | undefined; now: number }): Promise<void> {
  await db.run(
    `INSERT INTO credential_presentations (id, thread_id, holder_did, verifier_did, vp_json, issuers_json, credential_count, document_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    row.id, row.threadId, row.holderDid, row.verifierDid, row.vpJson, JSON.stringify(row.issuers), row.credentialCount, row.documentId ?? null, row.now,
  );
}

export async function remove(db: DataSource, id: string): Promise<void> {
  await db.run('DELETE FROM credential_presentations WHERE id = ?', id);
}
