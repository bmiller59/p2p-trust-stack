// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Witnessed credentials (kind `vwc`) and the evidence that earned them (conformance phase P7,
 * migration 0022). `insert` writes the credential and its evidence in one transaction, so a
 * credential never exists without the pair that evidences it. Portable statements only.
 */
import type { DataSource } from '../data-source.js';

export interface WitnessedCredentialRow {
  /** Multibase digest of the credential as stored. */
  id: string;
  exchangeId: string;
  kind: 'vwc';
  subjectDid: string;
  witnessDid: string;
  senderConnectionDid: string;
  /** The credential as stored (RFC 8785 text). */
  w3cVcJson: string;
  witnessVerified: boolean;
  shareDocumentId: string | null;
  createdAt: number;
}

export interface WitnessShareEvidenceRow {
  id: string;
  exchangeId: string;
  presentationJson: string;
  initiatingJson: string;
  terminalJson: string;
  createdAt: number;
}

export interface InsertWitnessShare {
  id: string;
  exchangeId: string;
  subjectDid: string;
  witnessDid: string;
  senderConnectionDid: string;
  w3cVcJson: string;
  shareDocumentId?: string | undefined;
  presentationJson: string;
  initiatingJson: string;
  terminalJson: string;
  now?: number;
}

interface RawCredential {
  id: string;
  exchange_id: string;
  kind: string;
  subject_did: string;
  witness_did: string;
  sender_connection_did: string;
  w3c_vc_json: string;
  witness_verified: number | string;
  share_document_id: string | null;
  created_at: number | string;
}

const toCredential = (r: RawCredential): WitnessedCredentialRow => ({
  id: r.id,
  exchangeId: r.exchange_id,
  kind: 'vwc',
  subjectDid: r.subject_did,
  witnessDid: r.witness_did,
  senderConnectionDid: r.sender_connection_did,
  w3cVcJson: r.w3c_vc_json,
  witnessVerified: Number(r.witness_verified) === 1,
  shareDocumentId: r.share_document_id,
  createdAt: Number(r.created_at),
});

export async function findByDigest(db: DataSource, digest: string): Promise<WitnessedCredentialRow | null> {
  const row = await db.get<RawCredential>('SELECT * FROM witnessed_credentials WHERE id = ?', digest);
  return row === null || row === undefined ? null : toCredential(row);
}

export async function findByExchange(db: DataSource, exchangeId: string): Promise<WitnessedCredentialRow | null> {
  const row = await db.get<RawCredential>('SELECT * FROM witnessed_credentials WHERE exchange_id = ?', exchangeId);
  return row === null || row === undefined ? null : toCredential(row);
}

export async function count(db: DataSource): Promise<number> {
  return Number((await db.get<{ n: number | string }>('SELECT COUNT(*) AS n FROM witnessed_credentials'))!.n);
}

export async function findEvidence(db: DataSource, digest: string): Promise<WitnessShareEvidenceRow | null> {
  const r = await db.get<{ id: string; exchange_id: string; presentation_json: string; initiating_json: string; terminal_json: string; created_at: number | string }>(
    'SELECT * FROM witness_share_evidence WHERE id = ?',
    digest,
  );
  if (r === null || r === undefined) return null;
  return { id: r.id, exchangeId: r.exchange_id, presentationJson: r.presentation_json, initiatingJson: r.initiating_json, terminalJson: r.terminal_json, createdAt: Number(r.created_at) };
}

/** Store the credential and its evidence together. The caller has already checked for an existing row. */
export async function insert(db: DataSource, input: InsertWitnessShare): Promise<void> {
  const now = input.now ?? Date.now();
  await db.transaction(async (tx) => {
    await tx.run(
      `INSERT INTO witnessed_credentials
         (id, exchange_id, kind, subject_did, witness_did, sender_connection_did, w3c_vc_json, witness_verified, share_document_id, created_at)
       VALUES (?, ?, 'vwc', ?, ?, ?, ?, 1, ?, ?)`,
      input.id,
      input.exchangeId,
      input.subjectDid,
      input.witnessDid,
      input.senderConnectionDid,
      input.w3cVcJson,
      input.shareDocumentId ?? null,
      now,
    );
    await tx.run(
      `INSERT INTO witness_share_evidence (id, exchange_id, presentation_json, initiating_json, terminal_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      input.id,
      input.exchangeId,
      input.presentationJson,
      input.initiatingJson,
      input.terminalJson,
      now,
    );
  });
}
