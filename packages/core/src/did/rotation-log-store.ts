// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * RotationLogStore — key rotation history persistence using the shared
 * P2PTS migration table `rotation_log` (0004).
 *
 * Maps agent-specific rotation data into the standard P2PTS rotation_log schema:
 *   - did_document_id FK → the DID document being rotated
 *   - version → rotation version number (1-based, auto-incremented)
 *   - new_public_key → the new Ed25519 public key (BLOB)
 *   - signed_entry → the full signed rotation entry (BLOB)
 *   - previous_hash → hash link to prior entry
 *
 * Agent-specific payloads (did_document_json, digest, signature) are stored
 * in the existing `new_public_key`/`signed_entry` columns where the standard
 * schema already accommodates rotation commit data.
 */

import type { DatabaseSync } from 'node:sqlite';
import type { IdentityResolver } from '../services/identity-resolver.js';
import type { DidDocument } from './types.js';
import type { RotationLogEntry } from './rotation-types.js';
import { packRotationEntry, unpackRotationEntry } from './rotation-entry-codec.js';
import { generateUuid } from '../db/uuid-helpers.js';

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

interface RotationLogRow {
  uuid: string;
  did_document_uuid: string;
  version: number;
  previous_hash: Buffer | Uint8Array | null;
  new_public_key: Buffer | Uint8Array;
  signed_entry: Buffer | Uint8Array;
  created_at: number | null;
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

function packSignedEntry(
  didDocument: DidDocument,
  parameters: import('./types.js').DidParameters | undefined,
  digest: Uint8Array,
  signature: Uint8Array,
  mlDsa65Signature?: Uint8Array,
): Uint8Array {
  // Layout (incl. the optional ML-DSA-65 tail) lives in rotation-entry-codec.
  return packRotationEntry({ didDocument, parameters, digest, signature, mlDsa65Signature });
}

function unpackSignedEntry(packed: Uint8Array): {
  parameters?: import('./types.js').DidParameters;
  didDocument: DidDocument;
  digest: Uint8Array;
  signature: Uint8Array;
  mlDsa65Signature?: Uint8Array;
} {
  // One reader for the blob layout, including the optional ML-DSA-65 tail, which
  // fails closed on a damaged or unknown tail (see rotation-entry-codec).
  return unpackRotationEntry(packed);
}

function parseNextKeyCommitments(raw: Uint8Array): Uint8Array[] {
  try {
    const json = new TextDecoder().decode(raw);
    const arr = JSON.parse(json) as string[];
    return arr.map(b64 => new Uint8Array(Buffer.from(b64, 'base64')));
  } catch {
    // Legacy single-key format: raw bytes as one commitment
    return [new Uint8Array(raw)];
  }
}

function rowToEntry(row: RotationLogRow): RotationLogEntry {
  const unpacked = unpackSignedEntry(new Uint8Array(row.signed_entry));

  return {
    version: row.version,
    parameters: unpacked.parameters,
    didDocument: unpacked.didDocument,
    prevHash: row.previous_hash ? new Uint8Array(row.previous_hash) : null,
    nextKeyCommitments: parseNextKeyCommitments(new Uint8Array(row.new_public_key)),
    createdAt: row.created_at ?? 0,
    digest: unpacked.digest,
    signature: unpacked.signature,
    mlDsa65Signature: unpacked.mlDsa65Signature,
    witnessAttestations: [],
  };
}

// ---------------------------------------------------------------------------
// RotationLogStore
// ---------------------------------------------------------------------------

export class RotationLogStore {
  private readonly db: DatabaseSync;
  private readonly resolver: IdentityResolver;

  constructor(db: DatabaseSync, resolver: IdentityResolver) {
    this.db = db;
    this.resolver = resolver;
  }

  /**
   * Append a new rotation entry. Version auto-increments from the previous
   * highest version for this DID document.
   */
  appendEntry(did: string, entry: RotationLogEntry): void {
    const resolved = this.resolver.lookupByDid(did);
    if (!resolved || !resolved.didDocumentUuid) {
      throw new Error(`RotationLogStore.appendEntry: DID document not found for "${did}"`);
    }

    // Use the entry's own version number (0 for genesis, N for rotation).
    const version = entry.version;

    const packed = packSignedEntry(entry.didDocument, entry.parameters, entry.digest, entry.signature, entry.mlDsa65Signature);
    const uuid = generateUuid();

    this.db.prepare(`
      INSERT INTO rotation_log
        (did_document_uuid, version, previous_hash,
         new_public_key, signed_entry, uuid, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      resolved.didDocumentUuid,
      version,
      entry.prevHash,
      Buffer.from(JSON.stringify(entry.nextKeyCommitments.map(k => Buffer.from(k).toString('base64')))),
      packed,
      uuid,
      entry.createdAt,
    );
  }

  /** Return the full rotation log for a DID, ordered by version ascending. */
  getLog(did: string): RotationLogEntry[] {
    const resolved = this.resolver.lookupByDid(did);
    if (!resolved || !resolved.didDocumentUuid) return [];

    const rows = this.db.prepare(`
      SELECT * FROM rotation_log
      WHERE did_document_uuid = ?
      ORDER BY version ASC
    `).all(resolved.didDocumentUuid) as unknown as RotationLogRow[];

    return rows.map(rowToEntry);
  }

  /** Return the latest (highest-version) entry, or undefined. */
  getLatestEntry(did: string): RotationLogEntry | undefined {
    const resolved = this.resolver.lookupByDid(did);
    if (!resolved || !resolved.didDocumentUuid) return undefined;

    const row = this.db.prepare(`
      SELECT * FROM rotation_log
      WHERE did_document_uuid = ?
      ORDER BY version DESC LIMIT 1
    `).get(resolved.didDocumentUuid) as RotationLogRow | undefined;

    return row ? rowToEntry(row) : undefined;
  }
}