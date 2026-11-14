// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The retained-document accessor (conformance phase P8c, plan 3.7 decision A4): read back what the
 * boundary kept in the append-only `trust_tasks` table, by document id or by thread. The request is
 * the VERBATIM text the carrier delivered (never a re-serialisation), the reply is the signed document
 * exactly as sent, and a request carries the signer the pipeline verified. A document refused before
 * its proof was verified was never stored, so it is not here.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import * as trustTasksRepo from '@p2p-trust-stack/core/db/repositories/trust-tasks-repo.js';
import type { TrustTaskRow } from '@p2p-trust-stack/core/db/repositories/trust-tasks-repo.js';

export interface RetainedDocument {
  id: string;
  threadId: string;
  direction: 'request' | 'response';
  type: string;
  /** The document exactly as received (request) or as sent (reply); null if no verbatim copy was kept. */
  verbatim: string | null;
  /** The identifier whose proof the pipeline verified on this request; null on a reply or an unsigned request. */
  verifiedSigner: string | null;
  issuer: string | null;
  recipient: string | null;
  /** The id of the request a reply answers. */
  inReplyTo: string | null;
  digest: string | null;
  taskDigest: string | null;
  disposition: string | null;
  lifecycle: string | null;
  errorCode: string | null;
}

const toRetained = (r: TrustTaskRow): RetainedDocument => ({
  id: r.uuid,
  threadId: r.threadId,
  direction: r.direction,
  type: r.type,
  verbatim: r.rawDocument,
  verifiedSigner: r.verifiedSigner,
  issuer: r.issuerDid,
  recipient: r.recipientDid,
  inReplyTo: r.inReplyTo,
  digest: r.digest,
  taskDigest: r.taskDigest,
  disposition: r.disposition,
  lifecycle: r.lifecycle,
  errorCode: r.errorCode,
});

export class RetainedDocuments {
  private readonly db: DataSource;
  constructor(db: DataSource) {
    this.db = db;
  }

  /** One retained document by its id, or null. */
  async byId(id: string): Promise<RetainedDocument | null> {
    const row = await trustTasksRepo.findByUuid(this.db, id);
    return row === null ? null : toRetained(row);
  }

  /** Every retained document of a thread (the repository orders by whole-second record time, then id). */
  async byThread(threadId: string): Promise<RetainedDocument[]> {
    return (await trustTasksRepo.listByThread(this.db, threadId)).map(toRetained);
  }

  /** The reply retained for a request id (the signed bytes that went out), or null. */
  async replyTo(requestId: string): Promise<RetainedDocument | null> {
    const row = await this.db.get<{ uuid: string }>('SELECT uuid FROM trust_tasks WHERE in_reply_to = ? LIMIT 1', requestId);
    return row === null || row === undefined ? null : this.byId(row.uuid);
  }
}
