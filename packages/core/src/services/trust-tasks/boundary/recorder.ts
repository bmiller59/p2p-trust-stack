// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Persistence of what the boundary processed (conformance plan 3.7, decision A4): the VERBATIM
 * received document, its proof, the digests and the verified signer go into the append-only
 * `trust_tasks` table (migration 0021 columns), and so does the signed reply as sent.
 *
 * Retention rule: a body refused BEFORE proof verification is never stored (it is unauthenticated
 * input that anyone could use to fill the table); only counters and a hashed sender are kept. A
 * document accepted, or refused after its proof verified (or after the duplicate claim), is stored
 * verbatim. A duplicate of a stored document is not stored again; a recording failure is reported
 * and never changes the answer (the duplicate record, not this log, is the replay defence).
 */
import { createHash } from 'node:crypto';
import type { DataSource } from '../../../db/data-source.js';
import * as trustTasksRepo from '../../../db/repositories/trust-tasks-repo.js';
import { documentDigest } from './runtime.js';
import type { PipelineResult } from './pipeline.js';
import { parseDateTimeStamp } from './datetime.js';
import { taskDigestMultibase } from './proof/digest.js';

export interface RefusalCounters {
  /** Bodies refused before proof verification, by wire code (never stored). */
  readonly byCode: Readonly<Record<string, number>>;
  readonly total: number;
  /** SHA-256 (hex, truncated) of the most recent in-band sender, never the identifier itself. */
  readonly lastSenderHash: string | undefined;
}

export interface TrustTaskRecorderOptions {
  /** Recorded with each row (`recorded_by_node`). */
  node?: string;
  /** Receives a recording failure; the answer is unaffected. */
  onError?: (err: unknown) => void;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);
const ms = (v: unknown): number | undefined => (typeof v === 'string' ? parseDateTimeStamp(v) : undefined);

export class TrustTaskRecorder {
  private readonly db: DataSource;
  private readonly options: TrustTaskRecorderOptions;
  private readonly counts: Record<string, number> = {};
  private total = 0;
  private lastHash: string | undefined;

  constructor(db: DataSource, options: TrustTaskRecorderOptions = {}) {
    this.db = db;
    this.options = options;
  }

  get counters(): RefusalCounters {
    return { byCode: { ...this.counts }, total: this.total, lastSenderHash: this.lastHash };
  }

  /** Record one pipeline result. Never throws. */
  async record(result: PipelineResult): Promise<void> {
    try {
      if (result.refusedBeforeProof) {
        this.count(result);
        return;
      }
      await this.store(result);
    } catch (err) {
      this.options.onError?.(err);
    }
  }

  private count(result: PipelineResult): void {
    const code = result.code ?? result.kind;
    this.counts[code] = (this.counts[code] ?? 0) + 1;
    this.total++;
    const issuer = str(result.received?.issuer);
    if (issuer !== undefined) this.lastHash = createHash('sha256').update(issuer).digest('hex').slice(0, 16);
  }

  private async store(result: PipelineResult): Promise<void> {
    const doc = result.received;
    if (doc === undefined || result.raw === undefined || result.kind === 'duplicate' || result.kind === 'inFlight') return;
    const id = str(doc.id);
    const type = str(doc.type);
    if (id === undefined || type === undefined) return;
    if ((await trustTasksRepo.findByUuid(this.db, id)) !== null) return;
    const reply = isObject(result.document) ? result.document : undefined;
    const errored = result.kind === 'error';
    const threadId = str(doc.threadId) ?? id;
    const issuedAt = ms(doc.issuedAt);
    const expiresAt = ms(doc.expiresAt);
    await trustTasksRepo.record(this.db, {
      uuid: id,
      threadId,
      type,
      direction: 'request',
      ...(str(doc.issuer) === undefined ? {} : { issuerDid: str(doc.issuer)! }),
      ...(str(doc.recipient) === undefined ? {} : { recipientDid: str(doc.recipient)! }),
      ...(str(doc.parentThreadId) === undefined ? {} : { parentThreadId: str(doc.parentThreadId)! }),
      ...(doc.payload === undefined ? {} : { payload: doc.payload }),
      ...(doc.proof === undefined ? {} : { proof: doc.proof }),
      status: 'recorded',
      ...(this.options.node === undefined ? {} : { recordedByNode: this.options.node }),
      rawDocument: result.raw,
      digest: documentDigest(doc as never),
      taskDigest: taskDigestMultibase(doc),
      ...(issuedAt === undefined ? {} : { issuedAt }),
      ...(expiresAt === undefined ? {} : { expiresAt }),
      ...(result.code === undefined ? {} : { errorCode: result.code }),
      disposition: result.kind,
      ...(result.verified === undefined ? {} : { verifiedSigner: result.verified.signer }),
      lifecycle: errored ? 'errored' : result.kind === 'response' ? 'responded' : 'accepted',
    });
    if (reply !== undefined && str(reply.id) !== undefined && str(reply.type) !== undefined && (await trustTasksRepo.findByUuid(this.db, str(reply.id)!)) === null) {
      const payload = isObject(reply.payload) ? reply.payload : undefined;
      await trustTasksRepo.record(this.db, {
        uuid: str(reply.id)!,
        threadId: str(reply.threadId) ?? threadId,
        type: str(reply.type)!,
        direction: 'response',
        ...(str(reply.issuer) === undefined ? {} : { issuerDid: str(reply.issuer)! }),
        ...(str(reply.recipient) === undefined ? {} : { recipientDid: str(reply.recipient)! }),
        ...(reply.payload === undefined ? {} : { payload: reply.payload }),
        ...(reply.proof === undefined ? {} : { proof: reply.proof }),
        status: errored ? 'failed' : 'completed',
        ...(this.options.node === undefined ? {} : { recordedByNode: this.options.node }),
        // The document exactly as the carrier sends it.
        rawDocument: JSON.stringify(reply),
        digest: documentDigest(reply as never),
        taskDigest: taskDigestMultibase(reply),
        ...(ms(reply.issuedAt) === undefined ? {} : { issuedAt: ms(reply.issuedAt)! }),
        inReplyTo: id,
        ...(errored && typeof payload?.code === 'string' ? { errorCode: payload.code } : {}),
        disposition: errored ? 'error' : 'response',
        lifecycle: errored ? 'errored' : 'responded',
      });
    }
  }
}
