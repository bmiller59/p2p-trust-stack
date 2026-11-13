// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The durable duplicate record (framework 7.2 item 11; conformance plan 3.5): the registry runtime's
 * `ReplayGuard` over a `DataSource`, so one class serves the agent and core (SQLite) and the utility
 * server (a distributed SQL database), table `trust_task_accepted` (migration 0021).
 *
 * Dialect rule (utility-server `session-store.ts`): no `INSERT OR IGNORE`, no `ON CONFLICT`, no
 * DB-side time. The claim is a PLAIN INSERT whose primary-key violation is CAUGHT, after which the row
 * is read again to say what the loser sees. The error is never classified by code, so the same path
 * serves SQLite (UNIQUE constraint) and Postgres dialects (23505). Replacing an expired row is a
 * delete plus insert inside `db.transaction`; if that transaction fails (a concurrent claim won), the
 * row is read again as well. The key column is `id`: the distributed data source appends
 * `RETURNING id` to plain inserts.
 *
 * Fail closed: any error that leaves the row unreadable is rethrown, which the runtime maps to
 * `unavailable` (retryable). The store never answers `fresh` when it could not establish the state.
 *
 * Window: `retainUntil` comes from the runtime (`expiresAt`, else `issuedAt` + max age + skew,
 * clamped to the expiry horizon; with no `issuedAt` the window runs from first sight). The store
 * clamps again to `now` + horizon + skew, a backstop against a caller passing an unbounded value. A row
 * is live while `now < retain_until` (half-open) and is treated as absent afterwards.
 */
import type { DataSource } from "../../../db/data-source.js";
import { EXPIRY_HORIZON_MS, SKEW_MS } from "./pins.js";
import type { ReplayGuard, ReplayVerdict } from "./runtime.js";

export type AcceptedState = "claimed" | "completed";

/** The outcome values the settle sweep reads from the coordinator (`TransactionManager.getOutcome`). */
export type SettleOutcome = "committed" | "aborted" | "inFlight" | "unknown";

export interface AcceptedRow {
  id: string;
  digest: string;
  issuer: string | null;
  type: string | null;
  threadId: string | null;
  txId: string | null;
  state: AcceptedState;
  retainUntil: number;
  response: string | null;
  createdAt: number;
  updatedAt: number;
}

interface RawRow {
  id: string;
  digest: string;
  issuer: string | null;
  type: string | null;
  thread_id: string | null;
  tx_id: string | null;
  state: string;
  retain_until: number | string;
  response: string | null;
  created_at: number | string;
  updated_at: number | string;
}

const toRow = (r: RawRow): AcceptedRow => ({
  id: r.id,
  digest: r.digest,
  issuer: r.issuer,
  type: r.type,
  threadId: r.thread_id,
  txId: r.tx_id,
  state: r.state === "completed" ? "completed" : "claimed",
  retainUntil: Number(r.retain_until),
  response: r.response,
  createdAt: Number(r.created_at),
  updatedAt: Number(r.updated_at),
});

export interface AcceptedStoreOptions {
  /** Whether a response is kept for answering duplicates; false for a response that is secret. */
  keepResponse?: (response: unknown) => boolean;
  /** Replacement attempts after a lost race before the store gives up (fail closed). */
  maxAttempts?: number;
  /** Clock for calls that are not given `now` (the sweep and prune hooks); defaults to `Date.now`. */
  now?: () => number;
}

/** Verdict for an existing live row. */
function verdictFor(row: AcceptedRow, digest: string): ReplayVerdict {
  if (row.digest !== digest) return { kind: "conflict" };
  if (row.state === "claimed") return { kind: "duplicate", inFlight: true };
  if (row.response === null) return { kind: "duplicate", inFlight: false };
  return { kind: "duplicate", inFlight: false, priorResponse: JSON.parse(row.response) as unknown };
}

export class AcceptedIdStore implements ReplayGuard {
  private readonly db: DataSource;
  private readonly keepResponse: (response: unknown) => boolean;
  private readonly maxAttempts: number;
  private readonly clock: () => number;
  /** Context for the next claim of an id, set by `describe` (type and thread are not in the guard interface). */
  private readonly context = new Map<string, { type?: string; threadId?: string }>();

  constructor(db: DataSource, options: AcceptedStoreOptions = {}) {
    this.db = db;
    this.keepResponse = options.keepResponse ?? (() => true);
    this.maxAttempts = options.maxAttempts ?? 3;
    this.clock = options.now ?? Date.now;
  }

  /** Record the type and thread of a document before it is claimed (informational columns only). */
  describe(id: string, info: { type?: string; threadId?: string }): void {
    this.context.set(id, info);
    if (this.context.size > 1024) this.context.delete(this.context.keys().next().value as string);
  }

  async find(id: string): Promise<AcceptedRow | null> {
    const raw = await this.db.get<RawRow>("SELECT * FROM trust_task_accepted WHERE id = ?", id);
    return raw === null ? null : toRow(raw);
  }

  claim(id: string, digest: string, retainUntil: number | undefined, now: number): Promise<ReplayVerdict> {
    return this.claimFor(undefined, id, digest, retainUntil, now);
  }

  async claimFor(issuer: string | undefined, id: string, digest: string, retainUntil: number | undefined, now: number): Promise<ReplayVerdict> {
    if (retainUntil === undefined) throw new Error("a claim needs a retention deadline");
    const until = Math.min(retainUntil, now + EXPIRY_HORIZON_MS + SKEW_MS);
    const info = this.context.get(id);
    this.context.delete(id);
    const row = (): unknown[] => [id, digest, issuer ?? null, info?.type ?? null, info?.threadId ?? null, null, "claimed", until, null, now, now];
    const insert = "INSERT INTO trust_task_accepted (id, digest, issuer, type, thread_id, tx_id, state, retain_until, response, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    let lastError: unknown;
    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      // The read fails closed: an error here propagates and the caller answers `unavailable`.
      const existing = await this.find(id);
      if (existing !== null && now < existing.retainUntil) return verdictFor(existing, digest);

      try {
        if (existing === null) {
          await this.db.run(insert, ...row());
        } else {
          // Expired row: delete and insert in one transaction, the delete conditioned on expiry so a
          // row that a concurrent claim refreshed is not removed.
          await this.db.transaction(async (tx) => {
            await tx.run("DELETE FROM trust_task_accepted WHERE id = ? AND retain_until <= ?", id, now);
            await tx.run(insert, ...row());
          });
        }
        return { kind: "fresh" };
      } catch (err) {
        // Primary-key violation (or a lost transaction race): read the row again and decide from it.
        lastError = err;
        const winner = await this.find(id);
        if (winner !== null && now < winner.retainUntil) return verdictFor(winner, digest);
        // No live row to explain the failure: a real fault, or a race that left the slot empty. Retry.
      }
    }
    throw lastError instanceof Error ? lastError : new Error("the duplicate record could not be written");
  }

  /** Attach the coordinator transaction to a claimed id (the settle sweep reads it). */
  async attachTx(id: string, txId: string, now: number = this.clock()): Promise<void> {
    await this.db.run("UPDATE trust_task_accepted SET tx_id = ?, updated_at = ? WHERE id = ?", txId, now, id);
  }

  async recordResponse(id: string, response: unknown): Promise<void> {
    const body = this.keepResponse(response) ? JSON.stringify(response) : null;
    await this.db.run("UPDATE trust_task_accepted SET state = 'completed', response = ?, updated_at = ? WHERE id = ?", body, this.clock(), id);
  }

  /** Release a claim that is not to stand (a `retryable: true` failure). Only an unfinished claim is released. */
  async release(id: string, digest: string): Promise<void> {
    await this.db.run("DELETE FROM trust_task_accepted WHERE id = ? AND digest = ? AND state = 'claimed'", id, digest);
  }

  /** Janitor hook: drop rows whose window has closed. Returns the number removed. */
  async pruneExpired(now: number = this.clock()): Promise<number> {
    const result = await this.db.run("DELETE FROM trust_task_accepted WHERE retain_until <= ?", now);
    return result.changes;
  }

  /** Claims that name a transaction and have not completed (input of the settle sweep). */
  async listClaimedWithTx(now: number = this.clock()): Promise<AcceptedRow[]> {
    const rows = await this.db.all<RawRow>("SELECT * FROM trust_task_accepted WHERE state = 'claimed' AND tx_id IS NOT NULL AND retain_until > ?", now);
    return rows.map(toRow);
  }

  /**
   * Settle check (plan 3.5), run at boot, on an interval and on a duplicate: ask the coordinator what
   * became of each claimed transaction. `committed` completes the claim (the response is rebuilt by
   * `rebuild`, if given); `aborted` releases it only when the failure was retryable (else the claim
   * stands, completed, so a resend is not re-run); `inFlight` and `unknown` leave it, a resend keeps
   * getting the in-flight answer. Never guesses: an outcome that cannot be read leaves the claim.
   */
  async settle(
    outcomeFor: (txId: string) => Promise<{ outcome: SettleOutcome; retryable?: boolean }>,
    rebuild?: (row: AcceptedRow) => Promise<unknown | undefined>,
    now: number = this.clock(),
  ): Promise<{ completed: number; released: number; pending: number }> {
    const tally = { completed: 0, released: 0, pending: 0 };
    for (const row of await this.listClaimedWithTx(now)) {
      let verdict: { outcome: SettleOutcome; retryable?: boolean };
      try {
        verdict = await outcomeFor(row.txId!);
      } catch {
        tally.pending++;
        continue;
      }
      if (verdict.outcome === "committed") {
        const response = rebuild === undefined ? undefined : await rebuild(row);
        if (response === undefined) {
          await this.db.run("UPDATE trust_task_accepted SET state = 'completed', updated_at = ? WHERE id = ?", now, row.id);
        } else await this.recordResponse(row.id, response);
        tally.completed++;
      } else if (verdict.outcome === "aborted") {
        if (verdict.retryable === true) {
          await this.release(row.id, row.digest);
          tally.released++;
        } else {
          await this.db.run("UPDATE trust_task_accepted SET state = 'completed', updated_at = ? WHERE id = ?", now, row.id);
          tally.completed++;
        }
      } else tally.pending++;
    }
    return tally;
  }
}
