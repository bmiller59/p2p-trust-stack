// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The durable accepted-id store (conformance plan P3; plan 3.5) and the DUP vectors against it.
 * Names embed the suite's vector ids. DUP-002 (re-signed proof) needs the signer, which is the
 * attestation phase: it is asserted at store level (a different digest is `idConflict`) and the
 * vector itself is reported not runnable here, not passed.
 *
 * Both dialects: the store runs on SQLite as is and on a Postgres-dialect emulation of the data
 * source that rejects SQLite-only statements, returns 64-bit columns as strings and reports a primary-key
 * violation with SQLSTATE 23505. A real distributed database was not available: not exercised.
 * Temp directories only.
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { SqliteDataSource } from "../../../../src/db/sqlite-data-source.ts";
import type { DataSource, QueryResult } from "../../../../src/db/data-source.ts";
import { runMigrations } from "../../../../src/db/migrate.ts";
import { getMigrationsDir } from "../../../../src/db/migrations-dir.ts";
import { AcceptedIdStore } from "../../../../src/services/trust-tasks/boundary/accepted-store.ts";
import { TaskError } from "../../../../src/services/trust-tasks/boundary/errors.ts";
import { EXPIRY_HORIZON_MS, MAX_AGE_MS, SKEW_MS } from "../../../../src/services/trust-tasks/boundary/pins.ts";
import type { ReplayGuard, SpecPolicy, TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { TxJanitor } from "../../../../src/tx/janitor.ts";
import { TX_SCHEMA_SQL } from "../../../../src/tx/schema.ts";
import { BoundaryAdapter } from "./conformance/adapter.ts";
import type { BoundaryHandler } from "./conformance/adapter.ts";
import { allVectors, runVector } from "./conformance/vector-runner.ts";
import type { Env } from "./conformance/vector-runner.ts";
import { CARRIER_TYPE } from "./helpers.ts";

const dir = mkdtempSync(join(tmpdir(), "p3-accepted-"));
after(() => rmSync(dir, { recursive: true, force: true }));
let counter = 0;
const dbPath = (): string => join(dir, `db-${counter++}.sqlite`);

/** A SQLite database with every migration applied (the claim table comes from 0021). */
function open(path: string): SqliteDataSource {
  const ds = new SqliteDataSource(path);
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}

const SQLITE_ONLY = /INSERT\s+OR\s|ON\s+CONFLICT|PRAGMA|datetime\s*\(|unixepoch|strftime|\bGLOB\b/i;

/** Postgres-dialect emulation over SQLite: portable statements only, string BIGINTs, 23505 on a key violation. */
class PgDialect implements DataSource {
  readonly inner: DataSource;
  readonly statements: string[] = [];
  yieldBefore = false;
  constructor(inner: DataSource) {
    this.inner = inner;
  }
  private check(sql: string): void {
    this.statements.push(sql);
    if (SQLITE_ONLY.test(sql)) throw new Error(`not portable to the Postgres dialect: ${sql}`);
  }
  private static widen<T>(row: T): T {
    if (row === null || typeof row !== "object") return row;
    const out: Record<string, unknown> = { ...(row as Record<string, unknown>) };
    for (const k of ["retain_until", "created_at", "updated_at", "issued_at", "expires_at"]) if (typeof out[k] === "number") out[k] = String(out[k]);
    return out as T;
  }
  async all<T = Record<string, unknown>>(sql: string, ...p: unknown[]): Promise<T[]> {
    this.check(sql);
    return (await this.inner.all<T>(sql, ...p)).map((r) => PgDialect.widen(r));
  }
  async get<T = Record<string, unknown>>(sql: string, ...p: unknown[]): Promise<T | null> {
    this.check(sql);
    if (this.yieldBefore) await new Promise((r) => setImmediate(r));
    return PgDialect.widen(await this.inner.get<T>(sql, ...p));
  }
  async run(sql: string, ...p: unknown[]): Promise<QueryResult> {
    this.check(sql);
    if (this.yieldBefore) await new Promise((r) => setImmediate(r));
    try {
      return await this.inner.run(sql, ...p);
    } catch (err) {
      if (/UNIQUE constraint/i.test((err as Error).message)) throw Object.assign(new Error("duplicate key value violates unique constraint"), { code: "23505" });
      throw err;
    }
  }
  exec(sql: string): Promise<void> {
    return this.inner.exec(sql);
  }
  transaction<T>(fn: (ds: DataSource) => Promise<T>): Promise<T> {
    return this.inner.transaction(() => fn(this));
  }
  close(): Promise<void> {
    return this.inner.close();
  }
}

/** A data source whose every call fails: the record cannot be consulted. */
const throwing = (): DataSource => {
  const fail = (): never => {
    throw new Error("connection refused: db.internal.example:5433");
  };
  return { all: fail, get: fail, run: fail, exec: fail, transaction: fail, close: async () => {} } as unknown as DataSource;
};

const NOW = Date.parse("2026-11-12T10:00:00Z");
const ID = "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000aa01";

const flavours: { name: string; make: (path: string) => { db: DataSource; reopen: () => DataSource } }[] = [
  { name: "SQLite", make: (path) => ({ db: open(path), reopen: () => open(path) }) },
  { name: "Postgres dialect", make: (path) => ({ db: new PgDialect(open(path)), reopen: () => new PgDialect(open(path)) }) },
];

for (const flavour of flavours) {
  describe(`accepted-id store on ${flavour.name}`, () => {
    const fresh = (): { db: DataSource; reopen: () => DataSource; store: AcceptedIdStore } => {
      const made = flavour.make(dbPath());
      return { ...made, store: new AcceptedIdStore(made.db) };
    };

    it("the primary key column is named id (the distributed data source appends RETURNING id)", async () => {
      const { db } = fresh();
      const raw = db instanceof PgDialect ? db.inner : db;
      const cols = await raw.all<{ name: string; pk: number }>("PRAGMA table_info(trust_task_accepted)");
      assert.deepEqual(cols.filter((c) => c.pk > 0).map((c) => c.name), ["id"]);
    });

    it("DUP-001: the same document again is a duplicate, in flight until a response is recorded, then the prior response", async () => {
      const { store } = fresh();
      assert.deepEqual(await store.claim(ID, "d1", NOW + 360_000, NOW), { kind: "fresh" });
      assert.deepEqual(await store.claim(ID, "d1", NOW + 360_000, NOW + 5000), { kind: "duplicate", inFlight: true });
      await store.recordResponse(ID, { type: "x#response", payload: { ok: true } });
      assert.deepEqual(await store.claim(ID, "d1", NOW + 360_000, NOW + 6000), { kind: "duplicate", inFlight: false, priorResponse: { type: "x#response", payload: { ok: true } } });
    });

    it("DUP-002, DUP-003 (store level): another digest for the same id (re-signed proof, other payload, other recipient) is a conflict, never a duplicate", async () => {
      const { store } = fresh();
      await store.claim(ID, "digest-original", NOW + 360_000, NOW);
      await store.recordResponse(ID, { ok: 1 });
      for (const other of ["digest-resigned", "digest-other-payload", "digest-other-recipient"]) {
        assert.deepEqual(await store.claim(ID, other, NOW + 360_000, NOW + 1000), { kind: "conflict" }, other);
      }
    });

    it("DUP-005 / DUP-111 (store level): half-open window, live at retainUntil minus 1 ms, replaced at retainUntil", async () => {
      const { store, db } = fresh();
      const until = NOW + 360_000;
      await store.claim(ID, "d1", until, NOW);
      await store.recordResponse(ID, { first: true });
      assert.equal((await store.claim(ID, "d1", until, until - 1)).kind, "duplicate");
      assert.deepEqual(await store.claim(ID, "d2", until + 360_000, until), { kind: "fresh" }, "an expired row is treated as absent, even for another digest");
      const row = await store.find(ID);
      assert.equal(row?.digest, "d2");
      assert.equal(row?.state, "claimed");
      assert.equal(row?.retainUntil, until + 360_000);
      assert.equal(row?.response, null, "the replaced row carries no stale response");
      assert.equal((await db.all("SELECT id FROM trust_task_accepted")).length, 1);
    });

    it("DUP restart: a new store over the same database still answers duplicate with the prior response, and a claim without a response stays in flight", async () => {
      const { store, reopen } = fresh();
      await store.claim(ID, "d1", NOW + 360_000, NOW);
      await store.recordResponse(ID, { done: 1 });
      await store.claim("urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000aa02", "d9", NOW + 360_000, NOW);
      const afterRestart = new AcceptedIdStore(reopen());
      assert.deepEqual(await afterRestart.claim(ID, "d1", NOW + 360_000, NOW + 1000), { kind: "duplicate", inFlight: false, priorResponse: { done: 1 } });
      assert.deepEqual(await afterRestart.claim("urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000aa02", "d9", NOW + 360_000, NOW + 1000), { kind: "duplicate", inFlight: true });
      assert.deepEqual(await afterRestart.claim(ID, "other", NOW + 360_000, NOW + 1000), { kind: "conflict" });
    });

    it("DUP concurrent double claim: exactly one caller is fresh, the other sees the claim in flight", async () => {
      const { store, db } = fresh();
      if (db instanceof PgDialect) db.yieldBefore = true;
      for (let i = 0; i < 20; i++) {
        const id = `urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000c${String(i).padStart(4, "0")}`;
        const verdicts = await Promise.all([store.claim(id, "same", NOW + 360_000, NOW), store.claim(id, "same", NOW + 360_000, NOW), store.claim(id, "same", NOW + 360_000, NOW)]);
        assert.equal(verdicts.filter((v) => v.kind === "fresh").length, 1, JSON.stringify(verdicts));
        assert.ok(verdicts.filter((v) => v.kind !== "fresh").every((v) => v.kind === "duplicate" && v.inFlight));
      }
      const conflicting = await Promise.all([store.claim(ID, "a", NOW + 360_000, NOW), store.claim(ID, "b", NOW + 360_000, NOW)]);
      assert.deepEqual(conflicting.map((v) => v.kind).sort(), ["conflict", "fresh"]);
    });

    it("concurrent claims racing for an expired row still give one winner", async () => {
      const { store, db } = fresh();
      await store.claim(ID, "old", NOW + 1000, NOW);
      if (db instanceof PgDialect) db.yieldBefore = true;
      const verdicts = await Promise.all([store.claim(ID, "new", NOW + 400_000, NOW + 2000), store.claim(ID, "new", NOW + 400_000, NOW + 2000)]);
      assert.equal(verdicts.filter((v) => v.kind === "fresh").length, 1, JSON.stringify(verdicts));
    });

    it("DUP horizon clamp: an unbounded retention deadline is clamped to now + 30 days + skew", async () => {
      const { store } = fresh();
      await store.claim(ID, "d1", NOW + 365 * 24 * 3_600_000, NOW);
      assert.equal((await store.find(ID))?.retainUntil, NOW + EXPIRY_HORIZON_MS + SKEW_MS);
    });

    it("fail closed: a store that cannot be read or written throws, never answers fresh", async () => {
      const broken = new AcceptedIdStore(throwing());
      await assert.rejects(() => broken.claim(ID, "d1", NOW + 1000, NOW), /connection refused/);
    });

    it("a claim needs a deadline (the runtime refuses a document it cannot window before it gets here)", async () => {
      const { store } = fresh();
      await assert.rejects(() => store.claim(ID, "d1", undefined, NOW), /retention deadline/);
    });

    it("release frees an unfinished claim only, and only for the same digest", async () => {
      const { store } = fresh();
      await store.claim(ID, "d1", NOW + 360_000, NOW);
      await store.release(ID, "other");
      assert.notEqual(await store.find(ID), null);
      await store.release(ID, "d1");
      assert.equal(await store.find(ID), null);
      await store.claim(ID, "d1", NOW + 360_000, NOW);
      await store.recordResponse(ID, { r: 1 });
      await store.release(ID, "d1");
      assert.notEqual(await store.find(ID), null, "a completed claim is never released");
    });

    it("a secret response is not kept (keepResponse false): a duplicate is absorbed without a body", async () => {
      const made = flavour.make(dbPath());
      const store = new AcceptedIdStore(made.db, { keepResponse: () => false });
      await store.claim(ID, "d1", NOW + 360_000, NOW);
      await store.recordResponse(ID, { secret: true });
      assert.deepEqual(await store.claim(ID, "d1", NOW + 360_000, NOW + 1), { kind: "duplicate", inFlight: false });
      assert.equal((await store.find(ID))?.response, null);
    });

    it("janitor hook: pruneExpired removes closed windows only, through TxJanitor.prune", async () => {
      const { store } = fresh();
      const idA = "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000bb01";
      const idB = "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-00000000bb02";
      await store.claim(idA, "d", NOW + 1000, NOW);
      await store.claim(idB, "d", NOW + 100_000, NOW);
      const tx = new SqliteDataSource(":memory:");
      tx.getRawDb().exec(TX_SCHEMA_SQL);
      const janitor = new TxJanitor(tx);
      let clock = NOW + 50_000;
      janitor.addPruneHook("trust_task_accepted", () => store.pruneExpired(clock));
      assert.equal((await janitor.prune()).hooks.trust_task_accepted, 1);
      assert.equal(await store.find(idA), null);
      assert.notEqual(await store.find(idB), null);
      clock = NOW + 100_000;
      assert.equal((await janitor.prune()).hooks.trust_task_accepted, 1, "closed at the instant, half-open");
      janitor.addPruneHook("broken", async () => {
        throw new Error("boom");
      });
      assert.deepEqual((await janitor.prune()).hooks, { trust_task_accepted: 0 }, "a failing hook is logged and does not stop the pass");
    });

    it("attachTx and describe fill the informational columns", async () => {
      const { store } = fresh();
      store.describe(ID, { type: CARRIER_TYPE, threadId: "urn:uuid:thread" });
      await store.claimFor("did:web:a.example", ID, "d1", NOW + 360_000, NOW);
      await store.attachTx(ID, "tx-1", NOW + 1);
      const row = await store.find(ID);
      assert.equal(row?.issuer, "did:web:a.example");
      assert.equal(row?.type, CARRIER_TYPE);
      assert.equal(row?.threadId, "urn:uuid:thread");
      assert.equal(row?.txId, "tx-1");
      assert.equal(row?.updatedAt, NOW + 1);
    });

    it("settle sweep: committed completes, aborted+retryable releases, aborted otherwise completes, in flight and unreadable stay", async () => {
      const { store } = fresh();
      const ids = ["c", "r", "n", "f", "u", "x"].map((s, i) => `urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000d000${i}-${s}`);
      for (const [i, id] of ids.entries()) {
        await store.claim(id, "d", NOW + 360_000, NOW);
        if (i < 5) await store.attachTx(id, `tx-${i}`);
      }
      const outcomes: Record<string, { outcome: "committed" | "aborted" | "inFlight" | "unknown"; retryable?: boolean } | Error> = {
        "tx-0": { outcome: "committed" },
        "tx-1": { outcome: "aborted", retryable: true },
        "tx-2": { outcome: "aborted", retryable: false },
        "tx-3": { outcome: "inFlight" },
        "tx-4": new Error("coordinator unreachable"),
      };
      const tally = await store.settle(async (txId) => {
        const o = outcomes[txId]!;
        if (o instanceof Error) throw o;
        return o;
      }, async (row) => (row.id === ids[0] ? { rebuilt: true } : undefined), NOW + 10);
      assert.deepEqual(tally, { completed: 2, released: 1, pending: 2 });
      assert.deepEqual(await store.claim(ids[0]!, "d", NOW + 360_000, NOW + 20), { kind: "duplicate", inFlight: false, priorResponse: { rebuilt: true } });
      assert.equal(await store.find(ids[1]!), null, "released: the resend runs again");
      assert.deepEqual(await store.claim(ids[2]!, "d", NOW + 360_000, NOW + 20), { kind: "duplicate", inFlight: false });
      assert.deepEqual(await store.claim(ids[3]!, "d", NOW + 360_000, NOW + 20), { kind: "duplicate", inFlight: true });
      assert.deepEqual(await store.claim(ids[4]!, "d", NOW + 360_000, NOW + 20), { kind: "duplicate", inFlight: true });
      assert.deepEqual(await store.claim(ids[5]!, "d", NOW + 360_000, NOW + 20), { kind: "duplicate", inFlight: true }, "no transaction attached: left alone");
    });
  });
}

// ── The DUP vectors, driven through the pipeline with the durable store as the duplicate record ──────

const IUT = "did:web:iut.example";
const SENDER = "did:web:a.example";
const spec: SpecPolicy = {
  typeUri: CARRIER_TYPE,
  isBearer: false,
  isProofRequired: false,
  isRecipientRequired: true,
  isIssuedAtRequired: true,
  payloadSchema: { type: "object", required: ["subject"], properties: { subject: { type: "string" } } },
};
const carrierPayload = { subject: "did:web:alice.example" };
const handler = (): BoundaryHandler => ({
  spec,
  handle: (doc) => ({ id: "urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-0000000000dd", threadId: doc.threadId ?? doc.id, type: `${CARRIER_TYPE}#response`, issuer: doc.recipient, recipient: doc.issuer, payload: {} }) as TrustTaskDocument<unknown>,
  carrier: { typeUri: CARRIER_TYPE, class: "consequential", validPayload: carrierPayload },
});
const env: Env = { iutVid: IUT, senderVid: SENDER, otherVid: "did:web:x.example", carrier: CARRIER_TYPE, carrierPayload, clockStart: "2026-11-12T10:00:00Z" };

/** An adapter whose duplicate record is the durable store; `reset` is a new empty database, `restart` the same one. */
function storeAdapter(wrap: (ds: DataSource) => DataSource, wrapGuard: (g: ReplayGuard) => ReplayGuard = (g) => g): BoundaryAdapter {
  let db: DataSource = wrap(open(":memory:"));
  return new BoundaryAdapter({
    servedVids: [IUT],
    handlers: [handler()],
    guardFactory: (kind) => {
      if (kind === "reset") db = wrap(open(":memory:"));
      return wrapGuard(new AcceptedIdStore(db));
    },
  });
}

const dupVectors = allVectors(["dup.json"]);
const notRunnable = ["DUP-002"];

describe("DUP vectors as built", () => {
  it("the file holds exactly DUP-001..005 and DUP-101..113 (18 vectors), all Tier 1", () => {
    assert.deepEqual(dupVectors.map((v) => v.vector.id), [...["001", "002", "003", "004", "005"].map((n) => `DUP-${n}`), ...Array.from({ length: 13 }, (_, i) => `DUP-${101 + i}`)]);
    assert.ok(dupVectors.every((v) => v.vector.tier === 1));
  });
});

for (const flavour of [
  { name: "SQLite", wrap: (ds: DataSource) => ds },
  { name: "Postgres dialect", wrap: (ds: DataSource) => new PgDialect(ds) as DataSource },
]) {
  describe(`DUP vectors against the durable store (${flavour.name})`, () => {
    for (const { file, vector } of dupVectors) {
      if (notRunnable.includes(vector.id)) {
        it(`${vector.id}: needs the signer (re-signed proof): not runnable before the attestation phase`, async () => {
          const out = await runVector(storeAdapter(flavour.wrap), file, vector, env);
          assert.ok(!out.pass && out.failures.some((f) => /needs the signer/.test(f)), out.failures.join(" | "));
        });
        continue;
      }
      it(`${vector.id}: ${vector.title}`, async () => {
        const out = await runVector(storeAdapter(flavour.wrap), file, vector, env);
        assert.deepEqual(out.failures, []);
      });
    }
  });
}

describe("non-vacuity: a broken duplicate record fails the DUP vectors that name the rule", () => {
  const byId = (id: string) => dupVectors.find((v) => v.vector.id === id)!;
  const fails = async (id: string, guard: (g: ReplayGuard) => ReplayGuard, text: RegExp): Promise<void> => {
    const { file, vector } = byId(id);
    const out = await runVector(storeAdapter((d) => d, guard), file, vector, env);
    assert.ok(!out.pass, `${id} should fail`);
    assert.ok(out.failures.some((f) => text.test(f)), `${id}: ${out.failures.join(" | ")}`);
  };
  const alwaysFresh = (): ReplayGuard => ({ claim: async () => ({ kind: "fresh" }) });
  const idOnly = (g: ReplayGuard): ReplayGuard => ({
    claim: (id, _digest, until, now) => Promise.resolve(g.claim(id, "constant", until, now)),
    ...(g.recordResponse === undefined ? {} : { recordResponse: g.recordResponse.bind(g) }),
  });
  it("noReplayRecord: DUP-001 and DUP-101 see the effect twice", async () => {
    await fails("DUP-001", alwaysFresh, /executed again|observable|handled/);
    await fails("DUP-101", alwaysFresh, /executed again|handled/);
  });
  it("idOnlyDuplicateKey: DUP-003 and DUP-103 are absorbed instead of idConflict", async () => {
    await fails("DUP-003", idOnly, /expected a trust-task-error|expected one error|expected code idConflict/);
    await fails("DUP-103", idOnly, /expected a trust-task-error|expected one error|expected code idConflict/);
  });
});

// ── Fail closed, restart and missing issuedAt through the pipeline ──────────────────────────────

const requestBytes = (over: Record<string, unknown> = {}, omit: string[] = []): string => {
  const doc: Record<string, unknown> = { id: ID, type: CARRIER_TYPE, issuer: SENDER, recipient: IUT, issuedAt: "2026-11-12T10:00:00Z", payload: carrierPayload, ...over };
  for (const k of omit) delete doc[k];
  return JSON.stringify(doc);
};
const send = (a: BoundaryAdapter, bytes: string) => a.send({ from: { kind: "actor", vid: SENDER }, bytes });
const codeOf = (replies: string[]): string => (JSON.parse(replies[0]!) as { payload: { code: string } }).payload.code;

describe("DUP fail closed: a throwing data source gives unavailable, retryable, and no effect", () => {
  it("through the pipeline: 503-class refusal, handled stays 0, the handler never runs", async () => {
    const a = new BoundaryAdapter({ servedVids: [IUT], handlers: [handler()], guardFactory: () => new AcceptedIdStore(throwing()) });
    await a.setClock("2026-11-12T10:00:05Z");
    const res = await send(a, requestBytes());
    assert.equal(codeOf(res.replies), "unavailable");
    assert.equal((JSON.parse(res.replies[0]!) as { payload: { retryable: boolean } }).payload.retryable, true);
    assert.equal((await a.observe({ query: "handled" })).value, 0);
    assert.ok(!res.replies[0]!.includes("db.internal.example"), "the connection detail never reaches the wire");
  });
});

describe("DUP restart through the pipeline", () => {
  it("a resend after restart is a duplicate with the stored response and is not executed again", async () => {
    const path = dbPath();
    const dbs: DataSource[] = [];
    const a = new BoundaryAdapter({
      servedVids: [IUT],
      handlers: [handler()],
      guardFactory: () => {
        const db = open(path);
        dbs.push(db);
        return new AcceptedIdStore(db);
      },
    });
    await a.setClock("2026-11-12T10:00:05Z");
    const first = await send(a, requestBytes());
    assert.equal(first.transport.status, 200);
    await a.restart();
    await a.setClock("2026-11-12T10:00:10Z");
    const again = await send(a, requestBytes());
    assert.equal(again.transport.status, 200);
    assert.deepEqual(JSON.parse(again.replies[0]!), JSON.parse(first.replies[0]!));
    assert.equal((await a.observe({ query: "handled" })).value, 1);
    assert.equal(codeOf((await send(a, requestBytes({ payload: { subject: "did:web:bob.example" } }))).replies), "idConflict");
  });
});

describe("DUP failed handler: the claim is released on a retryable failure only (plan 3.5)", () => {
  const failing = (retryable: boolean): BoundaryHandler => ({
    spec,
    handle: () => {
      throw new TaskError({ code: retryable ? "unavailable" : "taskFailed", retryable, internalMessage: "no" });
    },
    carrier: { typeUri: CARRIER_TYPE, class: "consequential", validPayload: carrierPayload },
  });
  for (const retryable of [true, false]) {
    it(`retryable ${String(retryable)}: the row ${retryable ? "is released" : "stays and a resend is absorbed with the same failure"}`, async () => {
      const db = open(":memory:");
      const store = new AcceptedIdStore(db);
      const a = new BoundaryAdapter({ servedVids: [IUT], handlers: [failing(retryable)], guardFactory: () => store });
      await a.setClock("2026-11-12T10:00:05Z");
      const res = await send(a, requestBytes());
      assert.equal(codeOf(res.replies), retryable ? "unavailable" : "taskFailed");
      assert.equal((await store.find(ID)) === null, retryable);
      const again = await send(a, requestBytes());
      assert.equal(again.replies.length, 1);
      assert.equal(codeOf(again.replies), retryable ? "unavailable" : "taskFailed");
    });
  }
});

describe("DUP missing issuedAt: a consequential document that cannot be dated is refused before any claim", () => {
  const noDate: BoundaryHandler = { ...handler(), spec: { ...spec, isIssuedAtRequired: false } };
  const run = async (over: Record<string, unknown>) => {
    const store = new AcceptedIdStore(open(":memory:"));
    const a = new BoundaryAdapter({ servedVids: [IUT], handlers: [noDate], guardFactory: () => store });
    await a.setClock("2026-11-12T10:00:05Z");
    const res = await send(a, requestBytes(over, ["issuedAt"]));
    return { res, store, a };
  };
  it("no issuedAt and no expiresAt: malformedRequest, nothing claimed, nothing executed", async () => {
    const { res, store, a } = await run({});
    assert.equal(codeOf(res.replies), "malformedRequest");
    assert.equal(await store.find(ID), null);
    assert.equal((await a.observe({ query: "handled" })).value, 0);
  });
  it("an expiresAt but no issuedAt: also malformedRequest (the runtime requires issuedAt beside expiresAt), nothing claimed", async () => {
    const { res, store } = await run({ expiresAt: "2026-11-12T10:30:00Z" });
    assert.equal(codeOf(res.replies), "malformedRequest");
    assert.equal(await store.find(ID), null);
  });
});

before(() => {
  // Evidence that the pins used by these tests are the pinned windows.
  assert.equal(MAX_AGE_MS, 300_000);
  assert.equal(SKEW_MS, 60_000);
  assert.equal(EXPIRY_HORIZON_MS, 30 * 24 * 3_600_000);
});
