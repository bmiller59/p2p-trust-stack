// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Decision 36: the read-only evaluate query is never recorded in `trust_tasks` (and so never in the
 * thread index), whatever its outcome; every other handler, including a non-consequential one, is.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SqliteDataSource } from "../../../../src/db/sqlite-data-source.ts";
import { runMigrations } from "../../../../src/db/migrate.ts";
import { getMigrationsDir } from "../../../../src/db/migrations-dir.ts";
import * as trustTasksRepo from "../../../../src/db/repositories/trust-tasks-repo.ts";
import { Pipeline } from "../../../../src/services/trust-tasks/boundary/pipeline.ts";
import { TrustTaskRecorder } from "../../../../src/services/trust-tasks/boundary/recorder.ts";
import { createLegacyEvaluateHandler, POLICY_EVALUATE_WIRE_TYPE } from "../../../../src/services/trust-tasks/boundary/legacy-evaluate.ts";
import { CARRIER_TYPE } from "./helpers.ts";
import type { SpecPolicy } from "../../../../src/services/trust-tasks/boundary/runtime.ts";

const NOW = Date.parse("2026-11-12T10:00:00Z");
const T = "2026-11-12T10:00:00Z";
const ME = "did:example:community";
const spec: SpecPolicy = { typeUri: CARRIER_TYPE, isBearer: false, isProofRequired: false, isRecipientRequired: true, isIssuedAtRequired: true };

function setup() {
  const ds = new SqliteDataSource(":memory:");
  runMigrations(ds.getRawDb(), getMigrationsDir());
  const recorder = new TrustTaskRecorder(ds, { node: "test" });
  const pipeline = new Pipeline({
    handlers: [
      createLegacyEvaluateHandler(ds),
      { types: [CARRIER_TYPE], spec, consequential: false, handle: (d) => ({ id: "urn:uuid:99999999-9999-4999-8999-999999999999", threadId: d.threadId ?? d.id, type: `${CARRIER_TYPE}#response`, issuer: d.recipient, recipient: d.issuer, issuedAt: T, payload: {} }) as never },
    ],
    servedVids: [ME], now: () => NOW, record: (r) => recorder.record(r),
  });
  return { ds, pipeline };
}
const doc = (id: string, type: string, payload: unknown) => ({ id: `urn:uuid:${id}-1111-4111-8111-111111111111`, type, issuer: "did:example:alice", recipient: ME, issuedAt: T, payload });
const count = (ds: SqliteDataSource): number => (ds.getRawDb().prepare("SELECT count(*) AS n FROM trust_tasks").get() as { n: number }).n;

describe("read-only evaluate documents are not recorded (decision 36)", () => {
  it("an answered evaluate (here: wrongRecipient after the handler ran) stores nothing, request or reply, under both type forms", async () => {
    const { ds, pipeline } = setup();
    for (const [i, type] of [POLICY_EVALUATE_WIRE_TYPE, "task:p2pts:policy:evaluate:0.1"].entries()) {
      const d = doc(`aaaaaaa${i}`, type, { action: "register_name" });
      const r = await pipeline.process({ raw: JSON.stringify(d), sender: "did:example:alice" });
      assert.equal(r.kind, "error", "the handler did run and answered");
      assert.equal(r.refusedBeforeProof, false, "this is the path that would otherwise be stored");
      assert.equal(r.unrecorded, true);
    }
    assert.equal(count(ds), 0);
    assert.deepEqual(await trustTasksRepo.listThreads(ds), []);
  });

  it("a refused evaluate (malformed payload, no sender) is not stored either", async () => {
    const { ds, pipeline } = setup();
    await pipeline.process({ raw: JSON.stringify(doc("bbbbbbbb", POLICY_EVALUATE_WIRE_TYPE, {})), sender: "did:example:alice" });
    await pipeline.process({ raw: JSON.stringify(doc("cccccccc", POLICY_EVALUATE_WIRE_TYPE, { action: "register_name" })) });
    assert.equal(count(ds), 0);
  });

  it("every other handler is still recorded, request and reply, even a non-consequential one", async () => {
    const { ds, pipeline } = setup();
    const d = doc("dddddddd", CARRIER_TYPE, { s: "x" });
    const r = await pipeline.process({ raw: JSON.stringify(d), sender: "did:example:alice" });
    assert.equal(r.kind, "response");
    assert.equal(r.unrecorded, undefined);
    assert.equal(count(ds), 2);
    assert.ok(await trustTasksRepo.findByUuid(ds, d.id));
    assert.equal((await trustTasksRepo.listThreads(ds)).length, 1);
  });
});
