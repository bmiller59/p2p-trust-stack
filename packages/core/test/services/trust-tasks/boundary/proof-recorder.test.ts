// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * P4c: persistence of proof, raw document and verified signer (decision A4): a body refused before
 * proof verification is never stored (counters and a hashed sender only); a document accepted, or
 * refused after its proof verified, is stored verbatim with its proof, digests and verified signer;
 * the signed reply is stored as sent; a duplicate is not stored twice; a recording failure never
 * changes the answer.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { SqliteDataSource } from "../../../../src/db/sqlite-data-source.ts";
import { runMigrations } from "../../../../src/db/migrate.ts";
import { getMigrationsDir } from "../../../../src/db/migrations-dir.ts";
import * as trustTasksRepo from "../../../../src/db/repositories/trust-tasks-repo.ts";
import { Pipeline } from "../../../../src/services/trust-tasks/boundary/pipeline.ts";
import { TrustTaskRecorder } from "../../../../src/services/trust-tasks/boundary/recorder.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { DidKeyResolver, didKeyFromEd25519 } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import { createEd25519BoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import { taskDigestMultibase } from "../../../../src/services/trust-tasks/boundary/proof/digest.ts";
import { AcceptedIdStore } from "../../../../src/services/trust-tasks/boundary/accepted-store.ts";
import { CARRIER_TYPE } from "./helpers.ts";
import type { SpecPolicy } from "../../../../src/services/trust-tasks/boundary/runtime.ts";

const actor = (byte: number) => {
  const secretKey = new Uint8Array(32).fill(byte);
  const did = didKeyFromEd25519(ed25519.getPublicKey(secretKey));
  return createEd25519BoundarySigner({ did, secretKey, fragment: did.slice(8) });
};
const IUT = actor(1);
const A = actor(2);
const NOW = Date.parse("2026-11-12T10:00:00Z");
const T = "2026-11-12T10:00:00Z";
const spec: SpecPolicy = { typeUri: CARRIER_TYPE, isBearer: false, isProofRequired: false, isRecipientRequired: true, isIssuedAtRequired: true };

function setup(tier: 1 | 2 = 1) {
  const ds = new SqliteDataSource(":memory:");
  runMigrations(ds.getRawDb(), getMigrationsDir());
  const errors: unknown[] = [];
  const recorder = new TrustTaskRecorder(ds, { node: "test-node", onError: (e) => errors.push(e) });
  let n = 0;
  let executed = 0;
  const pipeline = new Pipeline({
    handlers: [{ types: [CARRIER_TYPE], spec, consequential: true, handle: (d) => { executed++; return { id: `urn:uuid:00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`, threadId: d.threadId ?? d.id, type: `${CARRIER_TYPE}#response`, issuer: d.recipient, recipient: d.issuer, issuedAt: T, payload: {} } as never; } }],
    servedVids: [IUT.did], now: () => NOW, guard: new AcceptedIdStore(ds, { now: () => NOW }),
    proof: { verifier: new DidProofVerifier({ resolver: new DidKeyResolver() }), tier }, signer: IUT,
    record: (r) => recorder.record(r),
  });
  return { ds, recorder, pipeline, errors, executed: () => executed };
}
const base = (id: string, over: Record<string, unknown> = {}) => ({ id: `urn:uuid:${id}-3333-4333-8333-333333333333`, type: CARRIER_TYPE, issuer: A.did, recipient: IUT.did, issuedAt: T, payload: { s: "x" }, ...over });
const send = (p: Pipeline, doc: Record<string, unknown>, raw?: string) => p.process({ raw: raw ?? JSON.stringify(doc), sender: A.did });

describe("accepted documents are stored verbatim with proof, digests and verified signer", () => {
  it("request row: raw bytes exactly as received (key order, whitespace), proof, task digest, verified signer; reply row: the signed reply as sent", async () => {
    const { ds, pipeline } = setup();
    const signed = signDocument(base("aaaaaaaa"), A, { created: NOW });
    const raw = JSON.stringify(signed, null, 2).replace(/\n/g, "\r\n");
    const result = await send(pipeline, signed, raw);
    assert.equal(result.kind, "response");
    const row = (await trustTasksRepo.findByUuid(ds, signed.id))!;
    assert.equal(row.rawDocument, raw, "verbatim, not re-serialised");
    assert.equal(row.verifiedSigner, A.did);
    assert.equal(row.taskDigest, taskDigestMultibase(signed));
    assert.deepEqual(JSON.parse(row.proof!), signed.proof);
    assert.equal(row.disposition, "response");
    assert.equal(row.lifecycle, "responded");
    assert.equal(row.issuedAt, NOW);
    assert.equal(row.direction, "request");
    const reply = result.document as { id: string; proof: unknown };
    const replyRow = (await trustTasksRepo.findByUuid(ds, reply.id))!;
    assert.equal(replyRow.direction, "response");
    assert.equal(replyRow.inReplyTo, signed.id);
    assert.equal(replyRow.rawDocument, JSON.stringify(result.document), "the reply exactly as the carrier sends it");
    assert.ok(JSON.parse(replyRow.proof!), "the reply's proof is stored");
  });

  it("an unsigned request accepted at Tier 1 is stored verbatim with no verified signer", async () => {
    const { ds, pipeline } = setup();
    const doc = base("bbbbbbbb");
    await send(pipeline, doc);
    const row = (await trustTasksRepo.findByUuid(ds, doc.id))!;
    assert.equal(row.verifiedSigner, null);
    assert.equal(row.proof, null);
    assert.equal(row.rawDocument, JSON.stringify(doc));
  });

  it("refused AFTER the proof verified (a changed resend: idConflict) is stored verbatim, with the verified signer", async () => {
    const { ds, pipeline } = setup();
    const first = signDocument(base("cccccccc"), A, { created: NOW });
    await send(pipeline, first);
    const changed = signDocument({ ...base("cccccccc"), payload: { s: "other" } }, A, { created: NOW });
    const res = await send(pipeline, changed);
    assert.equal(res.code, "idConflict");
    assert.equal(res.refusedBeforeProof, false);
    // the id is the primary key: the first document stays, and the conflicting body is not lost silently
    assert.equal((await trustTasksRepo.findByUuid(ds, first.id))!.rawDocument, JSON.stringify(first));
  });

  it("a verbatim resend (duplicate) is not stored again", async () => {
    const { ds, pipeline } = setup();
    const signed = signDocument(base("dddddddd"), A, { created: NOW });
    await send(pipeline, signed);
    await send(pipeline, signed);
    const rows = await ds.all<{ n: number }>("SELECT COUNT(*) AS n FROM trust_tasks");
    assert.equal(Number(rows[0]!.n), 2, "one request row and one reply row");
  });
});

describe("decision A4: nothing refused before proof verification is stored", () => {
  const count = async (ds: SqliteDataSource) => Number((await ds.all<{ n: number }>("SELECT COUNT(*) AS n FROM trust_tasks"))[0]!.n);
  it("a tampered proof, an unparseable body, a wrong recipient, a bad proof purpose and an oversize body leave the table empty; counters and a hashed sender only", async () => {
    const { ds, pipeline, recorder } = setup();
    const signed = signDocument(base("eeeeeeee"), A, { created: NOW });
    const results = [
      await send(pipeline, { ...signed, payload: { s: "tampered" } }),
      await send(pipeline, {}, "{not json"),
      await send(pipeline, signDocument(base("ffffffff", { recipient: "did:web:elsewhere" }), A, { created: NOW })),
      await send(pipeline, signDocument(base("99999999"), A, { created: NOW, purpose: "keyAgreement" })),
      await send(pipeline, {}, "x".repeat(2_000_000)),
    ];
    for (const r of results) assert.equal(r.refusedBeforeProof, true, String(r.code));
    assert.equal(await count(ds), 0, "no row for any of them");
    const c = recorder.counters;
    assert.equal(c.total, 5);
    assert.equal(c.byCode.proofInvalid, 2);
    assert.match(String(c.lastSenderHash), /^[0-9a-f]{16}$/);
    assert.ok(!JSON.stringify(c).includes(A.did), "the sender identifier itself is never kept");
  });

  it("an unavailable resolution is refused before proof verification: not stored", async () => {
    const { ds } = setup();
    const down = new Pipeline({
      handlers: [{ types: [CARRIER_TYPE], spec, consequential: false, handle: () => undefined }], servedVids: [IUT.did], now: () => NOW, signer: IUT,
      proof: { verifier: new DidProofVerifier({ resolver: { async resolve() { throw new (await import("../../../../src/services/trust-tasks/boundary/proof/resolver.ts")).ResolutionUnavailable("down"); } } }) },
      record: (r) => new TrustTaskRecorder(ds).record(r),
    });
    const res = await send(down, signDocument(base("12121212"), A, { created: NOW }));
    assert.equal(res.code, "unavailable");
    assert.equal(res.refusedBeforeProof, true);
    assert.equal(await count(ds), 0);
  });
});

describe("recording failures never change the answer", () => {
  it("a throwing recorder is reported through onUnexpected and the reply is unchanged", async () => {
    const seen: unknown[] = [];
    const ds = new SqliteDataSource(":memory:");
    runMigrations(ds.getRawDb(), getMigrationsDir());
    const p = new Pipeline({
      handlers: [{ types: [CARRIER_TYPE], spec, consequential: false, handle: (d) => ({ id: "urn:uuid:00000000-0000-4000-8000-0000000000aa", threadId: d.id, type: `${CARRIER_TYPE}#response`, issuer: d.recipient, recipient: d.issuer, issuedAt: T, payload: {} }) as never }],
      servedVids: [IUT.did], now: () => NOW, signer: IUT, onUnexpected: (e) => seen.push(e),
      record: async () => { throw new Error("disk full"); },
    });
    const res = await send(p, base("34343434"));
    assert.equal(res.kind, "response");
    assert.equal(seen.length, 1);
    // and the recorder itself swallows repository failures
    const broken = new SqliteDataSource(":memory:"); // no migrations: no table
    const errs: unknown[] = [];
    await new TrustTaskRecorder(broken, { onError: (e) => errs.push(e) }).record({ ...res, refusedBeforeProof: false, received: base("56565656"), raw: "{}" });
    assert.equal(errs.length, 1);
  });
});
