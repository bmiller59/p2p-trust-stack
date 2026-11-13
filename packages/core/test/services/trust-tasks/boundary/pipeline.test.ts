// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The boundary pipeline, handler registry, URN codec and payload validator (conformance plan P2).
 * Design concerns with no suite vector are named "design ..." here: the byte limits and the status for
 * unparseable input, claim settlement by `retryable`, the lenient flag's reach, the A4 retention line,
 * wire-message normalisation of library refusals, `servedVersions`.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import * as typeUris from "../../../../src/services/trust-tasks/type-uris.ts";
import { TaskError } from "../../../../src/services/trust-tasks/boundary/errors.ts";
import { HandlerRegistry } from "../../../../src/services/trust-tasks/boundary/handlers.ts";
import type { PipelineHandler } from "../../../../src/services/trust-tasks/boundary/handlers.ts";
import { Pipeline } from "../../../../src/services/trust-tasks/boundary/pipeline.ts";
import type { LenientEvent, PipelineOptions, PipelineResult } from "../../../../src/services/trust-tasks/boundary/pipeline.ts";
import { simplePayloadValidator } from "../../../../src/services/trust-tasks/boundary/payload-validator.ts";
import { fromWireTypeUri, toWireTypeUri } from "../../../../src/services/trust-tasks/boundary/urn-codec.ts";
import { tryParseTypeUri } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import type { TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { CARRIER_TYPE } from "./helpers.ts";

const IUT = "did:web:iut.example";
const A = "did:web:a.example";
const NOW = Date.parse("2026-11-12T10:00:00Z");
const T = "2026-11-12T10:00:00Z";
const ID = "urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

interface Harness {
  pipeline: Pipeline;
  calls: TrustTaskDocument<unknown>[];
  unexpected: unknown[];
  lenient: LenientEvent[];
  behaviour: { next: () => unknown };
}

function harness(over: Partial<PipelineOptions> = {}, consequential = true): Harness {
  const calls: TrustTaskDocument<unknown>[] = [];
  const unexpected: unknown[] = [];
  const lenient: LenientEvent[] = [];
  const behaviour: { next: () => unknown } = { next: () => undefined };
  const respond = (doc: TrustTaskDocument<unknown>): unknown => ({ id: `urn:uuid:r-${calls.length}`, type: `${CARRIER_TYPE}#response`, threadId: doc.threadId ?? doc.id, issuer: doc.recipient, recipient: doc.issuer, issuedAt: T, payload: {} });
  behaviour.next = () => undefined;
  const handler: PipelineHandler = {
    types: [CARRIER_TYPE],
    spec: { typeUri: CARRIER_TYPE, isBearer: false, isProofRequired: false, isRecipientRequired: true, isIssuedAtRequired: consequential, payloadSchema: { type: "object", required: ["subject"], properties: { subject: { type: "string" } } } },
    consequential,
    handle: (doc) => {
      calls.push(doc);
      const v = behaviour.next();
      if (v === undefined) return respond(doc) as TrustTaskDocument<unknown>;
      if (v instanceof Error) throw v;
      return v as never;
    },
  };
  const pipeline = new Pipeline({ handlers: [handler], servedVids: [IUT], now: () => NOW, newId: (() => { let n = 0; return () => `urn:uuid:e-${n++}`; })(), onUnexpected: (e) => unexpected.push(e), onLenient: (e) => lenient.push(e), ...over });
  return { pipeline, calls, unexpected, lenient, behaviour };
}

const doc = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ id: ID, type: CARRIER_TYPE, issuer: A, recipient: IUT, issuedAt: T, payload: { subject: "did:web:alice.example" }, ...over });
const send = (h: Harness, body: unknown, sender: string | undefined = A): Promise<PipelineResult> => h.pipeline.process({ raw: typeof body === "string" ? body : JSON.stringify(body), sender });
const codeOf = (r: PipelineResult): string | undefined => (r.document as { payload?: { code?: string } } | undefined)?.payload?.code;

describe("design BND/ENV: bytes in, no invented replies", () => {
  it("an unparseable body is refused with 400, no document, not stored, handler untouched", async () => {
    const h = harness();
    for (const body of ['{"id":', "", "not json", "[1,2]", "null", "42"]) {
      const r = await send(h, body);
      assert.equal(r.kind, "refused", body);
      assert.equal(r.status, 400);
      assert.equal(r.document, undefined);
      assert.equal(r.refusedBeforeProof, true);
      assert.equal(r.minimal?.code, "malformedRequest");
      assert.equal(r.minimal?.retryable, false);
    }
    assert.equal(h.calls.length, 0);
  });
  it("bytes that are not UTF-8 are refused; a BOM is not stripped (JSON.parse refuses it)", async () => {
    const h = harness();
    assert.equal((await h.pipeline.process({ raw: new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]), sender: A })).status, 400);
    assert.equal((await h.pipeline.process({ raw: new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), sender: A })).kind, "refused");
  });
  it("an oversize body is refused with 413 before anything is parsed", async () => {
    const h = harness({ maxBodyBytes: 64 });
    const r = await send(h, JSON.stringify(doc({ payload: { subject: "x".repeat(200) } })));
    assert.equal(r.status, 413);
    assert.equal(r.kind, "refused");
    assert.equal(r.raw, undefined);
    assert.equal(h.calls.length, 0);
  });
  it("a document with neither id nor type has nothing to address: 400, no document", async () => {
    const r = await send(harness(), { payload: {} });
    assert.equal(r.kind, "refused");
    assert.equal(r.status, 400);
  });
  it("the body is retained exactly as received, in any spelling", async () => {
    const h = harness();
    const text = `  ${JSON.stringify(doc()).replace(/,/g, " ,\n")}  `;
    const r = await send(h, text);
    assert.equal(r.raw, text);
    assert.equal(r.kind, "response");
    assert.equal(r.status, 200);
  });
  it("an inbound error is absorbed with 204 and never reaches a handler", async () => {
    const h = harness();
    const r = await send(h, { id: ID, type: "https://trusttasks.org/spec/trust-task-error/0.6", issuer: A, recipient: IUT, payload: { code: "taskFailed", retryable: false } });
    assert.equal(r.kind, "absorbed");
    assert.equal(r.status, 204);
    assert.equal(r.document, undefined);
    assert.equal(h.calls.length, 0);
  });
  it("a variant fragment on a request type is malformedRequest (not unsupportedType)", async () => {
    for (const frag of ["#response", "#request"]) {
      const r = await send(harness(), doc({ type: `${CARRIER_TYPE}${frag}` }));
      assert.equal(codeOf(r), "malformedRequest", frag);
      assert.equal(r.status, 400);
    }
  });
});

describe("design ERR: library refusals reach the wire in the typed error model", () => {
  it("messages are the fixed vocabulary, never the library's text", async () => {
    const h = harness();
    for (const body of [doc({ recipient: "did:web:x.example" }), doc({ type: "https://trusttasks.org/spec/conformance/gadget/0.1" }), doc({ issuedAt: "2026-11-12T09:00:00Z" }), doc({ payload: { subject: 5 } }), doc({ proof: { type: "DataIntegrityProof" } })]) {
      const r = await send(h, body);
      const p = (r.document as { payload: { message: string; retryable: boolean; code: string } }).payload;
      assert.doesNotMatch(p.message, /SPEC|§|consumer|in-band|schema/i, `${p.code}: ${p.message}`);
      assert.equal(typeof p.retryable, "boolean");
    }
  });
  it("wrongRecipient is issued by the served identifier, never by the contested recipient", async () => {
    const r = await send(harness(), doc({ recipient: "did:web:x.example" }));
    const d = r.document as { issuer: string; recipient: string; payload: { code: string } };
    assert.equal(d.payload.code, "wrongRecipient");
    assert.equal(d.issuer, IUT);
    assert.equal(d.recipient, A);
    assert.equal(r.status, 422);
  });
  it("identityMismatch goes to the transport sender, withholds the request id, and names no identity", async () => {
    const r = await send(harness(), doc(), "did:web:x.example");
    const d = r.document as { recipient: string; payload: { code: string; message: string; inResponseTo: { id?: string } } };
    assert.equal(d.payload.code, "identityMismatch");
    assert.equal(d.recipient, "did:web:x.example");
    assert.equal(d.payload.inResponseTo.id, undefined);
    assert.ok(!d.payload.message.includes(A) && !d.payload.message.includes("did:web:x.example"));
  });
  it("unsupportedVersion carries details.servedVersions; an unknown type does not", async () => {
    const h = harness();
    const v = await send(h, doc({ type: "https://trusttasks.org/spec/conformance/widget/1.0" }));
    assert.equal(codeOf(v), "unsupportedVersion");
    assert.deepEqual((v.document as { payload: { details: unknown } }).payload.details, { servedVersions: ["0.1"] });
    const u = await send(h, doc({ type: "https://trusttasks.org/spec/conformance/gadget/0.1" }));
    assert.equal(codeOf(u), "unsupportedType");
    assert.equal((u.document as { payload: { details?: unknown } }).payload.details, undefined);
  });
  it("a binding specification and an upper-case slug are never served", async () => {
    for (const type of ["https://trusttasks.org/spec/bindings/https/0.3", "https://trusttasks.org/spec/conformance/Widget/0.1", "http://trusttasks.org/spec/conformance/widget/0.1"]) {
      assert.ok(["unsupportedType", "malformedRequest"].includes(codeOf(await send(harness(), doc({ type }))) ?? ""), type);
    }
  });
  it("PRF interim: a proof is refused (rejectIfPresent) in strict and lenient mode alike", async () => {
    for (const strictness of ["strict", "lenient"] as const) {
      const h = harness({ strictness }, false);
      const r = await send(h, doc({ proof: { type: "DataIntegrityProof" } }));
      assert.equal(codeOf(r), "malformedRequest", strictness);
      assert.equal(h.calls.length, 0);
    }
  });
  it("PRF interim: an unauthenticated proof is not attributed to anyone (no transport sender, no identity claim)", async () => {
    const r = await send(harness(), doc({ proof: { type: "DataIntegrityProof" } }), undefined);
    assert.equal(codeOf(r), "malformedRequest");
  });
});

describe("design DUP/ERR: the claim follows the outcome, not the throw", () => {
  it("success then the same bytes: the prior response, handler run once (200)", async () => {
    const h = harness();
    const first = await send(h, doc());
    const again = await send(h, doc());
    assert.equal(first.status, 200);
    assert.equal(again.kind, "duplicate");
    assert.equal(again.status, 200);
    assert.deepEqual(again.document, first.document);
    assert.equal(h.calls.length, 1);
  });
  it("same id, other payload: idConflict 409, after the claim stage (refusedBeforeProof false)", async () => {
    const h = harness();
    await send(h, doc());
    const r = await send(h, doc({ payload: { subject: "did:web:bob.example" } }));
    assert.equal(codeOf(r), "idConflict");
    assert.equal(r.status, 409);
    assert.equal(r.refusedBeforeProof, false);
  });
  it("a non-retryable TaskError keeps the claim (the same document is not run again)", async () => {
    const h = harness();
    h.behaviour.next = () => new TaskError({ reason: "notAccepted" });
    const first = await send(h, doc());
    assert.equal(codeOf(first), "taskFailed");
    assert.equal(first.refusedBeforeProof, false);
    h.behaviour.next = () => undefined;
    const again = await send(h, doc());
    assert.equal(again.kind, "duplicate");
    assert.equal(h.calls.length, 1);
  });
  it("a retryable failure releases the claim, so a retry runs again", async () => {
    const h = harness();
    h.behaviour.next = () => new TaskError({ reason: "storeFailed" });
    const first = await send(h, doc());
    assert.equal(codeOf(first), "unavailable");
    assert.equal((first.document as { payload: { retryable: boolean } }).payload.retryable, true);
    assert.equal(first.status, 503);
    h.behaviour.next = () => undefined;
    assert.equal((await send(h, doc())).kind, "response");
    assert.equal(h.calls.length, 2);
  });
  it("an unexpected throw is an opaque internalError (retryable), logged not leaked, claim released", async () => {
    const h = harness();
    h.behaviour.next = () => new Error("secret: /etc/passwd at db.sqlite");
    const r = await send(h, doc());
    const p = (r.document as { payload: { code: string; message: string; retryable: boolean } }).payload;
    assert.equal(p.code, "internalError");
    assert.equal(r.status, 500);
    assert.equal(p.retryable, true);
    assert.doesNotMatch(JSON.stringify(r.document), /secret|passwd|sqlite/);
    assert.equal(h.unexpected.length, 1);
    h.behaviour.next = () => undefined;
    assert.equal((await send(h, doc())).kind, "response");
  });
  it("a failing duplicate record fails closed: unavailable 503, handler not run", async () => {
    const guard = { claim: async () => { throw new Error("down"); } };
    const h = harness({ guard: guard as never });
    const r = await send(h, doc());
    assert.equal(codeOf(r), "unavailable");
    assert.equal(r.status, 503);
    assert.equal(h.calls.length, 0);
  });
  it("a handler that returns nothing is accepted: 204", async () => {
    const h = harness();
    h.behaviour.next = () => null;
    const r = await send(h, doc());
    assert.equal(r.kind, "absorbed");
    assert.equal(r.status, 204);
  });
});

describe("design A4: what may be stored (the retention line)", () => {
  it("every refusal before the duplicate claim is flagged refusedBeforeProof; later outcomes are not", async () => {
    const h = harness();
    const before: PipelineResult[] = [
      await send(h, "{"),
      await send(h, doc({ recipient: "did:web:x.example" })),
      await send(h, doc({ type: "https://trusttasks.org/spec/conformance/gadget/0.1" })),
      await send(h, doc({ issuedAt: "2026-11-12T09:00:00Z" })),
      await send(h, doc({ payload: {} })),
      await send(h, doc({ proof: {} })),
      await send(h, doc(), "did:web:x.example"),
    ];
    for (const r of before) assert.equal(r.refusedBeforeProof, true, String(codeOf(r) ?? r.kind));
    assert.equal(h.calls.length, 0);
    const ok = await send(h, doc());
    assert.equal(ok.refusedBeforeProof, false);
  });
});

describe("design TIME: strictness flag (one release): freshness and recipient only, never proof, never consequential", () => {
  const stale = { issuedAt: "2026-11-12T09:00:00Z" };
  it("strict is the default and refuses a stale read task as expired", async () => {
    assert.equal(codeOf(await send(harness({}, false), doc(stale))), "expired");
  });
  it("lenient lets a stale or future read task through and reports each", async () => {
    const h = harness({ strictness: "lenient" }, false);
    assert.equal((await send(h, doc(stale))).kind, "response");
    assert.equal((await send(h, doc({ id: "urn:uuid:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", issuedAt: "2027-01-01T00:00:00Z" }))).kind, "response");
    assert.deepEqual(h.lenient.map((e) => e.check), ["freshness", "freshness"]);
  });
  it("lenient lets an unserved recipient reach the handler (which owns the check) and reports it", async () => {
    const h = harness({ strictness: "lenient" }, false);
    assert.equal((await send(h, doc({ recipient: "did:web:other.example" }))).kind, "response");
    assert.equal(h.lenient[0]?.check, "recipient");
    assert.equal(harness({}, false) !== undefined && codeOf(await send(harness({}, false), doc({ recipient: "did:web:other.example" }))), "wrongRecipient");
  });
  it("lenient still refuses an expired expiresAt, a malformed timestamp and a missing recipient", async () => {
    const h = harness({ strictness: "lenient" }, false);
    assert.equal(codeOf(await send(h, doc({ expiresAt: "2026-11-12T09:59:00Z" }))), "expired");
    assert.equal(codeOf(await send(h, doc({ issuedAt: "yesterday" }))), "malformedRequest");
    const noRecipient = doc();
    delete noRecipient.recipient;
    assert.equal(codeOf(await send(h, noRecipient)), "malformedRequest");
  });
  it("lenient never relaxes a consequential handler", async () => {
    const h = harness({ strictness: "lenient" }, true);
    assert.equal(codeOf(await send(h, doc(stale))), "expired");
    assert.equal(codeOf(await send(h, doc({ recipient: "did:web:other.example" }))), "wrongRecipient");
    assert.equal(h.lenient.length, 0);
  });
  it("a read task with no timestamps at all keeps being accepted (strict); a dated one gets the pinned window", async () => {
    const h = harness({}, false);
    const undated = doc();
    delete undated.issuedAt;
    assert.equal((await send(h, undated)).kind, "response");
    assert.equal((await send(h, doc({ id: "urn:uuid:cccccccc-cccc-4ccc-8ccc-cccccccccccc", issuedAt: "2026-11-12T09:54:00Z" }))).kind, "error");
    assert.equal((await send(h, doc({ id: "urn:uuid:dddddddd-dddd-4ddd-8ddd-dddddddddddd", issuedAt: "2026-11-12T09:54:01Z" }))).kind, "response");
  });
});

describe("design ID: hosted recipients through isServed", () => {
  it("a recipient the callback accepts is served and answered as; others get wrongRecipient from the default", async () => {
    const h = harness({ isServed: async (r) => r === "did:web:club.example", defaultVid: IUT });
    const ok = await send(h, doc({ recipient: "did:web:club.example" }));
    assert.equal(ok.kind, "response");
    assert.equal(ok.issuer, "did:web:club.example");
    const no = await send(h, doc({ recipient: "did:web:nobody.example", id: "urn:uuid:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }));
    assert.equal(codeOf(no), "wrongRecipient");
    assert.equal((no.document as { issuer: string }).issuer, IUT);
  });
  it("with no identifier of its own the issuer falls back to the document's recipient (the pre-P2 behaviour)", async () => {
    const p = new Pipeline({ handlers: [], isServed: () => false, now: () => NOW });
    const r = await p.process({ raw: JSON.stringify(doc({ recipient: "did:web:x.example" })), sender: A });
    assert.equal(codeOf(r), "unsupportedType");
    assert.equal((r.document as { issuer: string }).issuer, "did:web:x.example");
  });
});

describe("handler registry", () => {
  const h = (types: string[]): PipelineHandler => ({ types, spec: { typeUri: types[0]!, isBearer: false, isProofRequired: false, isRecipientRequired: false }, consequential: false, handle: () => undefined });
  it("refuses an empty handler and a type served twice", () => {
    assert.throws(() => new HandlerRegistry([h([])]));
    assert.throws(() => new HandlerRegistry([h([CARRIER_TYPE]), h([CARRIER_TYPE])]), /already served/);
  });
  it("finds by exact type only and lists served versions of the same specification", () => {
    const r = new HandlerRegistry([h(["https://trusttasks.org/spec/conformance/widget/0.1"]), h(["https://trusttasks.org/spec/conformance/widget/0.2"])]);
    assert.ok(r.find("https://trusttasks.org/spec/conformance/widget/0.1"));
    assert.equal(r.find("https://trusttasks.org/spec/conformance/widget/0.3"), undefined);
    assert.deepEqual(r.sameSpecification("https://trusttasks.org/spec/conformance/widget/1.0")?.servedVersions, ["0.1", "0.2"]);
    assert.equal(r.sameSpecification("https://trusttasks.org/spec/conformance/other/0.1"), undefined);
    assert.equal(r.sameSpecification("task:p2pts:policy:evaluate:0.1"), undefined);
  });
});

describe("URN codec (boundary-only wire form of the private types)", () => {
  const seeded = Object.entries(typeUris).filter(([, v]) => typeof v === "string" && (v as string).startsWith("task:p2pts:")).map(([k, v]) => [k, v as string] as const);
  it("there are seeded private types to check", () => {
    assert.ok(seeded.length >= 10);
  });
  for (const [name, internal] of seeded) {
    if (name === "TRUST_TASK_ERROR_TYPE") continue;
    it(`${name}: ${internal} has a valid wire form that round-trips`, () => {
      const wire = toWireTypeUri(internal);
      assert.ok(wire !== undefined && wire.startsWith("urn:p2pts:tasks:spec:"), internal);
      assert.notEqual(tryParseTypeUri(wire), null, wire);
      assert.equal(fromWireTypeUri(wire), internal);
      assert.equal(toWireTypeUri(`${internal}#response`), `${wire}#response`);
    });
  }
  it("the internal error type is the legacy private form; it is never minted on the wire as a trust-task-error", () => {
    assert.equal(typeUris.TRUST_TASK_ERROR_TYPE, "task:p2pts:error:trust-task:0.1");
  });
  it("names that break the slug grammar have no wire form (they must be renamed at the boundary)", () => {
    for (const bad of ["task:p2pts:policy:Evaluate:0.1", "task:p2pts:policy:eval_uate:0.1", "task:p2pts:policy:1evaluate:0.1", "task:p2pts:policy:evaluate:1", "task:other:policy:evaluate:0.1", "https://x/y"]) {
      assert.equal(toWireTypeUri(bad), undefined, bad);
    }
    assert.equal(fromWireTypeUri("urn:p2pts:tasks:spec:policy:Evaluate:0.1"), undefined);
    assert.equal(fromWireTypeUri("urn:p2pts:policy:evaluate:0.1"), undefined);
  });
});

describe("payload validator", () => {
  const v = simplePayloadValidator;
  const schema = { type: "object", required: ["a"], properties: { a: { type: "string" }, n: { type: "integer" }, o: { type: "object", required: ["x"], properties: { x: { type: "boolean" } } } }, additionalProperties: false };
  it("checks type, required, nested properties and closure", () => {
    const ok = (p: unknown): boolean => (v.validate(schema, p) as { ok: boolean }).ok;
    assert.ok(ok({ a: "s", n: 1, o: { x: true } }));
    assert.ok(!ok({}));
    assert.ok(!ok({ a: 1 }));
    assert.ok(!ok({ a: "s", n: 1.5 }));
    assert.ok(!ok({ a: "s", o: {} }));
    assert.ok(!ok({ a: "s", extra: 1 }));
    assert.ok(!ok([]));
    assert.ok(!ok(null));
  });
  it("never throws on a hostile schema and ignores what it does not understand", () => {
    assert.ok((v.validate(null, {}) as { ok: boolean }).ok);
    assert.ok((v.validate({ type: "object", oneOf: [1] }, {}) as { ok: boolean }).ok);
  });
});
