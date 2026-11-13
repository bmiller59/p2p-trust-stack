// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The typed error model (plan P1). Vector ids in the names are the suite's (ERR-001 shape and
 * threading, ERR-002 no answer to an inbound error); the "design" ids follow the suite design table
 * (docs/04 section 11: ERR-001..008 = shape, threadId, inResponseTo, code set and extended form,
 * retryable defaults, no leak, bounded details, no reply to an inbound error), whose numbering the
 * built suite does not use past ERR-003.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  DEFAULT_RETRYABLE,
  DETAILS_MAX_BYTES,
  DETAILS_MAX_MEMBERS,
  HTTP_STATUS_BY_CODE,
  LEGACY_CODE_MAP,
  REASONS,
  REASON_VOCABULARY,
  TaskError,
  buildErrorDocument,
  defaultRetryable,
  detailsWithinBound,
  fromLegacyCode,
  httpStatusForCode,
  isExtendedCode,
  isInboundError,
  isWireCode,
  taskErrorForReason,
  toWireError,
} from "../../../../src/services/trust-tasks/boundary/errors.ts";
import { ERROR_SPEC_VERSION } from "../../../../src/services/trust-tasks/boundary/pins.ts";
import { STANDARD_CODES, TRUST_TASK_ERROR_TYPE_URI, canonicalJson, rejectWith, toErrorPayload } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import type { TrustTaskDocument } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import { TRUST_TASK_ERROR_TYPE } from "../../../../src/services/trust-tasks/type-uris.ts";
import { CARRIER_TYPE } from "./helpers.ts";

const request = (over: Record<string, unknown> = {}): TrustTaskDocument<unknown> =>
  ({ id: "urn:uuid:11111111-1111-4111-8111-111111111111", type: CARRIER_TYPE, issuer: "did:web:a.example", recipient: "did:web:iut.example", issuedAt: "2026-11-12T10:00:00Z", payload: {}, ...over }) as TrustTaskDocument<unknown>;
const opts = { newId: () => "urn:uuid:22222222-2222-4222-8222-222222222222", now: () => "2026-11-12T10:00:05Z" };

describe("ERR-001: error shape, threading, inResponseTo", () => {
  it("is a trust-task-error at the pinned version with the framework's payload members", () => {
    assert.equal(TRUST_TASK_ERROR_TYPE_URI, `https://trusttasks.org/spec/trust-task-error/${ERROR_SPEC_VERSION}`);
    const doc = buildErrorDocument(request(), new TaskError({ code: "expired" }), opts);
    assert.equal(doc.type, TRUST_TASK_ERROR_TYPE_URI);
    assert.deepEqual(doc.payload, {
      code: "expired",
      retryable: false,
      message: "The document has expired.",
      inResponseTo: { typeUri: CARRIER_TYPE, id: "urn:uuid:11111111-1111-4111-8111-111111111111" },
    });
  });

  it("is a fresh document: new id, whole-second issuedAt, issuer is the request's recipient, addressed to its issuer", () => {
    const req = request();
    const doc = buildErrorDocument(req, new TaskError({ code: "taskFailed" }), opts);
    assert.notEqual(doc.id, req.id);
    assert.equal(doc.id, "urn:uuid:22222222-2222-4222-8222-222222222222");
    assert.equal(doc.issuer, req.recipient);
    assert.equal(doc.recipient, req.issuer);
    const stamped = buildErrorDocument(req, new TaskError({ code: "taskFailed" }));
    assert.match(stamped.issuedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    assert.match(stamped.id, /^[0-9a-f-]{36}$/);
  });

  it("design ERR-002: threadId continues the request's thread, else the request's id, else its own id", () => {
    assert.equal(buildErrorDocument(request({ threadId: "t-1" }), new TaskError(), opts).threadId, "t-1");
    assert.equal(buildErrorDocument(request(), new TaskError(), opts).threadId, request().id);
    assert.equal(buildErrorDocument(undefined, new TaskError(), opts).threadId, opts.newId());
    assert.equal(buildErrorDocument({ type: CARRIER_TYPE }, new TaskError(), opts).threadId, opts.newId());
  });

  it("carries the parent thread when the request has one", () => {
    assert.equal(buildErrorDocument(request({ parentThreadId: "p-1" }), new TaskError(), opts).parentThreadId, "p-1");
    assert.equal("parentThreadId" in buildErrorDocument(request(), new TaskError(), opts), false);
  });

  it("design ERR-003: inResponseTo keeps the fragment of the request type and omits what it does not have", () => {
    const d = buildErrorDocument(request({ type: `${CARRIER_TYPE}#request` }), new TaskError(), opts);
    assert.equal(d.payload.inResponseTo?.typeUri, `${CARRIER_TYPE}#request`);
    assert.equal(buildErrorDocument(undefined, new TaskError(), opts).payload.inResponseTo, undefined);
    assert.deepEqual(buildErrorDocument({ type: CARRIER_TYPE }, new TaskError(), opts).payload.inResponseTo, { typeUri: CARRIER_TYPE });
    assert.equal(buildErrorDocument({ id: "x" }, new TaskError(), opts).payload.inResponseTo, undefined);
  });

  it("an unparseable request gives an error with no issuer or recipient (nobody trustworthy to address)", () => {
    const d = buildErrorDocument(undefined, new TaskError({ code: "malformedRequest" }), opts);
    assert.equal("issuer" in d, false);
    assert.equal("recipient" in d, false);
  });

  it("matches the registry runtime's own builder byte for byte for a full request (differential check)", () => {
    for (const code of ["malformedRequest", "unsupportedType", "expired", "idConflict", "internalError"] as const) {
      const req = request({ threadId: "t-9", parentThreadId: "p-9" });
      const ours = buildErrorDocument(req, new TaskError({ code }), opts);
      const lib = rejectWith(req, opts.newId(), toErrorPayload({ code, message: ours.payload.message, retryable: DEFAULT_RETRYABLE[code] }), opts.now);
      assert.equal(canonicalJson(ours as never), canonicalJson(lib as never), code);
    }
  });

  it("identityMismatch goes to the transport sender when one is given and never echoes inResponseTo.id", () => {
    const d = buildErrorDocument(request(), new TaskError({ code: "identityMismatch" }), { ...opts, recipient: "did:web:sender.example" });
    assert.equal(d.recipient, "did:web:sender.example");
    assert.deepEqual(d.payload.inResponseTo, { typeUri: CARRIER_TYPE });
    const noSender = buildErrorDocument(request(), new TaskError({ code: "identityMismatch" }), opts);
    assert.equal(noSender.recipient, "did:web:a.example"); // no transport sender: the in-band issuer
  });

  it("the payload fits the registry's trust-task-error 0.6 schema (closed members, message length, code grammar)", () => {
    const allowed = new Set(["code", "inResponseTo", "message", "retryable", "retryAfter", "details"]);
    const cases = [
      new TaskError({ code: "unavailable", retryAfter: "2026-11-12T10:01:00Z" }),
      taskErrorForReason("deadlineLapsed"),
      new TaskError({ code: "vrc/relationships/issue:notAccepted" }),
      new Error("boom"),
    ];
    for (const e of cases) {
      const p = buildErrorDocument(request(), e, opts).payload;
      for (const k of Object.keys(p)) assert.ok(allowed.has(k), k);
      assert.equal(typeof p.retryable, "boolean");
      assert.ok(isWireCode(p.code), p.code);
      assert.ok(p.message.length > 0 && p.message.length <= 1024);
    }
  });
});

describe("design ERR-004: code set and extended form", () => {
  it("every framework standard code is recognised and has a default and a status", () => {
    assert.deepEqual(Object.keys(DEFAULT_RETRYABLE).sort(), [...STANDARD_CODES].sort());
    assert.deepEqual(Object.keys(HTTP_STATUS_BY_CODE).sort(), [...STANDARD_CODES].sort());
    for (const c of STANDARD_CODES) assert.ok(isWireCode(c), c);
  });

  it("extended codes: slug:local grammar", () => {
    for (const ok of ["acl/grant:roleNotRecognized", "vrc/relationships/propose:declined", "vrc/relationships/issue:alreadyIssued", "did-management:unknownDomain"]) assert.ok(isExtendedCode(ok), ok);
    for (const bad of ["", "endpointNotFound", "Acl/grant:x", "acl/grant:", "acl/grant:1x", "acl grant:x", "proof/unattributable", "policy/invalid"]) assert.equal(isExtendedCode(bad), false, bad);
  });

  it("an ill-formed code never reaches the wire: it becomes an opaque internalError", () => {
    for (const bad of ["endpointNotFound", "", "TaskFailed", "policy/invalid"]) {
      const w = toWireError(new TaskError({ code: bad }));
      assert.equal(w.code, "internalError", bad);
    }
  });

  it("snake_case spellings of the frozen 0.1 codes are normalised to the canonical spelling", () => {
    assert.equal(toWireError(new TaskError({ code: "proof_required" })).code, "proofRequired");
  });

  it("an extended code is emitted as is and carries a generic message", () => {
    const w = toWireError(new TaskError({ code: "vrc/relationships/propose:declined" }));
    assert.equal(w.code, "vrc/relationships/propose:declined");
    assert.equal(w.retryable, false);
    assert.equal(w.message, "The task could not be completed.");
  });
});

describe("design ERR-005: retryable defaults (framework 8.3)", () => {
  it("true only for unavailable, indeterminate and internalError", () => {
    const yes = STANDARD_CODES.filter((c) => DEFAULT_RETRYABLE[c]);
    assert.deepEqual([...yes].sort(), ["indeterminate", "internalError", "unavailable"]);
  });
  it("retryable is always explicit on the wire, and an explicit value wins over the default", () => {
    assert.equal(toWireError(new TaskError({ code: "unavailable" })).retryable, true);
    assert.equal(toWireError(new TaskError({ code: "unavailable", retryable: false })).retryable, false);
    assert.equal(toWireError(new TaskError({ code: "taskFailed", retryable: true })).retryable, true);
    assert.equal(typeof toWireError(new TaskError()).retryable, "boolean");
    assert.equal(defaultRetryable("some/ext:code"), false);
  });
  it("retryAfter is carried only when retryable, and only when it is an RFC 3339 timestamp", () => {
    assert.equal(toWireError(new TaskError({ code: "unavailable", retryAfter: "2026-11-12T10:01:00Z" })).retryAfter, "2026-11-12T10:01:00Z");
    assert.equal("retryAfter" in toWireError(new TaskError({ code: "taskFailed", retryAfter: "2026-11-12T10:01:00Z" })), false);
    assert.equal("retryAfter" in toWireError(new TaskError({ code: "unavailable", retryAfter: "soon" })), false);
  });
});

describe("design ERR-006: no leak", () => {
  it("the wire message comes only from the code and reason vocabulary, never from the thrown message", () => {
    const secret = "SELECT * FROM identities WHERE did='did:web:a.example' at /srv/db/x.sqlite";
    for (const e of [new TaskError({ code: "taskFailed", internalMessage: secret }), new Error(secret), new TaskError({ code: "identityMismatch", internalMessage: secret })]) {
      const w = toWireError(e);
      assert.ok(!w.message.includes("SELECT") && !w.message.includes("did:web") && !w.message.includes("/srv"), w.message);
    }
  });
  it("no request member (issuer, recipient, id, type) appears in a message or in details", () => {
    const req = request({ issuer: "did:web:contested.example", recipient: "did:web:other.example" });
    for (const code of STANDARD_CODES) {
      const doc = buildErrorDocument(req, new TaskError({ code }), opts);
      const text = JSON.stringify(doc.payload.message) + JSON.stringify(doc.payload.details ?? {});
      for (const v of ["contested.example", "other.example", String(req.id)]) assert.ok(!text.includes(v), `${code}: ${v}`);
    }
  });
  it("an unknown error type is opaque, not an echo", () => {
    const w = toWireError("a string was thrown");
    assert.deepEqual(w, { code: "internalError", retryable: true, message: "An internal error occurred." });
    assert.deepEqual(toWireError(undefined), w);
    assert.deepEqual(toWireError(Object.assign(new Error("x"), { code: "taskFailed", details: { a: 1 } })), w);
  });
});

describe("design ERR-007: bounded details (framework 8.2.2)", () => {
  it("accepts details within 16 members and 4096 canonical bytes", () => {
    assert.ok(detailsWithinBound({}));
    assert.ok(detailsWithinBound(Object.fromEntries(Array.from({ length: DETAILS_MAX_MEMBERS }, (_, i) => [`k${i}`, i]))));
  });
  it("refuses 17 members, more than 4096 bytes, non-objects and things that cannot be canonicalised", () => {
    assert.equal(detailsWithinBound(Object.fromEntries(Array.from({ length: DETAILS_MAX_MEMBERS + 1 }, (_, i) => [`k${i}`, i]))), false);
    assert.equal(detailsWithinBound({ big: "x".repeat(DETAILS_MAX_BYTES) }), false);
    assert.equal(detailsWithinBound({ big: "x".repeat(DETAILS_MAX_BYTES - 20) }), true);
    assert.equal(detailsWithinBound([1]), false);
    assert.equal(detailsWithinBound("s"), false);
    assert.equal(detailsWithinBound({ n: 10n }), false);
    const loop: Record<string, unknown> = {};
    loop.self = loop;
    assert.equal(detailsWithinBound(loop), false);
  });
  it("oversized details are dropped from the document but code and retryable survive; the reason is kept", () => {
    const w = toWireError(new TaskError({ code: "taskFailed", details: { big: "x".repeat(10_000) } }));
    assert.equal(w.code, "taskFailed");
    assert.equal("details" in w, false);
    const r = toWireError(taskErrorForReason("nameTaken", { details: { big: "x".repeat(10_000) } }));
    assert.deepEqual(r.details, { reason: "nameTaken" });
    const many = Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`k${i}`, i]));
    assert.deepEqual(toWireError(taskErrorForReason("nameTaken", { details: many })).details, { reason: "nameTaken" });
  });
  it("a reason cannot be overwritten by caller details", () => {
    assert.equal(toWireError(taskErrorForReason("nameTaken", { details: { reason: "notFound" } })).details?.reason, "nameTaken");
  });
});

describe("the closed details.reason vocabulary (plan 3.9)", () => {
  const planned = ["policyDenied", "notAdmin", "nameTaken", "deadlineLapsed", "alreadyCommitted", "notAccepted", "vcInvalid", "outcomeEvidenceInvalid", "notFound", "storeFailed", "notFoundOrNotPermitted"];
  it("is exactly the planned set", () => {
    assert.deepEqual([...REASON_VOCABULARY].sort(), [...planned].sort());
  });
  it("each reason is table-tested: standard code, explicit retryable, fixed message, round trip on the wire", () => {
    for (const reason of REASON_VOCABULARY) {
      const spec = REASONS[reason];
      assert.ok((STANDARD_CODES as readonly string[]).includes(spec.code), reason);
      const w = toWireError(taskErrorForReason(reason));
      assert.equal(w.code, spec.code, reason);
      assert.equal(w.retryable, spec.retryable, reason);
      assert.equal(w.message, spec.message, reason);
      assert.deepEqual(w.details, { reason });
    }
  });
  it("a ceremony deadline is taskFailed with deadlineLapsed, not expired", () => {
    const w = toWireError(taskErrorForReason("deadlineLapsed"));
    assert.equal(w.code, "taskFailed");
    assert.deepEqual(w.details, { reason: "deadlineLapsed" });
  });
  it("an ineligible approver gets the same wire answer as a missing ceremony (notFoundOrNotPermitted)", () => {
    const a = buildErrorDocument(request(), taskErrorForReason("notFoundOrNotPermitted"), opts);
    const b = buildErrorDocument(request(), taskErrorForReason("notFoundOrNotPermitted", { internalMessage: "ceremony exists but caller is not an admin" }), opts);
    assert.equal(canonicalJson(a as never), canonicalJson(b as never));
    assert.equal(a.payload.code, "permissionDenied");
  });
  it("a reason outside the vocabulary is a programming error: opaque internalError", () => {
    assert.equal(toWireError(new TaskError({ reason: "madeUp" as never })).code, "internalError");
  });
});

describe("the status function (HTTPS binding 0.3, section 4)", () => {
  const table: [string, number][] = [
    ["malformedRequest", 400], ["permissionDenied", 403], ["idConflict", 409], ["internalError", 500], ["unavailable", 503], ["indeterminate", 503],
    ["unsupportedType", 422], ["unsupportedVersion", 422], ["expired", 422], ["proofRequired", 422], ["proofInvalid", 422], ["identityMismatch", 422],
    ["wrongRecipient", 422], ["cancelled", 422], ["taskFailed", 422], ["unsupportedExtension", 422],
  ];
  it("matches the binding row for row, for every standard code", () => {
    assert.equal(table.length, STANDARD_CODES.length);
    for (const [code, status] of table) assert.equal(httpStatusForCode(code), status, code);
  });
  it("401 is not a framework error status: no code maps to it", () => {
    for (const c of STANDARD_CODES) assert.notEqual(httpStatusForCode(c), 401);
    for (const c of STANDARD_CODES) assert.notEqual(httpStatusForCode(c), 404);
  });
  it("an extended code is the taskFailed bucket; garbage is a server fault", () => {
    assert.equal(httpStatusForCode("vrc/relationships/issue:notAccepted"), 422);
    assert.equal(httpStatusForCode("endpointNotFound"), 500);
    assert.equal(httpStatusForCode(undefined as never), 500);
  });
});

describe("ERR-002 / design ERR-008: an inbound error is recognised so it is never answered", () => {
  it("any registry version and fragment, and the bridge's pre-P1 error type", () => {
    for (const t of ["https://trusttasks.org/spec/trust-task-error/0.6", "https://trusttasks.org/spec/trust-task-error/0.1#response", "https://trusttasks.org/spec/trust-task-error/0.5", TRUST_TASK_ERROR_TYPE, `${TRUST_TASK_ERROR_TYPE}#response`]) {
      assert.ok(isInboundError({ type: t }), t);
    }
  });
  it("not a carrier task, a response, a look-alike or a missing type", () => {
    for (const t of [CARRIER_TYPE, `${CARRIER_TYPE}#response`, "https://trusttasks.org/spec/trust-task-errors/0.6", "https://example.org/spec/trust-task-error/0.6", ""]) assert.equal(isInboundError({ type: t }), false, t);
    assert.equal(isInboundError({}), false);
    assert.equal(isInboundError(undefined), false);
  });
  it("our own error documents are recognised as errors (so a looped-back error is dropped)", () => {
    assert.ok(isInboundError(buildErrorDocument(request(), new TaskError(), opts)));
  });
});

describe("legacy codes of the pre-P1 bridge", () => {
  it("each maps to a standard code", () => {
    assert.deepEqual(LEGACY_CODE_MAP, {
      malformedRequest: "malformedRequest",
      "policy/invalid": "malformedRequest",
      endpointNotFound: "unsupportedType",
      communityNotFound: "wrongRecipient",
      "proof/unattributable": "identityMismatch",
    });
    for (const c of Object.values(LEGACY_CODE_MAP)) assert.ok((STANDARD_CODES as readonly string[]).includes(c));
    assert.equal(fromLegacyCode("endpointNotFound"), "unsupportedType");
    assert.equal(fromLegacyCode("toString"), undefined);
    assert.equal(fromLegacyCode("nope"), undefined);
  });
  it("the old 404 and 401 rows land in the 422 bucket", () => {
    assert.equal(httpStatusForCode(fromLegacyCode("endpointNotFound")!), 422);
    assert.equal(httpStatusForCode(fromLegacyCode("communityNotFound")!), 422);
    assert.equal(httpStatusForCode(fromLegacyCode("proof/unattributable")!), 422);
    assert.equal(httpStatusForCode(fromLegacyCode("malformedRequest")!), 400);
  });
});
