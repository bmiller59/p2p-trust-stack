// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 3b handlers (conformance plan P4b): the `trust-task-next-step` builder, `trust-task-discovery`
 * 0.4 and the `trust-task-control` refusal. Concerns with no suite vector are named "design ...".
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { HandlerRegistry } from "../../../../src/services/trust-tasks/boundary/handlers.ts";
import type { PipelineHandler } from "../../../../src/services/trust-tasks/boundary/handlers.ts";
import { Pipeline } from "../../../../src/services/trust-tasks/boundary/pipeline.ts";
import { ACCEPTANCE_WINDOW, FRAMEWORK_VERSION } from "../../../../src/services/trust-tasks/boundary/pins.ts";
import { buildNextStep, isNextStep } from "../../../../src/services/trust-tasks/boundary/next-step.ts";
import {
  CONTROL_TYPE_URI,
  DISCOVERY_TYPE_URI,
  advertisedTypes,
  createDiscoveryHandler,
  discover,
  registerDiscovery,
  slugMatches,
  windowSeconds,
} from "../../../../src/services/trust-tasks/boundary/discovery.ts";
import {
  DISCOVERY_RESPONSE_TYPE_URI,
  NEXT_STEP_TYPE_URI,
  NEXT_STEP_PAYLOAD_SCHEMA,
  DISCOVERY_PAYLOAD_SCHEMA,
  simpleSchemaCheck,
} from "./layer3b-support.ts";
import { CARRIER_TYPE } from "./helpers.ts";

const IUT = "did:web:iut.example";
const A = "did:web:a.example";
const NOW = Date.parse("2026-11-12T10:00:00Z");
const T = "2026-11-12T10:00:00Z";
const ID = "urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const WIRE_EVAL = "urn:p2pts:tasks:spec:policy:evaluate:0.1";
const INTERNAL_EVAL = "task:p2pts:policy:evaluate:0.1";
const VRC_PROPOSE = "https://trusttasks.org/spec/vrc/relationships/propose/0.1";

const handler = (types: string[]): PipelineHandler => ({
  types,
  spec: { typeUri: types[0]!, isBearer: false, isProofRequired: false, isRecipientRequired: true, isIssuedAtRequired: false },
  consequential: false,
  handle: () => undefined,
});

function setup(types: string[][] = [[WIRE_EVAL, INTERNAL_EVAL], [VRC_PROPOSE], [CARRIER_TYPE]]) {
  const registry = new HandlerRegistry(types.map(handler));
  registerDiscovery(registry);
  let n = 0;
  const pipeline = new Pipeline({ handlers: registry, servedVids: [IUT], now: () => NOW, newId: () => `urn:uuid:r-${n++}` });
  return { registry, pipeline };
}

const request = (type: string, payload: unknown = {}, over: Record<string, unknown> = {}) =>
  JSON.stringify({ id: ID, type, issuer: A, recipient: IUT, issuedAt: T, payload, ...over });

describe("buildNextStep", () => {
  const req = { id: ID, type: VRC_PROPOSE, threadId: "urn:uuid:thread", issuer: A, recipient: IUT };

  it("design next-step shape: resubmit continuation naming the originating type, same thread, inResponseTo, swapped parties", () => {
    const doc = buildNextStep(req, { expects: [{ typeUri: VRC_PROPOSE, reason: "decision pending" }], message: "decision pending" }, { newId: () => "urn:uuid:n1", now: () => T });
    assert.equal(doc.type, NEXT_STEP_TYPE_URI);
    assert.equal(doc.id, "urn:uuid:n1");
    assert.equal(doc.threadId, "urn:uuid:thread");
    assert.equal(doc.issuer, IUT);
    assert.equal(doc.recipient, A);
    assert.equal(doc.issuedAt, T);
    assert.deepEqual(doc.payload.expects, [{ typeUri: VRC_PROPOSE, reason: "decision pending" }]);
    assert.equal(doc.payload.continuation, "resubmit");
    assert.deepEqual(doc.payload.inResponseTo, { typeUri: VRC_PROPOSE, id: ID });
    assert.equal(isNextStep(doc), true);
  });

  it("design next-step payload validates against the library schema and is closed", () => {
    const doc = buildNextStep(req, { expects: [{ typeUri: VRC_PROPOSE }, { typeUri: CARRIER_TYPE, hint: { challenge: "x" } }], continuation: "proceed" });
    assert.deepEqual(simpleSchemaCheck(NEXT_STEP_PAYLOAD_SCHEMA, doc.payload), []);
    assert.deepEqual(Object.keys(doc.payload).sort(), ["continuation", "expects", "inResponseTo"]);
    assert.notEqual(simpleSchemaCheck(NEXT_STEP_PAYLOAD_SCHEMA, { ...doc.payload, note: "x" }).length, 0);
  });

  it("design next-step thread: request thread, else request id, else its own id; no id withheld", () => {
    const noThread = buildNextStep({ id: ID, type: VRC_PROPOSE, issuer: A, recipient: IUT }, { expects: [{ typeUri: VRC_PROPOSE }] });
    assert.equal(noThread.threadId, ID);
    const noId = buildNextStep({ type: VRC_PROPOSE, issuer: A, recipient: IUT }, { expects: [{ typeUri: VRC_PROPOSE }] }, { newId: () => "urn:uuid:own" });
    assert.equal(noId.threadId, "urn:uuid:own");
    assert.deepEqual(noId.payload.inResponseTo, { typeUri: VRC_PROPOSE });
  });

  it("design next-step is a fresh document on every call and honours issuer and recipient overrides", () => {
    const a = buildNextStep(req, { expects: [{ typeUri: VRC_PROPOSE }] });
    const b = buildNextStep(req, { expects: [{ typeUri: VRC_PROPOSE }] });
    assert.notEqual(a.id, b.id);
    const o = buildNextStep(req, { expects: [{ typeUri: VRC_PROPOSE }] }, { issuer: "did:web:other", recipient: "did:web:peer" });
    assert.equal(o.issuer, "did:web:other");
    assert.equal(o.recipient, "did:web:peer");
  });

  it("design next-step refuses an empty expectation list, an expectation without a type and an unknown continuation", () => {
    assert.throws(() => buildNextStep(req, { expects: [] }), TypeError);
    assert.throws(() => buildNextStep(req, { expects: [{ typeUri: "" }] }), TypeError);
    assert.throws(() => buildNextStep(req, { expects: [{ typeUri: VRC_PROPOSE }], continuation: "later" as never }), TypeError);
  });

  it("design next-step bounds the message", () => {
    const doc = buildNextStep(req, { expects: [{ typeUri: VRC_PROPOSE }], message: "x".repeat(5000) });
    assert.equal(doc.payload.message?.length, 512);
  });
});

describe("trust-task-discovery 0.4", () => {
  it("design discovery lists exactly the registered types that are valid Type URIs, sorted, bare, unique", () => {
    const { registry } = setup();
    const listed = discover(registry, undefined).supportedTypes;
    const expected = registry.types().filter((t) => t !== INTERNAL_EVAL).sort();
    assert.deepEqual(listed, expected);
    assert.ok(listed.includes(DISCOVERY_TYPE_URI), "the discovery type itself is served and listed");
    assert.ok(listed.includes(WIRE_EVAL));
    assert.equal(listed.includes(INTERNAL_EVAL), false, "the compatibility name is served but not advertised");
    assert.equal(new Set(listed).size, listed.length);
    assert.ok(listed.every((t) => !/#/.test(t)));
    assert.equal(listed.includes(CONTROL_TYPE_URI), false);
    assert.equal(listed.includes(NEXT_STEP_TYPE_URI), false);
  });

  it("design discovery follows the registry: a later registration is listed, with no other change", () => {
    const { registry } = setup([[CARRIER_TYPE]]);
    const before = discover(registry, ["*"]).supportedTypes;
    registry.register(handler([VRC_PROPOSE]));
    const after = discover(registry, ["*"]).supportedTypes;
    assert.deepEqual(after.filter((t) => !before.includes(t)), [VRC_PROPOSE]);
  });

  it("design discovery acceptanceWindow equals the pins, in whole seconds, and states the horizon the pipeline honours", () => {
    const { registry } = setup();
    const w = discover(registry, []).acceptanceWindow;
    assert.deepEqual(w, { maxAgeSeconds: ACCEPTANCE_WINDOW.maxAgeMs / 1000, clockSkewSeconds: ACCEPTANCE_WINDOW.skewMs / 1000, expiryHorizonSeconds: ACCEPTANCE_WINDOW.expiryHorizonMs / 1000 });
    assert.ok(Object.values(w).every((v) => Number.isInteger(v)));
    assert.deepEqual(windowSeconds(), w);
    assert.equal(discover(registry, undefined).frameworkVersion, FRAMEWORK_VERSION);
  });

  it("design discovery pattern grammar: *, prefix/*, exact; wildcards elsewhere match literally; ORed; empty means *", () => {
    assert.equal(slugMatches("*", "a/b"), true);
    assert.equal(slugMatches("vrc/*", "vrc/relationships/propose"), true);
    assert.equal(slugMatches("vrc/*", "vrc"), false);
    assert.equal(slugMatches("vrc/*", "vrcx/y"), false);
    assert.equal(slugMatches("policy/evaluate", "policy/evaluate"), true);
    assert.equal(slugMatches("policy/eval", "policy/evaluate"), false);
    assert.equal(slugMatches("vrc/*-x", "vrc/a-x"), false);
    assert.equal(slugMatches("v*", "vrc"), false);
    const { registry } = setup();
    assert.deepEqual(discover(registry, ["vrc/*"]).supportedTypes, [VRC_PROPOSE]);
    assert.deepEqual(discover(registry, ["vrc/*", "policy/evaluate"]).supportedTypes, [VRC_PROPOSE, WIRE_EVAL].sort());
    assert.deepEqual(discover(registry, ["nothing/*"]).supportedTypes, []);
    assert.deepEqual(discover(registry, []).supportedTypes, discover(registry, ["*"]).supportedTypes);
    assert.deepEqual(advertisedTypes(registry).map((x) => x.slug).includes("trust-task-discovery"), true);
  });

  it("design discovery over the pipeline: a signed-capable response of the right type, thread, parties and payload", async () => {
    const { registry, pipeline } = setup();
    const r = await pipeline.process({ raw: request(DISCOVERY_TYPE_URI, { patterns: ["vrc/*"] }) });
    assert.equal(r.status, 200, JSON.stringify(r.document));
    const doc = r.document as { type: string; threadId: string; issuer: string; recipient: string; payload: unknown; id: string };
    assert.equal(doc.type, DISCOVERY_RESPONSE_TYPE_URI);
    assert.equal(doc.threadId, ID);
    assert.equal(doc.issuer, IUT);
    assert.equal(doc.recipient, A);
    assert.notEqual(doc.id, ID);
    assert.deepEqual(doc.payload, discover(registry, ["vrc/*"]));
    assert.deepEqual(simpleSchemaCheck(DISCOVERY_PAYLOAD_SCHEMA, { patterns: ["vrc/*"] }), []);
  });

  it("design discovery is repeat-safe: the same request twice is answered twice", async () => {
    const { pipeline } = setup();
    const a = await pipeline.process({ raw: request(DISCOVERY_TYPE_URI) });
    const b = await pipeline.process({ raw: request(DISCOVERY_TYPE_URI) });
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
  });

  it("design discovery refuses more than 16 patterns and non-string patterns as malformedRequest", async () => {
    const { pipeline } = setup();
    const tooMany = await pipeline.process({ raw: request(DISCOVERY_TYPE_URI, { patterns: Array.from({ length: 17 }, (_, i) => `p${i}`) }) });
    assert.equal(tooMany.code, "malformedRequest");
    const notStrings = await pipeline.process({ raw: request(DISCOVERY_TYPE_URI, { patterns: [1] }, { id: "urn:uuid:other" }) });
    assert.equal(notStrings.code, "malformedRequest");
    const empty = await pipeline.process({ raw: request(DISCOVERY_TYPE_URI, { patterns: [""] }, { id: "urn:uuid:empty" }) });
    assert.equal(empty.code, "malformedRequest");
  });

  it("design discovery payload with an unknown member is refused by the payload check", async () => {
    const { pipeline } = setup();
    const r = await pipeline.process({ raw: request(DISCOVERY_TYPE_URI, { patterns: ["*"], extra: 1 }) });
    assert.equal(r.kind, "error");
    assert.equal(r.code, "malformedRequest");
    assert.notEqual(simpleSchemaCheck(DISCOVERY_PAYLOAD_SCHEMA, { extra: 1 }).length, 0);
  });

  it("design discovery to a recipient we do not serve is wrongRecipient", async () => {
    const { pipeline } = setup();
    const r = await pipeline.process({ raw: request(DISCOVERY_TYPE_URI, {}, { recipient: "did:web:someone-else.example" }) });
    assert.equal(r.code, "wrongRecipient");
  });

  it("design discovery handler can be created on its own registry and registerDiscovery is idempotent", () => {
    const registry = new HandlerRegistry();
    registry.register(createDiscoveryHandler(registry));
    registerDiscovery(registry);
    assert.deepEqual(registry.types(), [DISCOVERY_TYPE_URI]);
  });
});

describe("trust-task-control", () => {
  it("design control is refused unsupportedType (framework 11.8), and never advertised", async () => {
    const { pipeline, registry } = setup();
    const r = await pipeline.process({ raw: request(CONTROL_TYPE_URI, { action: "cancel", target: { id: ID } }) });
    assert.equal(r.kind, "error");
    assert.equal(r.code, "unsupportedType");
    assert.equal(r.status, 422);
    const doc = r.document as { type: string; payload: { retryable: boolean; inResponseTo: { typeUri: string } } };
    assert.equal(doc.payload.retryable, false);
    assert.equal(doc.payload.inResponseTo.typeUri, CONTROL_TYPE_URI);
    assert.equal(registry.find(CONTROL_TYPE_URI), undefined);
    assert.equal(discover(registry, undefined).supportedTypes.includes(CONTROL_TYPE_URI), false);
  });

  it("design control #response as a request is malformedRequest, not a control answer", async () => {
    const { pipeline } = setup();
    const r = await pipeline.process({ raw: request(`${CONTROL_TYPE_URI}#response`) });
    assert.equal(r.code, "malformedRequest");
  });

  it("design a different control version is unsupportedType, not unsupportedVersion (the slug is not served at all)", async () => {
    const { pipeline } = setup();
    const r = await pipeline.process({ raw: request("https://trusttasks.org/spec/trust-task-control/0.2", {}) });
    assert.equal(r.code, "unsupportedType");
  });
});
