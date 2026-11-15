// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The verifier of `trust-ceremony-receipt` 0.1 (specs/trust-ceremony-receipt/0.1/spec.md:126-140, rules 1 to 11), over data it is
 * handed: the receipt, the resolved definition, the enactment's role bindings and the step documents it holds. Own fixtures: a
 * linear ceremony (apply, review, decide) and an approve ceremony (threshold of perRole approvals). The conformance suite's RCPT group
 * (70 vectors) is the cross-implementation check; this file is the unit oracle for each rule and for each position taken where the
 * specification is silent (those tests are named "position:").
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { base58btc } from "multiformats/bases/base58";
import { ceremonyStepDigest, verifyCeremonyReceipt } from "../../../../src/services/trust-tasks/boundary/ceremony-receipt.ts";
import type { ReceiptVerifyInput } from "../../../../src/services/trust-tasks/boundary/ceremony-receipt.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { DidKeyResolver, didKeyFromEd25519 } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import { createEd25519BoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import { digestMultibaseOf } from "../../../../src/services/trust-tasks/boundary/proof/digest.ts";
import { ed25519 } from "@noble/curves/ed25519.js";

const NOW = Date.parse("2026-11-14T10:00:00Z");
const RECEIPT_TYPE = "https://trusttasks.org/spec/trust-ceremony-receipt/0.1";
const STEP = "https://example.test/step";
const verifier = new DidProofVerifier({ resolver: new DidKeyResolver() });
const deps = { verifier, nowMs: NOW };

function actor(seed: number) {
  const secretKey = new Uint8Array(32).fill(seed);
  const did = didKeyFromEd25519(ed25519.getPublicKey(secretKey));
  return { vid: did, signer: createEd25519BoundarySigner({ did, secretKey, fragment: did.slice("did:key:".length) }) };
}
const A = actor(1), X = actor(2), W = actor(3), Q = actor(4), S = actor(5), M = actor(6);
const mb = (s: string): string => base58btc.encode(new Uint8Array(createHash("sha256").update(s).digest()));
const SALT = mb("salt");
const ENACTMENT = "urn:uuid:aaaaaaaa-0000-4000-8000-000000000001";

type Json = Record<string, any>;

const linearDef = (): Json => ({
  slug: "t-linear", version: "0.1",
  roles: { initiator: { cardinality: "one" }, reviewer: { cardinality: "one" }, recorder: { cardinality: "one" }, auditor: { cardinality: "one" } },
  steps: {
    apply: { kind: "task", type: `${STEP}/apply`, issuer: "initiator", recipient: "reviewer", prev: [] },
    review: { kind: "task", type: `${STEP}/review`, issuer: "reviewer", recipient: "initiator", optional: true, prev: ["apply"] },
    decide: { kind: "task", type: `${STEP}/decide`, issuer: "reviewer", recipient: "initiator", prev: ["review"], terminal: true },
  },
  completion: { allOf: ["apply", "decide"] },
  evidence: { level: "receipt", recorders: ["recorder", "auditor"] },
});
const approveDef = (): Json => ({
  slug: "t-approve", version: "0.1",
  roles: { proposer: { cardinality: "one" }, approver: { cardinality: "many" }, recorder: { cardinality: "one" } },
  steps: {
    propose: { kind: "task", type: `${STEP}/propose`, issuer: "proposer", recipient: "approver", prev: [] },
    approve: { kind: "task", type: `${STEP}/approve`, issuer: "approver", recipient: "proposer", multiplicity: "perRole", maxRounds: 2, prev: ["propose"], terminal: true },
  },
  completion: { threshold: { n: 2, ofStep: "approve" } },
  evidence: { level: "receipt", recorders: ["recorder"] },
});

interface Built { input: ReceiptVerifyInput; receipt: Json; docs: Json[]; def: Json }

/** An enactment of the linear ceremony, the receipt the recorder W issued and what a verifier holds. `tweak` edits before signing. */
function linear(opts: { hold?: "all" | "none" | number[]; tweak?: (b: { receipt: Json; docs: Json[]; payload: Json }) => void; skipSign?: boolean; hash?: "sha2-256" | "sha2-512" } = {}): Built {
  const H = opts.hash ?? "sha2-256";
  const def = linearDef();
  const defDigest = digestMultibaseOf(def);
  const who = [[A, X], [X, A], [X, A]] as const;
  const names = ["apply", "review", "decide"];
  const docs: Json[] = [];
  names.forEach((name, i) => {
    const prev = i === 0 ? [] : [{ id: docs[i - 1]!.id, digestMultibase: ceremonyStepDigest(docs[i - 1]!, SALT, H) }];
    const doc: Json = {
      id: `urn:uuid:bbbbbbbb-0000-4000-8000-00000000000${i}`, type: `${STEP}/${name}`, issuer: who[i]![0].vid, recipient: who[i]![1].vid,
      issuedAt: "2026-11-14T09:00:00Z",
      ceremony: { enactment: ENACTMENT, step: name, definition: "https://example.test/c/linear", definitionDigest: defDigest, ...(name === "decide" ? { terminal: true } : {}), ...(prev.length ? { prev } : {}) },
      payload: { n: i },
    };
    docs.push(signDocument(doc, who[i]![0].signer, { created: NOW - 60_000 }));
  });
  const payload: Json = {
    enactment: ENACTMENT, definition: "https://example.test/c/linear", definitionDigest: defDigest, complete: true, salt: SALT,
    steps: docs.map((d, i) => ({ step: names[i], typeUri: d.type, issuer: d.issuer, id: d.id, digestMultibase: ceremonyStepDigest(d, SALT, H), ...(i === 2 ? { terminal: true } : {}) })),
  };
  let receipt: Json = { id: "urn:uuid:cccccccc-0000-4000-8000-000000000001", type: RECEIPT_TYPE, issuer: W.vid, issuedAt: "2026-11-14T10:00:00Z", payload };
  opts.tweak?.({ receipt, docs, payload });
  if (opts.skipSign !== true) receipt = signDocument(receipt, W.signer, { created: NOW, purpose: "assertionMethod", allowIssuerMismatch: true });
  const held = opts.hold === "none" ? [] : Array.isArray(opts.hold) ? opts.hold.map((i) => docs[i]!) : docs;
  return {
    receipt, docs, def,
    input: {
      receipt: JSON.stringify(receipt), definition: def,
      roleBindings: { initiator: [A.vid], reviewer: [X.vid], recorder: [W.vid], auditor: [Q.vid] },
      steps: held.map((d) => JSON.stringify(d)),
    },
  };
}

const run = (input: ReceiptVerifyInput) => verifyCeremonyReceipt(input, deps);

describe("the step digest (spec.md:93-111)", () => {
  it("is H(JCS(document) || salt) over the document including its proof, multibase multihash", () => {
    const d = linear().docs[0]!;
    const salt = base58btc.decode(SALT);
    const msg = Buffer.concat([Buffer.from(JSON.stringify({ a: 1 })), Buffer.from(salt)]);
    const want = base58btc.encode(Uint8Array.from([0x12, 32, ...createHash("sha256").update(msg).digest()]));
    assert.equal(ceremonyStepDigest({ a: 1 }, SALT), want);
    const { proof: _p, ...bare } = d;
    assert.notEqual(ceremonyStepDigest(d, SALT), ceremonyStepDigest(bare, SALT), "the proof is part of the digested bytes");
  });
  it("puts the salt after the message, not before", () => {
    const salt = base58btc.decode(SALT);
    const prefixed = base58btc.encode(Uint8Array.from([0x12, 32, ...createHash("sha256").update(Buffer.concat([Buffer.from(salt), Buffer.from("{}")])).digest()]));
    assert.notEqual(ceremonyStepDigest({}, SALT), prefixed);
  });
  it("supports sha2-512 and says null for a salt that is not multibase", () => {
    assert.equal(base58btc.decode(ceremonyStepDigest({}, SALT, "sha2-512")!)[0], 0x13);
    assert.equal(ceremonyStepDigest({}, "!!!notmultibase", "sha2-256"), null);
  });
});

describe("verdicts", () => {
  it("complete: every document held, everything agrees", async () => {
    assert.equal((await run(linear().input)).outcome, "complete");
  });
  it("rule 7 and the closing paragraph: holding no step document is unverifiable, never complete", async () => {
    const r = await run(linear({ hold: "none" }).input);
    assert.equal(r.outcome, "unverifiable");
    assert.match(r.reason ?? "", /terminal/);
  });
  it("holding only a non-terminal document cannot confirm the marker: unverifiable", async () => {
    assert.equal((await run(linear({ hold: [0] }).input)).outcome, "unverifiable");
  });
  it("rule 1: not JSON, wrong type, no id or payload", async () => {
    assert.equal((await run({ receipt: "{" })).outcome, "invalid");
    assert.equal((await run(linear({ tweak: ({ receipt }) => { receipt.type = "https://trusttasks.org/spec/other/0.1"; } }).input)).outcome, "invalid");
    assert.equal((await run(linear({ tweak: ({ receipt }) => { delete receipt.id; } }).input)).outcome, "invalid");
  });
  it("rule 1: the payload schema is closed and typed", async () => {
    for (const f of [
      ({ payload }: { payload: Json }) => { payload.extra = 1; },
      ({ payload }: { payload: Json }) => { delete payload.complete; },
      ({ payload }: { payload: Json }) => { payload.complete = "yes"; },
      ({ payload }: { payload: Json }) => { payload.steps = []; },
      ({ payload }: { payload: Json }) => { payload.steps[0].extra = true; },
      ({ payload }: { payload: Json }) => { payload.steps[0].round = 0; },
      ({ payload }: { payload: Json }) => { payload.salt = "short"; },
      ({ payload }: { payload: Json }) => { payload.definitionDigest = "nonsense"; },
      ({ payload }: { payload: Json }) => { payload.ext = {}; },
    ]) assert.equal((await run(linear({ tweak: f }).input)).outcome, "invalid");
  });
  it("rule 1: the receipt's own proof is required, and must verify", async () => {
    assert.equal((await run(linear({ skipSign: true }).input)).outcome, "invalid");
    const b = linear();
    const bad = { ...b.receipt, proof: { ...b.receipt.proof, proofValue: b.receipt.proof.proofValue.slice(0, -2) + "zz" } };
    assert.equal((await run({ ...b.input, receipt: JSON.stringify(bad) })).outcome, "invalid");
    const tampered = { ...b.receipt, payload: { ...b.receipt.payload, complete: false } };
    assert.equal((await run({ ...b.input, receipt: JSON.stringify(tampered) })).outcome, "invalid");
  });
  it("rule 2: an unresolved or altered definition is unverifiable, not invalid", async () => {
    const b = linear();
    assert.equal((await run({ ...b.input, definition: null })).outcome, "unverifiable");
    assert.equal((await run({ ...b.input, definition: undefined })).outcome, "unverifiable");
    assert.equal((await run({ ...b.input, definition: { ...b.def, completion: { allOf: ["apply"] } } })).outcome, "unverifiable");
  });
  it("rule 3: the issuer must be a recorder the definition names, through the bindings", async () => {
    const b = linear();
    assert.equal((await run({ ...b.input, roleBindings: { ...b.input.roleBindings!, recorder: [M.vid], auditor: [] } })).outcome, "invalid");
    assert.equal((await run({ ...b.input, roleBindings: { ...b.input.roleBindings!, recorder: [M.vid], auditor: [W.vid] } })).outcome, "complete", "any named recorder role will do");
  });
  it("rule 8: no bindings is unverifiable, not satisfied", async () => {
    const b = linear();
    assert.equal((await run({ ...b.input, roleBindings: null })).outcome, "unverifiable");
    assert.equal((await run({ ...b.input, roleBindings: undefined })).outcome, "unverifiable");
  });
  it("rule 8: a step issuer not bound to the step's issuer role is invalid; so is a held recipient not bound to the recipient role", async () => {
    const b = linear();
    assert.equal((await run({ ...b.input, roleBindings: { ...b.input.roleBindings!, reviewer: [S.vid] } })).outcome, "invalid");
    assert.equal((await run({ ...b.input, roleBindings: { ...b.input.roleBindings!, initiator: [A.vid, S.vid], reviewer: [X.vid] }, steps: b.input.steps })).outcome, "complete");
    const wrongRecipient = linear({ tweak: ({ docs }) => { docs[0]!.recipient = S.vid; } });
    assert.equal((await run(wrongRecipient.input)).outcome, "invalid", "the re-signed-or-not document no longer matches the digest or the recipient role");
  });
  it("rule 4: the same document id twice, or one step twice at a round, is invalid", async () => {
    assert.equal((await run(linear({ tweak: ({ payload }) => { payload.steps.push({ ...payload.steps[0] }); } }).input)).outcome, "invalid");
    assert.equal((await run(linear({ tweak: ({ payload }) => { payload.steps.push({ ...payload.steps[0], id: "urn:uuid:dup" }); } }).input)).outcome, "invalid");
  });
  it("rule 5: the verifier evaluates the completion rule itself and ignores payload.complete", async () => {
    const lying = linear({ hold: "none", tweak: ({ payload }) => { payload.steps = payload.steps.slice(0, 1); payload.complete = true; } });
    assert.equal((await run(lying.input)).outcome, "incomplete");
    const modest = linear({ tweak: ({ payload }) => { payload.complete = false; } });
    assert.equal((await run(modest.input)).outcome, "complete", "position: a recorder that says incomplete over satisfying steps does not stop the verifier");
  });
  it("rule 6: no terminal step enumerated is a prefix; an echoed terminal on a step not declared terminal is invalid", async () => {
    const prefix = linear({ tweak: ({ payload }) => { payload.steps = payload.steps.slice(0, 2); } });
    assert.equal((await run(prefix.input)).outcome, "incomplete");
    const nominate = linear({ tweak: ({ payload }) => { payload.steps[0].terminal = true; } });
    assert.equal((await run(nominate.input)).outcome, "invalid");
  });
  it("rule 7: a held terminal document without the marker is not complete; an echo it contradicts is invalid", async () => {
    const b = linear();
    const { ceremony, proof: _p, ...rest } = b.docs[2]!;
    const { terminal: _t, ...c2 } = ceremony;
    const unmarked = signDocument({ ...rest, ceremony: c2 }, X.signer, { created: NOW - 60_000 });
    const digest = ceremonyStepDigest(unmarked, SALT);
    // the recorder echoes terminal and carries the new digest: contradicted by the held document
    const echo = linear({ tweak: ({ payload, docs }) => { docs[2] = unmarked; payload.steps[2].digestMultibase = digest; } });
    const input = { ...echo.input, steps: [...echo.input.steps!.slice(0, 2), JSON.stringify(unmarked)] };
    assert.equal((await run(input)).outcome, "invalid");
    // the recorder does not echo it: the receipt is then a prefix or the marker is missing
    const quiet = linear({ tweak: ({ payload }) => { delete payload.steps[2].terminal; payload.steps[2].digestMultibase = digest; } });
    const r = await run({ ...quiet.input, steps: [...quiet.input.steps!.slice(0, 2), JSON.stringify(unmarked)] });
    assert.equal(r.outcome, "incomplete");
  });
  it("rule 9: a held document that does not reproduce its digest is invalid (also: edited, re-signed, salt wrong)", async () => {
    const b = linear();
    const edited = { ...b.docs[0]!, payload: { n: 99 } };
    assert.equal((await run({ ...b.input, steps: [JSON.stringify(edited), ...b.input.steps!.slice(1)] })).outcome, "invalid");
    const resigned = signDocument(b.docs[0]!, A.signer, { created: NOW - 59_000 });
    assert.equal((await run({ ...b.input, steps: [JSON.stringify(resigned), ...b.input.steps!.slice(1)] })).outcome, "invalid", "the proof is in the digest");
    const wrongSalt = linear({ tweak: ({ payload }) => { payload.salt = mb("another"); } });
    assert.equal((await run(wrongSalt.input)).outcome, "invalid");
  });
  it("rule 9: a held document of another enactment, another definition, another step or round, or another issuer is invalid", async () => {
    for (const edit of [
      (c: Json) => { c.enactment = "urn:uuid:other"; },
      (c: Json) => { c.definitionDigest = mb("other def"); },
      (c: Json) => { c.step = "review"; },
      (c: Json) => { c.round = 2; },
    ]) {
      const b = linear();
      const target = { ...b.docs[0]!, ceremony: { ...b.docs[0]!.ceremony } };
      edit(target.ceremony);
      const { proof: _p, ...bare } = target;
      const re = signDocument(bare, A.signer, { created: NOW - 60_000 });
      const forged = linear({ tweak: ({ payload }) => { payload.steps[0].digestMultibase = ceremonyStepDigest(re, SALT); } });
      assert.equal((await run({ ...forged.input, steps: [JSON.stringify(re), ...forged.input.steps!.slice(1)] })).outcome, "invalid", JSON.stringify(target.ceremony));
    }
  });
  it("rule 10: a predecessor the held document commits to but the receipt omits is invalid; a different committed digest is invalid", async () => {
    const omitted = linear({ tweak: ({ payload }) => { payload.steps.splice(1, 1); } });
    assert.equal((await run(omitted.input)).outcome, "invalid");
    const b = linear();
    const { proof: _p, ...bare } = b.docs[2]!;
    const lie = signDocument({ ...bare, ceremony: { ...bare.ceremony, prev: [{ id: b.docs[1]!.id, digestMultibase: mb("lie") }] } }, X.signer, { created: NOW - 60_000 });
    const l = linear({ tweak: ({ payload }) => { payload.steps[2].digestMultibase = ceremonyStepDigest(lie, SALT); } });
    assert.equal((await run({ ...l.input, steps: [l.input.steps![0]!, l.input.steps![1]!, JSON.stringify(lie)] })).outcome, "invalid");
  });
  it("rule 10: a prev naming a document the verifier does not hold is not a failure; a predecessor that is not an ancestor is invalid", async () => {
    assert.equal((await run(linear({ hold: [2] }).input)).outcome, "complete");
    const b = linear();
    const { proof: _p, ...bare } = b.docs[0]!;
    const wrong = signDocument({ ...bare, ceremony: { ...bare.ceremony, prev: [{ id: b.docs[2]!.id, digestMultibase: ceremonyStepDigest(b.docs[2]!, SALT) }] } }, A.signer, { created: NOW - 60_000 });
    const w = linear({ tweak: ({ payload }) => { payload.steps[0].digestMultibase = ceremonyStepDigest(wrong, SALT); } });
    assert.equal((await run({ ...w.input, steps: [JSON.stringify(wrong), ...w.input.steps!.slice(1)] })).outcome, "invalid");
  });
  it("rule 11: a held document whose own proof is corrupt is invalid", async () => {
    const b = linear();
    const bad = { ...b.docs[1]!, proof: { ...b.docs[1]!.proof, proofValue: b.docs[1]!.proof.proofValue.slice(0, -2) + "zz" } };
    const withBad = linear({ tweak: ({ payload }) => { payload.steps[1].digestMultibase = ceremonyStepDigest(bad, SALT); } });
    assert.equal((await run({ ...withBad.input, steps: [withBad.input.steps![0]!, JSON.stringify(bad), withBad.input.steps![2]!] })).outcome, "invalid");
  });
});

describe("the approve ceremony: thresholds, perRole multiplicity, rounds", () => {
  function approve(instances: { step: string; actor: typeof A; round?: number }[], opts: { n?: number } = {}): ReceiptVerifyInput {
    const def = approveDef();
    if (opts.n !== undefined) def.completion = { threshold: { n: opts.n, ofStep: "approve" } };
    const defDigest = digestMultibaseOf(def);
    const docs = instances.map((s, i) => signDocument({
      id: `urn:uuid:dddddddd-0000-4000-8000-00000000000${i}`, type: `${STEP}/${s.step}`, issuer: s.actor.vid, recipient: s.step === "propose" ? X.vid : A.vid, issuedAt: "2026-11-14T09:00:00Z",
      ceremony: { enactment: ENACTMENT, step: s.step, definition: "https://example.test/c/approve", definitionDigest: defDigest, ...((s.round ?? 1) === 1 ? {} : { round: s.round }), ...(s.step === "approve" ? { terminal: true } : {}) },
      payload: {},
    }, s.actor.signer, { created: NOW - 60_000 }));
    const payload = {
      enactment: ENACTMENT, definition: "https://example.test/c/approve", definitionDigest: defDigest, complete: true, salt: SALT,
      steps: docs.map((d, i) => ({ step: instances[i]!.step, ...((instances[i]!.round ?? 1) === 1 ? {} : { round: instances[i]!.round }), typeUri: d.type, issuer: d.issuer, id: d.id, digestMultibase: ceremonyStepDigest(d, SALT), ...(instances[i]!.step === "approve" ? { terminal: true } : {}) })),
    };
    const receipt = signDocument({ id: "urn:uuid:cccccccc-0000-4000-8000-000000000009", type: RECEIPT_TYPE, issuer: W.vid, issuedAt: "2026-11-14T10:00:00Z", payload }, W.signer, { created: NOW, purpose: "assertionMethod" });
    return { receipt: JSON.stringify(receipt), definition: def, roleBindings: { proposer: [A.vid], approver: [X.vid, S.vid], recorder: [W.vid] }, steps: docs.map((d) => JSON.stringify(d)) };
  }
  it("two approvals by two approvers reach the threshold", async () => {
    assert.equal((await run(approve([{ step: "propose", actor: A }, { step: "approve", actor: X }, { step: "approve", actor: S }]))).outcome, "complete");
  });
  it("one approver listed twice at one round is invalid (a recorder cannot count one party n times)", async () => {
    assert.equal((await run(approve([{ step: "propose", actor: A }, { step: "approve", actor: X }, { step: "approve", actor: X }]))).outcome, "invalid");
  });
  it("one approver at two rounds counts once: incomplete at n = 2", async () => {
    assert.equal((await run(approve([{ step: "propose", actor: A }, { step: "approve", actor: X }, { step: "approve", actor: X, round: 2 }]))).outcome, "incomplete");
  });
  it("position: a round beyond maxRounds is invalid", async () => {
    assert.equal((await run(approve([{ step: "propose", actor: A }, { step: "approve", actor: X, round: 3 }, { step: "approve", actor: S }]))).outcome, "invalid");
  });
  it("one approval of two required is incomplete", async () => {
    assert.equal((await run(approve([{ step: "propose", actor: A }, { step: "approve", actor: X }]))).outcome, "incomplete");
  });
});

describe("positions where the specification is silent", () => {
  it("position: a step the definition does not declare, or a typeUri that differs from the declared one, is invalid", async () => {
    assert.equal((await run(linear({ hold: "none", tweak: ({ payload }) => { payload.steps[0].step = "ghost"; } }).input)).outcome, "invalid");
    assert.equal((await run(linear({ hold: "none", tweak: ({ payload }) => { payload.steps[0].typeUri = `${STEP}/other`; } }).input)).outcome, "invalid");
  });
  it("position: a bearer receipt addressed to someone else, with a threadId no step has, verifies like any other", async () => {
    assert.equal((await run(linear({ tweak: ({ receipt }) => { receipt.recipient = S.vid; receipt.threadId = "urn:uuid:eeeeeeee-0000-4000-8000-000000000001"; } }).input)).outcome, "complete");
  });
  it("position: a receipt that names its own enactment as parentEnactment is invalid", async () => {
    assert.equal((await run(linear({ tweak: ({ payload }) => { payload.parentEnactment = ENACTMENT; } }).input)).outcome, "invalid");
  });
  it("position: a held step document without a proof is invalid", async () => {
    const b = linear();
    const { proof: _p, ...bare } = b.docs[0]!;
    const unsigned = linear({ tweak: ({ payload }) => { payload.steps[0].digestMultibase = ceremonyStepDigest(bare, SALT); } });
    assert.equal((await run({ ...unsigned.input, steps: [JSON.stringify(bare), ...unsigned.input.steps!.slice(1)] })).outcome, "invalid");
  });
  it("position: no salt with held documents cannot be recomputed: unverifiable", async () => {
    assert.equal((await run(linear({ tweak: ({ payload }) => { delete payload.salt; } }).input)).outcome, "unverifiable");
  });
  it("position: a multihash function the verifier implements is checked (sha2-512); one it does not is unverifiable", async () => {
    assert.equal((await run(linear({ hash: "sha2-512" }).input)).outcome, "complete");
    const tampered = linear({ hash: "sha2-512", tweak: ({ payload }) => { payload.salt = mb("x"); } });
    assert.equal((await run(tampered.input)).outcome, "invalid");
    const unknown = linear({ hold: [0], tweak: ({ payload }) => { payload.steps[0].digestMultibase = base58btc.encode(Uint8Array.from([0x14, 32, ...new Uint8Array(32).fill(7)])); } });
    const r = await run(unknown.input);
    assert.equal(r.outcome, "unverifiable");
    assert.match(r.reason ?? "", /multihash/);
  });
  it("position: presenting the same receipt twice verifies the same way (the verifier keeps no state)", async () => {
    const b = linear();
    assert.deepEqual(await run(b.input), await run(b.input));
  });
  it("a proof whose issuer cannot be resolved right now is unverifiable, not invalid", async () => {
    const unavailable = new DidProofVerifier({ resolver: { async resolve() { const { ResolutionUnavailable } = await import("../../../../src/services/trust-tasks/boundary/proof/resolver.ts"); throw new ResolutionUnavailable("down"); } } });
    const r = await verifyCeremonyReceipt(linear().input, { verifier: unavailable, nowMs: NOW });
    assert.equal(r.outcome, "unverifiable");
  });
});
