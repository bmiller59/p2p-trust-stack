// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * P4c: task digests (design TD-001..006, docs/04 section 11: signed equals unsigned digest;
 * re-signed same digest; nested proof kept; two multibase encodings equal; plus the unknown
 * multihash and the changed-body cases) and outcome-evidence citations. Cross-checked against the
 * suite's reference digest when the suite is present.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { base58btc } from "multiformats/bases/base58";
import { generateEd25519KeyPair } from "../../../../src/crypto/primitives.ts";
import { checkCitation, citeTask, compareTaskDigest, decodeDigestMultibase, digestMultibaseOf, taskDigestMultibase } from "../../../../src/services/trust-tasks/boundary/proof/digest.ts";
import { createEd25519BoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import { didKeyFromEd25519 } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";

const key = generateEd25519KeyPair();
const did = didKeyFromEd25519(key.publicKey);
const signer = createEd25519BoundarySigner({ did, secretKey: key.secretKey, fragment: did.slice(8) });
const doc = { id: "urn:uuid:12121212-1212-4212-8212-121212121212", type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer: did, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: { b: 2, a: [1, { z: 1, y: 2 }], text: "café" } };
const T0 = Date.parse("2026-11-12T10:00:00Z");

describe("task digest (framework 4.9.3)", () => {
  it("TD-001: a signed document has the same task digest as the unsigned one", () => {
    assert.equal(taskDigestMultibase(signDocument(doc, signer, { created: T0 })), taskDigestMultibase(doc));
  });
  it("TD-002: re-signing (another instant, another purpose) leaves the task digest unchanged while the proof differs", () => {
    const one = signDocument(doc, signer, { created: T0 });
    const two = signDocument(doc, signer, { created: T0 + 5000, purpose: "assertionMethod" });
    assert.notDeepEqual(one.proof, two.proof);
    assert.equal(taskDigestMultibase(one), taskDigestMultibase(two));
  });
  it("TD-003: a proof nested inside the payload is part of the document and is kept", () => {
    const nested = { ...doc, payload: { ...doc.payload, proof: { type: "DataIntegrityProof", proofValue: "zabc" } } };
    assert.notEqual(taskDigestMultibase(nested), taskDigestMultibase(doc), "the nested proof changes the digest");
    assert.equal(taskDigestMultibase(signDocument(nested, signer, { created: T0 })), taskDigestMultibase(nested), "only the TOP-LEVEL proof is excluded");
  });
  it("TD-004: two multibase encodings of the same digest compare equal (decoded bytes), z base58btc and u base64url and f hex", () => {
    const z = taskDigestMultibase(doc);
    const bytes = decodeDigestMultibase(z)!;
    const raw = Buffer.concat([Buffer.from([0x12, 0x20]), Buffer.from(bytes.digest)]);
    const u = `u${raw.toString("base64url")}`;
    const f = `f${raw.toString("hex")}`;
    assert.ok(z.startsWith("z") && z !== u && z !== f);
    for (const spelling of [z, u, f]) assert.equal(compareTaskDigest(doc, spelling), "match", spelling);
  });
  it("TD-005: an unknown multihash is unverified, never a match and never a fallback to the id", () => {
    const sha3 = base58btc.encode(new Uint8Array([0x16, 0x20, ...new Uint8Array(32)]));
    assert.equal(compareTaskDigest(doc, sha3), "unverified");
    assert.equal(compareTaskDigest(doc, doc.id), "unverified");
    assert.equal(compareTaskDigest(doc, "z"), "unverified");
    assert.equal(compareTaskDigest(doc, 42), "unverified");
    assert.equal(compareTaskDigest(doc, `u${Buffer.from([0x12, 0x20, 1, 2]).toString("base64url")}`), "unverified", "a length that does not match the multihash header");
  });
  it("TD-006: any change of the body changes the digest and is a mismatch; member order does not", () => {
    const d = taskDigestMultibase(doc);
    assert.equal(compareTaskDigest({ ...doc, payload: { ...doc.payload, text: "cafe" } }, d), "mismatch");
    assert.equal(compareTaskDigest({ ...doc, recipient: "did:web:other.example" }, d), "mismatch");
    const reordered = Object.fromEntries(Object.entries(doc).reverse());
    assert.equal(compareTaskDigest(reordered, d), "match");
  });
  it("digestMultibaseOf is the same form over any JSON value (receipts over a credential as stored)", () => {
    assert.equal(digestMultibaseOf(doc), taskDigestMultibase(doc));
    assert.notEqual(digestMultibaseOf({ a: 1 }), digestMultibaseOf({ a: 2 }));
  });
  const suite = process.env.TRUST_CONFORMANCE_SUITE ?? "/srv/dev/code/seas/dtgwg-trust-conformance";
  it("agrees with the suite's reference digest", { skip: existsSync(join(suite, "src", "crypto", "digest.ts")) ? false : "suite not present" }, async () => {
    const ref = (await import(join(suite, "src", "crypto", "digest.ts"))) as { digestMultibase(v: unknown): string };
    const { proof: _p, ...body } = signDocument(doc, signer, { created: T0 });
    assert.equal(taskDigestMultibase(signDocument(doc, signer, { created: T0 })), ref.digestMultibase(body));
  });
});

describe("outcome evidence citations (framework 4.9.4)", () => {
  it("a citation of the initiating document checks out against the verbatim copy, signed or not", () => {
    const cite = citeTask(signDocument(doc, signer, { created: T0 }));
    assert.deepEqual(checkCitation(doc, cite), { ok: true });
    assert.deepEqual(checkCitation(signDocument(doc, signer, { created: T0 + 1000 }), cite), { ok: true });
  });
  it("refuses a wrong context, a changed document, an unknown multihash and a malformed citation", () => {
    const cite = citeTask(doc);
    assert.deepEqual(checkCitation(doc, { ...cite, taskContext: "urn:uuid:other" }), { ok: false, reason: "contextMismatch" });
    assert.deepEqual(checkCitation({ ...doc, payload: {} }, cite), { ok: false, reason: "digestMismatch" });
    assert.deepEqual(checkCitation(doc, { ...cite, taskDigestMultibase: base58btc.encode(new Uint8Array([0x16, 0x20, ...new Uint8Array(32)])) }), { ok: false, reason: "digestUnverified" });
    assert.deepEqual(checkCitation(doc, { taskContext: doc.id }), { ok: false, reason: "malformedCitation" });
    assert.throws(() => citeTask({ type: "x" }), /no id/);
  });
});
