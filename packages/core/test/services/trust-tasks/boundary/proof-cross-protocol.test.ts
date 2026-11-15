// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * P4b: cross-protocol separation (conformance plan 3.1). One Ed25519 key serves three protocols:
 * the TSP identity (raw Ed25519 over the binary CESR envelope), the operation proof (Ed25519 over a
 * canonical JSON text beginning `{"actor":"`) and, now, Trust Task document proofs (Ed25519 over two
 * concatenated 32-byte hashes). The framings are structurally disjoint, not domain-tagged, so this
 * pins that a signature made for one never validates as another, in both directions, with the SAME
 * key, and that the signed byte strings differ in length and form. (The VRC inner proof under a
 * relationship DID's own key is a further framing; it joins this test in phase P5c.)
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { base58btc } from "multiformats/bases/base58";
import { generateEd25519KeyPair, signEd25519, verifyEd25519 } from "../../../../src/crypto/primitives.ts";
import { cesrEncode } from "../../../../src/crypto/cesr.ts";
import { CESR_CODES } from "../../../../src/crypto/codes.ts";
import { operationDocumentPayload, signOperationProof, verifyOperationProof } from "../../../../src/tx/operation-proof.ts";
import { tspOpen, tspSeal } from "../../../../src/tsp/v3/index.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { DidKeyResolver, didKeyFromEd25519 } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import { createEd25519BoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import { hashData } from "../../../../src/services/trust-tasks/boundary/proof/data-integrity.ts";

const NOW = Date.parse("2026-11-12T10:00:00Z");
const key = generateEd25519KeyPair();
const vid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, key.publicKey);
const did = didKeyFromEd25519(key.publicKey);
const signer = createEd25519BoundarySigner({ did, secretKey: key.secretKey, fragment: did.slice("did:key:".length) });
const verifier = new DidProofVerifier({ resolver: new DidKeyResolver() });
const doc = { id: "urn:uuid:99999999-9999-4999-8999-999999999999", type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer: did, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: { a: 1 } };
const signedDoc = signDocument(doc, signer, { created: NOW });
const docSig = base58btc.decode(signedDoc.proof.proofValue as string);

const opInput = { actorVid: vid, txId: "tx-1", kind: "tx_prepare", messageId: "m-1", operations: [{ op: "x" }], issuedAt: Math.floor(NOW / 1000) };
const opProof = signOperationProof(opInput, signEd25519, key.secretKey);
const opSig = new Uint8Array(Buffer.from(opProof.signature, "base64url"));
const sealed = tspSeal({ vidSender: vid, vidReceiver: "did:web:peer.example", payload: { type: "TSP_GEN", body: new TextEncoder().encode("hello") }, signingSecretKey: key.secretKey });
const sealedText = new TextDecoder().decode(sealed);
// the indexed Ed25519 signature primitive is the last 88 characters of the attachment: code `AA` + 86 base64url characters of (2 zero bytes || signature)
const sigPrimitive = (sig: Uint8Array): string => Buffer.concat([Buffer.alloc(2), Buffer.from(sig)]).toString("base64url");
const tspSig = new Uint8Array(Buffer.from(sealedText.slice(-88), "base64url").subarray(2));

describe("cross-protocol separation of signatures made with one key", () => {
  it("sanity: each signature verifies in its own protocol", async () => {
    assert.equal((await verifier.verify(signedDoc, { nowMs: NOW })).valid, true);
    assert.equal(verifyOperationProof({ kind: opInput.kind, txId: opInput.txId, messageId: opInput.messageId, operations: opInput.operations, proof: opProof }, { senderVid: vid, now: opInput.issuedAt }).verdict, "verified");
    assert.equal(tspOpen({ message: sealed, senderPublicKey: key.publicKey }).vidSender, vid);
    assert.equal(tspSig.length, 64, "the extracted TSP signature is a raw Ed25519 signature");
    assert.ok(verifyEd25519(tspSig, new Uint8Array(0), key.publicKey) === false);
  });

  it("the signed byte strings are structurally disjoint (length and form)", () => {
    const op = new TextEncoder().encode(operationDocumentPayload({ actor: vid, txId: "tx-1", kind: "tx_prepare", messageId: "m-1", operations: [] }));
    assert.equal(hashData({}, {}).length, 64, "a document proof signs exactly two 32-byte hashes");
    assert.ok(new TextDecoder().decode(op).startsWith('{"actor":"'), "an operation proof signs canonical JSON beginning {\"actor\":\"");
    assert.notEqual(op.length, 64);
    assert.ok(sealedText.startsWith("-E") && sealed.length > 64, "a TSP message signs the binary CESR envelope, far longer than 64 bytes");
  });

  it("document proof -> operation proof: the document signature is not a valid operation proof", () => {
    const forged = { ...opProof, signature: Buffer.from(docSig).toString("base64url") };
    const out = verifyOperationProof({ kind: opInput.kind, txId: opInput.txId, messageId: opInput.messageId, operations: opInput.operations, proof: forged }, { senderVid: vid, now: opInput.issuedAt });
    assert.equal(out.verdict, "invalid");
  });

  it("document proof -> TSP: the document signature spliced into a TSP message does not open", () => {
    const spliced = new TextEncoder().encode(sealedText.slice(0, -88) + sigPrimitive(docSig));
    assert.throws(() => tspOpen({ message: spliced, senderPublicKey: key.publicKey }), /signature verification failed/);
    // and the splice is faithful: putting the TSP's own signature back opens it
    const back = new TextEncoder().encode(sealedText.slice(0, -88) + sigPrimitive(tspSig));
    assert.equal(tspOpen({ message: back, senderPublicKey: key.publicKey }).vidSender, vid);
  });

  it("operation proof -> document proof: the operation signature is not a valid document proof", async () => {
    const forged = { ...signedDoc, proof: { ...signedDoc.proof, proofValue: base58btc.encode(opSig) } };
    const verdict = await verifier.verify(forged, { nowMs: NOW });
    assert.equal(verdict.valid, false);
    assert.equal(verdict.failure, "signatureInvalid");
  });

  it("TSP message -> document proof: the TSP signature is not a valid document proof", async () => {
    const forged = { ...signedDoc, proof: { ...signedDoc.proof, proofValue: base58btc.encode(tspSig) } };
    assert.equal((await verifier.verify(forged, { nowMs: NOW })).valid, false);
  });

  it("operation proof -> TSP: the operation signature spliced into a TSP message does not open", () => {
    const spliced = new TextEncoder().encode(sealedText.slice(0, -88) + sigPrimitive(opSig));
    assert.throws(() => tspOpen({ message: spliced, senderPublicKey: key.publicKey }), /signature verification failed/);
  });

  it("TSP message -> operation proof: the TSP signature is not a valid operation proof", () => {
    const forged = { ...opProof, signature: Buffer.from(tspSig).toString("base64url") };
    const out = verifyOperationProof({ kind: opInput.kind, txId: opInput.txId, messageId: opInput.messageId, operations: opInput.operations, proof: forged }, { senderVid: vid, now: opInput.issuedAt });
    assert.equal(out.verdict, "invalid");
  });
});
