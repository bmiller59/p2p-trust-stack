// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * P4a: round trip against the conformance suite's reference signer and verifier (did:key documents):
 * what our signer produces the reference verifies, and what the reference signs ours verifies. The
 * suite lives beside this repository on the development machine; the test is skipped (and says so)
 * where the suite folder is absent. Override the location with TRUST_CONFORMANCE_SUITE.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { DidKeyResolver, didKeyFromEd25519 } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import { createEd25519BoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import { ed25519 } from "@noble/curves/ed25519.js";

const SUITE = process.env.TRUST_CONFORMANCE_SUITE ?? "/srv/dev/code/seas/dtgwg-trust-conformance";
const present = existsSync(join(SUITE, "src", "crypto", "proof.ts"));
const NOW = Date.parse("2026-11-12T10:00:00Z");

describe("round trip against the suite's reference verifier (did:key)", { skip: present ? false : `suite not found at ${SUITE}` }, () => {
  const doc = (issuer: string) => ({
    "@context": ["https://www.w3.org/ns/credentials/v2"], id: "urn:uuid:55555555-5555-4555-8555-555555555555",
    type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer, recipient: "did:web:peer.example",
    issuedAt: "2026-11-12T10:00:00Z", payload: { text: "café", n: [1, 2.5, 3e21], nested: { b: 1, a: 2 } },
  });

  it("our signature verifies under the reference verifier, for both purposes", async () => {
    const ref = (await import(join(SUITE, "src", "crypto", "proof.ts"))) as { verifyDocumentProof(d: unknown, o: { nowMs: number }): { valid: boolean; detail?: string } };
    const secretKey = new Uint8Array(32).fill(9);
    const did = didKeyFromEd25519(ed25519.getPublicKey(secretKey));
    const signer = createEd25519BoundarySigner({ did, secretKey, fragment: did.slice("did:key:".length) });
    for (const purpose of ["authentication", "assertionMethod"]) {
      const signed = signDocument(doc(did), signer, { created: NOW, purpose });
      const verdict = ref.verifyDocumentProof(signed, { nowMs: NOW });
      assert.equal(verdict.valid, true, `${purpose}: ${verdict.detail}`);
    }
  });

  it("the reference's signature verifies under ours, and a one-byte change breaks both", async () => {
    const refCrypto = (await import(join(SUITE, "src", "crypto", "didkey.ts"))) as { ed25519Signer(seed: Uint8Array): { did: string } };
    const ref = (await import(join(SUITE, "src", "crypto", "proof.ts"))) as { signDocument(d: unknown, s: unknown, o: { created: number }): Record<string, unknown> };
    const s = refCrypto.ed25519Signer(new Uint8Array(32).fill(11));
    const signed = ref.signDocument(doc(s.did), s, { created: NOW });
    const v = new DidProofVerifier({ resolver: new DidKeyResolver() });
    assert.equal((await v.verify(signed, { nowMs: NOW })).valid, true);
    const changed = { ...signed, payload: { text: "cafe" } };
    assert.equal((await v.verify(changed, { nowMs: NOW })).valid, false);
  });

  it("the proofs are byte-identical for the same key, document and instant (eddsa is deterministic)", async () => {
    const refCrypto = (await import(join(SUITE, "src", "crypto", "didkey.ts"))) as { ed25519Signer(seed: Uint8Array): { did: string; verificationMethod: string } };
    const ref = (await import(join(SUITE, "src", "crypto", "proof.ts"))) as { signDocument(d: unknown, s: unknown, o: { created: number }): { proof: Record<string, unknown> } };
    const seed = new Uint8Array(32).fill(13);
    const s = refCrypto.ed25519Signer(seed);
    const ours = createEd25519BoundarySigner({ did: s.did, secretKey: seed, verificationMethod: s.verificationMethod });
    assert.deepEqual(signDocument(doc(s.did), ours, { created: NOW }).proof, ref.signDocument(doc(s.did), s, { created: NOW }).proof);
  });
});
