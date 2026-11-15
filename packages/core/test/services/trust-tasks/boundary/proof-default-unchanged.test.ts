// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The dedicated boundary key is OFF by default and the default is unchanged (gate G2). With no
 * configuration, no `dedicated` option and no verifier policy, signing, resolution and verification
 * behave exactly as they did before the dedicated-key work: `#key-1` signs, the latest key set is
 * used, there is no freshness bound on `proof.created`, and `#key-1` is never retired, even when the
 * document also publishes `#key-boundary`.
 */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { base58btc } from "multiformats/bases/base58";
import { generateEd25519KeyPair } from "../../../../src/crypto/primitives.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { DidKeyResolver, didKeyFromEd25519 } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import type { KeyResolver, ResolvedKeySet } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import { createLocalKeyResolver, installBoundarySigner } from "../../../../src/services/trust-tasks/boundary/proof/install.ts";
import { keyPolicyOf, resolveBoundaryKeyConfig } from "../../../../src/services/trust-tasks/boundary/proof/key-config.ts";
import { createEd25519BoundarySigner, getBoundarySigner, setBoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import type { DidDocument } from "../../../../src/did/types.ts";

const NOW = Date.parse("2026-11-12T10:00:00Z");
const doc = (issuer: string) => ({ id: "urn:uuid:cccccccc-3333-4333-8333-333333333333", type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: {} });
const multikey = (pub: Uint8Array) => {
  const prefixed = new Uint8Array(2 + pub.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pub, 2);
  return base58btc.encode(prefixed);
};
afterEach(() => setBoundarySigner(undefined));

describe("the dedicated key is off by default", () => {
  it("no environment: the key-1 mode and no verifier policy (the gate is the only switch)", () => {
    const { config, problem } = resolveBoundaryKeyConfig({});
    assert.deepEqual(config, { mode: "key-1" });
    assert.equal(problem, undefined);
    assert.equal(keyPolicyOf(config), undefined);
  });

  it("installBoundarySigner without the dedicated option installs the plain #key-1 signer and reports nothing else", () => {
    const k = generateEd25519KeyPair();
    const did = "did:peer:4zdefault";
    const document: DidDocument = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      verificationMethod: [{ id: "#key-1", type: "Multikey", controller: "", publicKeyMultibase: multikey(k.publicKey) }],
      authentication: ["#key-1"], assertionMethod: ["#key-1"], keyAgreement: [],
    };
    const result = installBoundarySigner({ did, didDocument: document, keys: () => k });
    assert.deepEqual(result, { installed: true });
    const signer = getBoundarySigner()!;
    assert.equal(signer.verificationMethod, `${did}#key-1`);
    assert.equal(signer.at, undefined, "no cutover hook");
    // The proof is byte-identical to the one the plain signer makes (Ed25519 is deterministic).
    const plain = createEd25519BoundarySigner({ did, secretKey: k.secretKey, fragment: "key-1" });
    const a = signDocument(doc(did), signer, { created: NOW });
    const b = signDocument(doc(did), plain, { created: NOW });
    assert.deepEqual(a.proof, b.proof);
    assert.equal(a.proof.verificationMethod, `${did}#key-1`);
  });

  it("the default local resolver answers the latest key set, never a time-pinned one", async () => {
    const k = generateEd25519KeyPair();
    const did = didKeyFromEd25519(k.publicKey);
    const set = await createLocalKeyResolver({}).resolve(did, NOW - 365 * 24 * 3600 * 1000);
    assert.equal(set?.keySetAt, "latest");
    assert.equal(set?.version, undefined);
  });

  it("with no policy the verifier has no freshness bound and never retires #key-1, even beside a published #key-boundary", async () => {
    const legacy = generateEd25519KeyPair();
    const dedicated = generateEd25519KeyPair();
    const did = didKeyFromEd25519(legacy.publicKey);
    const both: KeyResolver = {
      async resolve(d): Promise<ResolvedKeySet | null> {
        if (d !== did) return null;
        return {
          did, source: "offline", keySetAt: "latest",
          keys: [
            { fragment: "key-1", publicKey: legacy.publicKey, relationships: ["authentication", "assertionMethod"] },
            { fragment: "key-boundary", publicKey: dedicated.publicKey, relationships: ["authentication"] },
          ],
        };
      },
    };
    const verifier = new DidProofVerifier({ resolver: both });
    const signer = createEd25519BoundarySigner({ did, secretKey: legacy.secretKey, fragment: "key-1" });
    // A proof a year old, and one created long after any conceivable cutover: both accepted.
    for (const created of [NOW - 365 * 24 * 3600 * 1000, NOW - 1000]) {
      const signed = signDocument(doc(did), signer, { created });
      const verdict = await verifier.verify(signed, { nowMs: NOW });
      assert.equal(verdict.valid, true, `created ${new Date(created).toISOString()}: ${verdict.failure ?? ""}`);
    }
    // And the same through the stock did:key resolver (no extra resolution path was added to it).
    const stock = new DidProofVerifier({ resolver: new DidKeyResolver() });
    const own = createEd25519BoundarySigner({ did, secretKey: legacy.secretKey, fragment: did.slice("did:key:".length) });
    assert.equal((await stock.verify(signDocument(doc(did), own, { created: NOW - 5 * 24 * 3600 * 1000 }), { nowMs: NOW })).valid, true);
  });
});
