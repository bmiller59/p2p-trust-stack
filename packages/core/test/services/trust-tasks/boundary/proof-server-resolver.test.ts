// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * P4b: the server-side key resolver over the database-backed resolution service, with the rule that
 * a result flagged `source: 'cache'` (a snapshot with no validated rotation log) is never used to
 * verify a proof. Also the install helper: the boundary signer is installed only when `#key-1` of
 * the published document is the key held.
 */
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { SqliteDataSource } from "../../../../src/db/sqlite-data-source.ts";
import { runMigrations } from "../../../../src/db/migrate.ts";
import { getMigrationsDir } from "../../../../src/db/migrations-dir.ts";
import { ScidVhMethod } from "../../../../src/did/scid-vh-method.ts";
import { DidResolutionService } from "../../../../src/did/did-resolution-service.ts";
import { packRotationEntry } from "../../../../src/did/rotation-entry-codec.ts";
import { generateEd25519KeyPair } from "../../../../src/crypto/primitives.ts";
import type { RotationLogEntry } from "../../../../src/did/rotation-types.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { createServerKeyResolver, installBoundarySigner } from "../../../../src/services/trust-tasks/boundary/proof/install.ts";
import { createEd25519BoundarySigner, getBoundarySigner, setBoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";

const NOW = Date.parse("2026-11-12T10:00:00Z");

async function seed(ds: SqliteDataSource, did: string, log: RotationLogEntry[], documentJson: string | null): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await ds.run(`INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at) VALUES ('id-1', 'vta', 'human', 'local', 'alice', ?, ?)`, now, now);
  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, status, created_at, updated_at) VALUES ('doc-1', 'id-1', ?, 'did:scid:vh', ?, 1, 'active', ?, ?)`,
    did, documentJson, now, now,
  );
  for (const entry of log) {
    await ds.run(
      `INSERT INTO rotation_log (uuid, did_document_uuid, version, previous_hash, new_public_key, signed_entry, created_at) VALUES (?, 'doc-1', ?, ?, ?, ?, ?)`,
      `rl-${entry.version}`, entry.version, entry.prevHash ?? null,
      Buffer.from(JSON.stringify(entry.nextKeyCommitments.map((k) => Buffer.from(k).toString("base64")))),
      Buffer.from(packRotationEntry({ didDocument: entry.didDocument, parameters: entry.parameters, digest: entry.digest, signature: entry.signature, mlDsa65Signature: entry.mlDsa65Signature })),
      entry.createdAt,
    );
  }
}
const db = (): SqliteDataSource => {
  const ds = new SqliteDataSource(":memory:");
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
};
const doc = (issuer: string) => ({ id: "urn:uuid:aaaaaaaa-1111-4111-8111-111111111111", type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: {} });

describe("server key resolver over DidResolutionService", () => {
  it("a did:scid:vh peer with a validated log verifies (source: log)", async () => {
    const ds = db();
    const r = await new ScidVhMethod({}).create();
    await seed(ds, r.did, r.log, null);
    const v = new DidProofVerifier({ resolver: createServerKeyResolver(new DidResolutionService(ds)) });
    const verdict = await v.verify(signDocument(doc(r.did), createEd25519BoundarySigner({ did: r.did, secretKey: r.signingKeyPair.secretKey }), { created: NOW }), { nowMs: NOW });
    assert.equal(verdict.valid, true, verdict.detail);
    assert.equal(verdict.keySource, "log");
  });

  it("a cached snapshot with no log is refused as unavailable even though its key would verify", async () => {
    const ds = db();
    const r = await new ScidVhMethod({}).create();
    await seed(ds, r.did, [], JSON.stringify(r.document));
    assert.equal((await new DidResolutionService(ds).resolve(r.did)).source, "cache", "precondition: the service reports a cache result");
    const v = new DidProofVerifier({ resolver: createServerKeyResolver(new DidResolutionService(ds)) });
    const signed = signDocument(doc(r.did), createEd25519BoundarySigner({ did: r.did, secretKey: r.signingKeyPair.secretKey }), { created: NOW });
    await assert.rejects(v.verify(signed, { nowMs: NOW }), (e: { code?: string; retryable?: boolean }) => e.code === "unavailable" && e.retryable === true);
  });

  it("an unknown DID is unavailable (retryable), a did:web issuer is a definite refusal", async () => {
    const ds = db();
    const v = new DidProofVerifier({ resolver: createServerKeyResolver(new DidResolutionService(ds)) });
    const key = generateEd25519KeyPair();
    const unknown = "did:scid:vh:1:zQmNobodyNobodyNobodyNobodyNobodyNobod";
    await assert.rejects(v.verify(signDocument(doc(unknown), createEd25519BoundarySigner({ did: unknown, secretKey: key.secretKey }), { created: NOW }), { nowMs: NOW }), (e: { code?: string }) => e.code === "unavailable");
    const web = "did:web:example.com";
    assert.equal((await v.verify(signDocument(doc(web), createEd25519BoundarySigner({ did: web, secretKey: key.secretKey }), { created: NOW }), { nowMs: NOW })).failure, "unresolvableIssuer");
  });
});

describe("installBoundarySigner", () => {
  afterEach(() => setBoundarySigner(undefined));

  it("installs as did#key-1 when the published #key-1 is the key held (Slot-B agent, Slot-A server)", async () => {
    const b = await new ScidVhMethod({}).create();
    assert.deepEqual(installBoundarySigner({ did: b.did, didDocument: b.document, keys: () => b.signingKeyPair }), { installed: true });
    assert.equal(getBoundarySigner()?.verificationMethod, `${b.did}#key-1`);
    setBoundarySigner(undefined);
    const tsp = generateEd25519KeyPair();
    const a = await new ScidVhMethod({}).create(undefined, { transportSigningKeyPair: tsp });
    assert.equal(installBoundarySigner({ did: a.did, didDocument: a.document, keys: () => tsp }).installed, true);
    assert.equal(installBoundarySigner({ did: a.did, didDocument: a.document, keys: () => a.signingKeyPair }).installed, false, "the Slot-A identity key is #key-scid, not #key-1");
  });

  it("refuses a key that is not #key-1 and a document with no #key-1; reads the key at every signature (rotation)", async () => {
    const b = await new ScidVhMethod({}).create();
    const other = generateEd25519KeyPair();
    const bad = installBoundarySigner({ did: b.did, didDocument: b.document, keys: () => other });
    assert.equal(bad.installed, false);
    assert.equal(getBoundarySigner(), undefined);
    assert.equal(installBoundarySigner({ did: b.did, didDocument: { ...b.document, verificationMethod: [] }, keys: () => b.signingKeyPair }).installed, false);
    let current = b.signingKeyPair;
    assert.equal(installBoundarySigner({ did: b.did, didDocument: b.document, keys: () => current }).installed, true);
    const before = getBoundarySigner()!.publicKey;
    current = other;
    assert.notDeepEqual(Buffer.from(getBoundarySigner()!.publicKey), Buffer.from(before), "after a rotation the signer uses the new key");
  });
});
