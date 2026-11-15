// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Gate G2 (phase P11), K5: the time-pinned verifier.
 *
 * Timeline used throughout (seconds after the genesis entry G): the dedicated `#key-boundary` is
 * appended by a log entry at E = G+100; the cutover instant (`BOUNDARY_KEY_CUTOVER_AT`) is C = G+200.
 * A proof signed with `#key-1` before C stays valid; `#key-1` is refused from C on for an identifier
 * that lists the dedicated key; a backdated `created` cannot extend the old key's life beyond the
 * verifier's own freshness bound; a key added by an entry never verifies documents created before it.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SqliteDataSource } from "../../../../src/db/sqlite-data-source.ts";
import { runMigrations } from "../../../../src/db/migrate.ts";
import { getMigrationsDir } from "../../../../src/db/migrations-dir.ts";
import { ScidVhMethod } from "../../../../src/did/scid-vh-method.ts";
import { DidResolutionService } from "../../../../src/did/did-resolution-service.ts";
import { packRotationEntry } from "../../../../src/did/rotation-entry-codec.ts";
import { computeRotationEntryDigest } from "../../../../src/did/rotation-codec.ts";
import { createDidPeer4 } from "../../../../src/did/create.ts";
import { generateEd25519KeyPair, generateEd25519KeyPairFromSeed, signEd25519 } from "../../../../src/crypto/primitives.ts";
import type { RotationLogEntry } from "../../../../src/did/rotation-types.ts";
import { DidProofVerifier } from "../../../../src/services/trust-tasks/boundary/proof/verify.ts";
import { TimePinnedKeyResolver, entryInForceAt, scidMatchesGenesis } from "../../../../src/services/trust-tasks/boundary/proof/time-pinned.ts";
import { createLocalKeyResolver, createTimePinnedServerKeyResolver } from "../../../../src/services/trust-tasks/boundary/proof/install.ts";
import { ResolutionUnavailable } from "../../../../src/services/trust-tasks/boundary/proof/resolver.ts";
import { createEd25519BoundarySigner, signDocument } from "../../../../src/services/trust-tasks/boundary/proof/signer.ts";

const method = new ScidVhMethod({});
const doc = (issuer: string) => ({ id: "urn:uuid:aaaaaaaa-1111-4111-8111-111111111111", type: "https://trusttasks.org/spec/conformance/widget/0.1", issuer, recipient: "did:web:peer.example", issuedAt: "2026-11-12T10:00:00Z", payload: {} });

interface World {
  did: string;
  log: RotationLogEntry[];
  /** Genesis second. */
  g: number;
  tsp: { publicKey: Uint8Array; secretKey: Uint8Array };
  boundary: { publicKey: Uint8Array; secretKey: Uint8Array };
  sign: (key: "key-1" | "key-boundary", createdSec: number) => Record<string, unknown>;
  verifier: (cutoverSec?: number, maxProofAgeMs?: number) => DidProofVerifier;
}

async function world(): Promise<World> {
  const tsp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x51));
  const created = await method.create(undefined, { transportSigningKeyPair: tsp });
  const g = created.log[0]!.createdAt;
  const boundary = generateEd25519KeyPair();
  const e1 = await method.addBoundaryKey({ currentLog: created.log, identityKeyPair: created.signingKeyPair, boundaryPublicKey: boundary.publicKey, mlDsa65KeyPair: created.mlDsa65KeyPair, now: (g + 100) * 1000 });
  const log = [...created.log, e1];
  const source = { getLog: async () => log };
  return {
    did: created.did, log, g, tsp, boundary,
    sign: (key, createdSec) => signDocument(doc(created.did), createEd25519BoundarySigner({ did: created.did, secretKey: (key === "key-1" ? tsp : boundary).secretKey, fragment: key }), { created: (g + createdSec) * 1000 }),
    verifier: (cutoverSec, maxProofAgeMs) => new DidProofVerifier({
      resolver: new TimePinnedKeyResolver({ source }),
      keyPolicy: { ...(cutoverSec === undefined ? {} : { cutoverAtMs: (g + cutoverSec) * 1000 }), ...(maxProofAgeMs === undefined ? {} : { maxProofAgeMs }) },
    }),
  };
}
const at = (w: World, sec: number) => ({ nowMs: (w.g + sec) * 1000 });

describe("entryInForceAt: the rule", () => {
  it("the entry strictly before the proof second applies; at an equal second the OLD set applies; genesis applies from its own second", async () => {
    const w = await world();
    const [genesis, add] = w.log as [RotationLogEntry, RotationLogEntry];
    assert.equal(entryInForceAt(w.log, (w.g - 1) * 1000), null, "before the identifier existed");
    assert.equal(entryInForceAt(w.log, w.g * 1000)?.version, 0, "genesis applies at its own second");
    assert.equal(entryInForceAt(w.log, (w.g + 99) * 1000 + 999)?.version, 0);
    assert.equal(entryInForceAt(w.log, (w.g + 100) * 1000)?.version, 0, "tie: the old set");
    assert.equal(entryInForceAt(w.log, (w.g + 100) * 1000 + 999)?.version, 0, "still the same second");
    assert.equal(entryInForceAt(w.log, (w.g + 101) * 1000)?.version, 1);
    assert.equal(genesis.createdAt, w.g);
    assert.equal(add.createdAt, w.g + 100);
  });

  it("effective time is monotone: an entry stamped earlier than its predecessor takes the predecessor's time", async () => {
    const w = await world();
    const backdated = { ...w.log[1]!, createdAt: w.g - 5000 } as RotationLogEntry;
    const chain = [w.log[0]!, backdated];
    assert.equal(entryInForceAt(chain, (w.g - 1) * 1000), null, "a backdated entry does not reach back before genesis");
    assert.equal(entryInForceAt(chain, w.g * 1000)?.version, 0, "at genesis' own second it ties, so the old set applies");
    assert.equal(entryInForceAt(chain, (w.g + 1) * 1000)?.version, 1);
  });
});

describe("the time-pinned verifier with the cutover policy", () => {
  it("a #key-1 proof created before the cutover stays valid (verified when received)", async () => {
    const w = await world();
    const v = await w.verifier(200);
    const verdict = await v.verify(w.sign("key-1", 150), at(w, 160));
    assert.equal(verdict.valid, true, verdict.detail);
    assert.equal(verdict.keySource, "log");
  });

  it("#key-1 is refused for documents created at or after the cutover; the dedicated key is accepted", async () => {
    const w = await world();
    const v = w.verifier(200);
    const refused = await v.verify(w.sign("key-1", 250), at(w, 260));
    assert.equal(refused.valid, false);
    assert.equal(refused.failure, "keyNotListed");
    assert.match(refused.detail ?? "", /retired/);
    assert.equal((await v.verify(w.sign("key-1", 200), at(w, 200))).valid, false, "the cutover second itself is after");
    assert.equal((await v.verify(w.sign("key-1", 199), at(w, 200))).valid, true, "one second before is before");
    const ok = await v.verify(w.sign("key-boundary", 250), at(w, 260));
    assert.equal(ok.valid, true, ok.detail);
  });

  it("the dedicated key does not verify documents created before the entry that added it (tie resolves to the old set)", async () => {
    const w = await world();
    const v = w.verifier(200);
    assert.equal((await v.verify(w.sign("key-boundary", 50), at(w, 60))).failure, "keyNotListed");
    assert.equal((await v.verify(w.sign("key-boundary", 100), at(w, 110))).failure, "keyNotListed", "created in the same second as the add entry");
    assert.equal((await v.verify(w.sign("key-boundary", 101), at(w, 110))).valid, true);
  });

  it("without a cutover configured #key-1 is never retired (the default)", async () => {
    const w = await world();
    const v = w.verifier(undefined);
    assert.equal((await v.verify(w.sign("key-1", 5000), at(w, 5010))).valid, true);
  });

  it("a backdated created cannot extend #key-1 beyond the freshness bound", async () => {
    const w = await world();
    const v = w.verifier(200, 600_000);
    // A #key-1 proof made after the cutover but claiming created = C-1: accepted ONLY inside the window
    // [cutover, cutover + maxProofAgeMs) (the documented residual), refused as stale after it.
    assert.equal((await v.verify(w.sign("key-1", 199), at(w, 700))).valid, true, "inside the window: residual risk, bounded by the freshness bound");
    const late = await v.verify(w.sign("key-1", 199), at(w, 200 + 600 + 1));
    assert.equal(late.valid, false);
    assert.equal(late.failure, "createdOutOfBounds");
    // The same document judged at its receipt time is still valid: a stored document is re-verified at the recorded receipt time.
    assert.equal((await v.verify(w.sign("key-1", 199), at(w, 205))).valid, true);
  });

  it("a proof without created is refused, and a created in the future still is", async () => {
    const w = await world();
    const v = w.verifier(200);
    const noCreated = w.sign("key-1", 150);
    delete (noCreated.proof as Record<string, unknown>).created;
    assert.equal((await v.verify(noCreated, at(w, 160))).failure, "createdOutOfBounds");
    assert.equal((await v.verify(w.sign("key-1", 400), at(w, 160))).failure, "malformedProof");
  });

  it("an identifier without the dedicated key (did:peer:4) keeps #key-1 after the cutover", async () => {
    const peer = await createDidPeer4();
    const now = Date.now();
    const v = new DidProofVerifier({
      resolver: createLocalKeyResolver({ timePinned: true }),
      keyPolicy: { cutoverAtMs: now - 3_600_000 },
    });
    const signed = signDocument(doc(peer.did), createEd25519BoundarySigner({ did: peer.did, secretKey: peer.signingKeyPair.secretKey }), { created: now });
    const verdict = await v.verify(signed, { nowMs: now });
    assert.equal(verdict.valid, true, verdict.detail);
    assert.equal(verdict.keySource, "offline");
  });

  it("a chain whose later entry does not validate does not grant that entry's key", async () => {
    const w = await world();
    const broken = { ...w.log[1]!, signature: new Uint8Array(64) } as RotationLogEntry;
    const v = new DidProofVerifier({ resolver: new TimePinnedKeyResolver({ source: { getLog: async () => [w.log[0]!, broken] } }), keyPolicy: { cutoverAtMs: (w.g + 200) * 1000 } });
    assert.equal((await v.verify(w.sign("key-boundary", 250), at(w, 260))).failure, "keyNotListed");
    assert.equal((await v.verify(w.sign("key-1", 250), at(w, 260))).valid, true, "no valid dedicated key: #key-1 is not retired");
  });
});

describe("resolution inputs", () => {
  it("an empty, failing or foreign log is unavailable, never an empty key set", async () => {
    const w = await world();
    const other = await method.create();
    const resolve = (log: RotationLogEntry[] | Error) => new TimePinnedKeyResolver({ source: { getLog: async () => { if (log instanceof Error) throw log; return log; } } }).resolve(w.did, (w.g + 150) * 1000);
    await assert.rejects(resolve([]), ResolutionUnavailable);
    await assert.rejects(resolve(new Error("down")), ResolutionUnavailable);
    await assert.rejects(resolve(other.log), ResolutionUnavailable, "another identifier's log");
  });

  it("a self-consistent log whose genesis is not the hash behind the identifier is refused (SCID self-certification)", async () => {
    const victim = await method.create();
    const forger = await method.create();
    const g = forger.log[0]!;
    // The forger relabels its own genesis with the victim's DID and re-signs: chain-valid, but not the SCID's preimage.
    const didDocument = { ...g.didDocument, id: victim.did };
    const digest = computeRotationEntryDigest({ ...g, didDocument });
    const forged: RotationLogEntry = { ...g, didDocument, digest, signature: signEd25519(digest, forger.signingKeyPair.secretKey), mlDsa65Signature: undefined };
    assert.equal(method.validateEntries([forged]).length, 1, "precondition: the forged log passes validateChain");
    assert.equal(scidMatchesGenesis(victim.did, forged), false);
    assert.equal(scidMatchesGenesis(forger.did, forger.log[0]!), true, "a genuine genesis matches");
    await assert.rejects(new TimePinnedKeyResolver({ source: { getLog: async () => [forged] } }).resolve(victim.did, Date.now()), /SCID mismatch/);
  });

  it("other methods are not served here (the composite falls through)", async () => {
    assert.equal(await new TimePinnedKeyResolver({ source: { getLog: async () => [] } }).resolve("did:peer:4zQm"), null);
  });
});

describe("server resolver: validated log rows only, never the cache", () => {
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

  it("pins to created over rows stored in the database", async () => {
    const w = await world();
    const ds = db();
    await seed(ds, w.did, w.log, null);
    const v = new DidProofVerifier({ resolver: createTimePinnedServerKeyResolver(new DidResolutionService(ds)), keyPolicy: { cutoverAtMs: (w.g + 200) * 1000 } });
    assert.equal((await v.verify(w.sign("key-1", 150), at(w, 160))).valid, true);
    assert.equal((await v.verify(w.sign("key-1", 250), at(w, 260))).failure, "keyNotListed");
    assert.equal((await v.verify(w.sign("key-boundary", 250), at(w, 260))).valid, true);
    assert.equal((await v.verify(w.sign("key-boundary", 50), at(w, 60))).failure, "keyNotListed");
  });

  it("a cached document_json that lists the dedicated key is ignored: with no log held the answer is unavailable, with only the genesis the key is not listed", async () => {
    const w = await world();
    const latestDoc = JSON.stringify(w.log[1]!.didDocument);
    const noLog = db();
    await seed(noLog, w.did, [], latestDoc);
    assert.equal((await new DidResolutionService(noLog).resolve(w.did)).source, "cache", "precondition");
    const v1 = new DidProofVerifier({ resolver: createTimePinnedServerKeyResolver(new DidResolutionService(noLog)), keyPolicy: {} });
    await assert.rejects(v1.verify(w.sign("key-boundary", 250), at(w, 260)), (e: { code?: string }) => e.code === "unavailable");

    const genesisOnly = db();
    await seed(genesisOnly, w.did, [w.log[0]!], latestDoc);
    const v2 = new DidProofVerifier({ resolver: createTimePinnedServerKeyResolver(new DidResolutionService(genesisOnly)), keyPolicy: {} });
    assert.equal((await v2.verify(w.sign("key-boundary", 250), at(w, 260))).failure, "keyNotListed");
  });
});
