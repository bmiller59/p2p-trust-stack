// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * In-process conformance adapter for the agent's VRC boundary (conformance P6). It implements the
 * suite's adapter contract over the REAL pieces: the core pipeline, the durable accepted-id store, the
 * per-exchange relationship DIDs and the propose / issue handlers, all on a temporary SQLite database.
 * Test code only. Observable state is read back from the database, never from adapter-side counters.
 *
 * `handled`  = accepted proposals (acceptor side) + conformant credentials stored.
 * `stored`   = conformant credentials stored (kind vrc).
 * documentState(id): held -> accepted, accepted/received -> responded, declined -> errored.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { AcceptedIdStore } from '@p2p-trust-stack/core/services/trust-tasks/boundary/accepted-store.js';
import { Pipeline } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pipeline.js';
import type { PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { DidProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/verify.js';
import { createLocalKeyResolver } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/install.js';
import { didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import type { BoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { ERROR_SPEC_VERSION, FRAMEWORK_VERSION } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pins.js';
import { VrcProposeService } from '../../src/runtime/trust-tasks-boundary/vrc-propose.ts';
import type { ProposeConsentPolicy, ProposeDecision } from '../../src/runtime/trust-tasks-boundary/vrc-propose.ts';
import { ISSUE_TYPE, PROPOSE_TYPE } from '../../src/runtime/trust-tasks-boundary/shared.ts';

export const PASSPHRASE = 'test-passphrase-not-a-default';

/** What a deployment-specific part (the issue handler needs a transaction manager) plugs in. */
export interface AdapterWiring {
  db: SqliteDataSource;
  iutDid: string;
  localIdentityUuid: string;
  now: () => number;
  newId: () => string;
  guard: AcceptedIdStore;
  verifier: DidProofVerifier;
}

export interface VrcAdapterOptions {
  attested?: boolean;
  name?: string;
  /** Extra handlers (the issue handler, from 6b), built over the adapter's database. */
  extraHandlers?: (w: AdapterWiring, propose: VrcProposeService) => Promise<PipelineHandler[]> | PipelineHandler[];
  tmpRoot?: string;
}

export class VrcBoundaryAdapter {
  private root: string;
  private seq = 0;
  private nowMs: number | undefined;
  private counter = 0;
  private policy: { propose: ProposeDecision; witnessed: boolean } = { propose: 'hold', witnessed: false };
  private snapshots = new Map<string, string>();
  readonly attested: boolean;
  readonly name: string;
  readonly signer: BoundarySigner;
  db!: SqliteDataSource;
  guard!: AcceptedIdStore;
  pipeline!: Pipeline;
  propose!: VrcProposeService;
  wiring!: AdapterWiring;
  private verifier!: DidProofVerifier;
  private dbPath!: string;

  private readonly options: VrcAdapterOptions;

  constructor(options: VrcAdapterOptions = {}) {
    this.options = options;
    this.attested = options.attested ?? false;
    this.name = options.name ?? 'truststackers-agent-vrc-boundary';
    this.root = mkdtempSync(join(options.tmpRoot ?? tmpdir(), 'p6-adapter-'));
    const seed = new Uint8Array(32).fill(0x42);
    const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
    this.signer = createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) });
  }

  /** Build (or rebuild over the same database, for a restart) every moving part. */
  private async build(fresh: boolean): Promise<void> {
    if (fresh) {
      this.dbPath = join(this.root, `app-${this.seq++}.db`);
      this.db = new SqliteDataSource(this.dbPath);
      runMigrations(this.db.getRawDb(), getMigrationsDir());
    }
    const did = this.signer.did;
    let identity = await identitiesRepo.findByRealDid(this.db, did);
    if (identity === null) {
      const uuid = await identitiesRepo.create(this.db, { realDid: did, role: 'vta', subjectKind: 'human', custody: 'local', name: 'iut' });
      await didDocumentsRepo.create(this.db, { identityUuid: uuid, did, method: 'did:key', documentJson: '{}', isPrimary: true });
      identity = await identitiesRepo.findByRealDid(this.db, did);
    }
    this.guard = new AcceptedIdStore(this.db, { now: () => this.now() });
    this.verifier = new DidProofVerifier({ resolver: createLocalKeyResolver({}) });
    const policy: ProposeConsentPolicy = {
      decide: () => this.policy.propose,
      witnessed: () => this.policy.witnessed,
    };
    this.propose = new VrcProposeService({
      db: this.db,
      localIdentityUuid: identity!.uuid,
      passphrase: PASSPHRASE,
      policy,
      now: () => this.now(),
      newId: () => this.newId(),
    });
    this.wiring = { db: this.db, iutDid: did, localIdentityUuid: identity!.uuid, now: () => this.now(), newId: () => this.newId(), guard: this.guard, verifier: this.verifier };
    const extra = (await this.options.extraHandlers?.(this.wiring, this.propose)) ?? [];
    this.pipeline = new Pipeline({
      handlers: [this.propose.handler(), ...extra],
      servedVids: [did],
      guard: this.guard,
      now: () => this.now(),
      newId: () => this.newId(),
      proof: { verifier: this.verifier, tier: this.attested ? 2 : 1 },
      signer: this.signer,
    });
  }

  async init(): Promise<this> {
    await this.build(true);
    return this;
  }

  dispose(): void {
    void this.db.close().catch(() => undefined);
    rmSync(this.root, { recursive: true, force: true });
  }

  private now(): number {
    return this.nowMs ?? Date.now();
  }
  private newId(): string {
    const n = this.counter++;
    const hex = (n.toString(16)).padStart(12, '0');
    return `urn:uuid:00000000-0000-4000-8000-${hex}`;
  }

  async capabilities() {
    return {
      name: this.name,
      version: '0.0.0-p6',
      tierMax: (this.attested ? 2 : 1) as 1 | 2,
      bindings: ['in-process'],
      supportedTypes: [PROPOSE_TYPE, ISSUE_TYPE],
      carriers: [{ typeUri: ISSUE_TYPE, class: 'consequential' as const, validPayload: {} }],
      cryptosuites: ['eddsa-jcs-2022'],
      optional: ['trigger.consent', 'clock', 'restart', 'proofVerify', ...(this.attested ? ['attested'] : [])],
      pins: { framework: FRAMEWORK_VERSION, error: ERROR_SPEC_VERSION, binding: 'none' },
    };
  }

  async provision(roles: string[]) {
    return Object.fromEntries(roles.map((r) => [r, { vid: this.signer.did, transportAddress: 'in-process', keyCustody: 'iut' as const }]));
  }
  async trust(): Promise<void> {
    /* did:key peers resolve locally; an unknown peer may propose (the human decides) */
  }
  async setClock(iso: string): Promise<void> {
    const ms = Date.parse(iso);
    if (Number.isNaN(ms)) throw new Error(`unreadable clock value: ${iso}`);
    this.nowMs = ms;
  }
  async advance(ms: number): Promise<void> {
    this.nowMs = this.now() + ms;
  }

  async trigger(action: string, args: Record<string, unknown>): Promise<{ documents: string[] }> {
    if (action === 'policy') {
      const p = args.propose;
      if (p !== 'accept' && p !== 'decline' && p !== 'hold') throw new Error('policy.propose must be accept, decline or hold');
      this.policy = { propose: p, witnessed: args.witnessed === true };
      return { documents: [] };
    }
    if (action === 'consent') {
      const doc = await this.propose.decide(String(args.exchangeId), args.decision === 'accept' ? 'accept' : 'decline');
      const signed = this.attested ? signDocument(doc as unknown as Record<string, unknown>, this.signer, { created: this.now() }) : doc;
      return { documents: [JSON.stringify(signed)] };
    }
    throw new Error(`unknown trigger ${action}`);
  }

  async restart(): Promise<void> {
    await this.build(false);
  }
  async reset(): Promise<void> {
    try {
      await this.db?.close();
    } catch {
      /* ignore */
    }
    this.counter = 0;
    this.nowMs = undefined;
    this.policy = { propose: 'hold', witnessed: false };
    this.snapshots.clear();
    await this.build(true);
  }

  private async count(sql: string): Promise<number> {
    return Number((await this.db.get<{ n: number | string }>(sql))!.n);
  }
  async storedCount(): Promise<number> {
    return this.count("SELECT COUNT(*) AS n FROM credentials WHERE vc_type = 'vrc'");
  }
  private async handledCount(): Promise<number> {
    const accepted = await this.count("SELECT COUNT(*) AS n FROM vrc_exchange_relationship_dids WHERE role = 'acceptor' AND state IN ('accepted','received','issued-by-me')");
    return accepted + (await this.storedCount());
  }

  async observe(q: { query: string; id?: string; kind?: string }) {
    if (q.query === 'handled') return { value: await this.handledCount() };
    if (q.query === 'stored') return { value: q.kind === 'vrc' ? await this.storedCount() : await this.handledCount() };
    const row = await exchangeDids.findByExchangeId(this.db, String(q.id));
    if (row !== null) {
      if (row.state === 'held') return { value: 'accepted' };
      if (row.state === 'declined') return { value: 'errored' };
      return { value: 'responded' };
    }
    const claim = await this.guard.find(String(q.id));
    if (claim !== null) return { value: claim.state === 'completed' ? 'responded' : 'accepted' };
    return { value: 'unknown' };
  }

  async snapshot(): Promise<string> {
    const id = `snap-${this.snapshots.size}`;
    this.snapshots.set(id, await this.stateText());
    return id;
  }
  async diff(snapshotId: string) {
    const before = this.snapshots.get(snapshotId);
    const now = await this.stateText();
    return before === now ? { changed: false } : { changed: true, detail: `${before} -> ${now}` };
  }
  private async stateText(): Promise<string> {
    return JSON.stringify({
      handled: await this.handledCount(),
      exchanges: await this.db.all('SELECT exchange_id, state FROM vrc_exchange_relationship_dids ORDER BY exchange_id'),
      credentials: await this.storedCount(),
    });
  }

  async verifyProof(params: { bytes: string }) {
    try {
      return { valid: (await this.verifier.verify(JSON.parse(params.bytes), { nowMs: this.now() })).valid };
    } catch {
      return { valid: false };
    }
  }

  async send(params: { from: { kind: string; vid?: string }; bytes: string }) {
    const result = await this.pipeline.process({ raw: params.bytes, sender: params.from.kind === 'none' ? undefined : params.from.vid });
    const replies = result.document === undefined ? [] : [JSON.stringify(result.document)];
    return { replies, transport: { status: result.status, kind: replies.length === 0 ? ('none' as const) : ('document' as const) }, quiescentAfterMs: 0 };
  }
}
