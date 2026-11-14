// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The truststackers conformance adapter (plan phases P6 to P8): the suite's adapter contract
 * implemented over the REAL pieces. The core pipeline, the durable accepted-id store, the proof
 * verifier and signer, the trust-task recorder, the per-exchange relationship DIDs (did:peer:4) and
 * the propose / issue / witness-share handlers run against temporary SQLite FILES; the receive
 * participants run on the transaction coordinator (its log is a file too). One injectable clock
 * drives the pipeline, the stores, expiry and the signer's timestamps. `restart` closes and reopens
 * the databases; `reset` starts a clean pair. Nothing here ships in the package (it is outside `src`).
 *
 * Identity: by default the agent's connection DID is a real `did:scid:vh` (the default agent class's
 * layout, `#key-1` is the identity key). `identity: 'key'` gives a `did:key` instead, which the suite's
 * harness can verify itself (it resolves only `did:key`; see the P8 report).
 *
 * Observable state is read back from the databases, never from adapter-side counters.
 * `handled`  = carrier executions + accepted proposals (acceptor side) + conformant credentials stored.
 * `stored`   = conformant credentials stored (kind vrc), witnessed credentials (kind vwc).
 * documentState(id): held -> accepted, accepted/received -> responded, declined -> errored.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as exchangeDids from '@p2p-trust-stack/core/db/repositories/vrc-exchange-dids-repo.js';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import { AcceptedIdStore } from '@p2p-trust-stack/core/services/trust-tasks/boundary/accepted-store.js';
import { Pipeline } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pipeline.js';
import type { PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { DidProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/verify.js';
import { createLocalKeyResolver } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/install.js';
import { didKeyFromEd25519, keysOfDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import type { KeyResolver, ResolvedKeySet } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { BOUNDARY_KEY_FRAGMENT, createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import type { BoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { TrustTaskRecorder } from '@p2p-trust-stack/core/services/trust-tasks/boundary/recorder.js';
import { createDiscoveryHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/discovery.js';
import { HandlerRegistry } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import type { SpecPolicy, TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { ERROR_SPEC_VERSION, FRAMEWORK_VERSION } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pins.js';
import { VrcProposeService } from '../src/runtime/trust-tasks-boundary/vrc-propose.ts';
import { createVrcIssueHandler } from '../src/runtime/trust-tasks-boundary/vrc-issue.ts';
import { VrcReceiveParticipant } from '../src/runtime/tx/vrc-receive-participant.ts';
import { WitnessShareParticipant } from '../src/runtime/tx/witness-share-participant.ts';
import { createWitnessShareHandler } from '../src/runtime/trust-tasks-boundary/witness-share.ts';
import { VtcStore } from '@p2p-trust-stack/core/vtc/store.js';
import type { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import { CompensationExecutor, DataSourceLogSink, TransactionCoordinator, TransactionLog, TransactionManager, TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/index.js';
import type { ProposeConsentPolicy, ProposeDecision } from '../src/runtime/trust-tasks-boundary/vrc-propose.ts';
import { ISSUE_TYPE, PROPOSE_TYPE, WITNESS_SHARE_TYPE } from '../src/runtime/trust-tasks-boundary/shared.ts';
import type { Adapter, Capabilities, ObserveQuery, ObserveResult, ProofVerifyResult, ProvisionedRole, SendParams, SendResult } from './contract.ts';

/** The suite's generic carrier task (its reference adapter serves the same type). A conformance fixture, not an agent feature. */
export const WIDGET_TYPE = 'https://trusttasks.org/spec/conformance/widget/0.1';
export const WIDGET_RESPONSE_TYPE = `${WIDGET_TYPE}#response`;

export interface TruststackersAdapterOptions {
  attested?: boolean;
  /** Serve `vrc/relationships/issue` (default true). */
  issue?: boolean;
  /** Also serve the suite-local `vrc/relationships/witness-share` task (conformance P7). */
  witness?: boolean;
  /**
   * The carrier the generic (framework) vectors use. `widget` (default): the suite's conformance widget
   * task, served by a fixture handler behind the same pipeline. `issue`: the issue type itself (P6 style).
   * `none`: no carrier declared, so every vector that needs one is SKIP.
   */
  carrier?: 'widget' | 'issue' | 'none';
  /** The agent's connection DID: `scid-vh` (default, a real did:scid:vh) or `key`. */
  identity?: 'scid-vh' | 'key';
  name?: string;
  tmpRoot?: string;
  seed?: number;
}

export const PASSPHRASE = 'test-passphrase-not-a-default';

/** Resolves the keys of counterpart identifiers the harness has told us about (`trust`), before anything else. */
class PinnedDocuments implements KeyResolver {
  readonly docs = new Map<string, DidDocument>();
  private readonly next: KeyResolver;
  constructor(next: KeyResolver) {
    this.next = next;
  }
  async resolve(did: string, atMs?: number): Promise<ResolvedKeySet | null> {
    const doc = this.docs.get(did);
    return doc === undefined ? this.next.resolve(did, atMs) : keysOfDocument(did, doc, 'local');
  }
}

export class TruststackersAdapter implements Adapter {
  private root: string;
  private seq = 0;
  private nowMs: number | undefined;
  private counter = 0;
  private policy: { propose: ProposeDecision; witnessed: boolean } = { propose: 'hold', witnessed: false };
  private snapshots = new Map<string, string>();
  private pinned: PinnedDocuments | undefined;
  readonly attested: boolean;
  readonly name: string;
  /** The agent's connection DID. */
  did!: string;
  /** The agent's connection DID document (what `provision` publishes). */
  didDocument: unknown;
  signer!: BoundarySigner;
  db!: SqliteDataSource;
  guard!: AcceptedIdStore;
  pipeline!: Pipeline;
  propose!: VrcProposeService;
  txManager!: TransactionManager;
  txDb!: SqliteDataSource;
  receive!: VrcReceiveParticipant;
  witnessShare!: WitnessShareParticipant;
  verifier!: DidProofVerifier;
  recorder!: TrustTaskRecorder;
  private dbPath!: string;
  private txPath!: string;

  private readonly options: TruststackersAdapterOptions;

  constructor(options: TruststackersAdapterOptions = {}) {
    this.options = options;
    this.attested = options.attested ?? false;
    this.name = options.name ?? 'truststackers-agent';
    this.root = mkdtempSync(join(options.tmpRoot ?? tmpdir(), 'ts-adapter-'));
  }

  /** Create the adapter, its identity and its databases. */
  static async create(options: TruststackersAdapterOptions = {}): Promise<TruststackersAdapter> {
    return new TruststackersAdapter(options).init();
  }

  private async makeIdentity(): Promise<void> {
    const seed = new Uint8Array(32).fill(this.options.seed ?? 0x42);
    if ((this.options.identity ?? 'scid-vh') === 'key') {
      const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
      this.did = did;
      this.didDocument = undefined;
      this.signer = createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) });
      return;
    }
    const made = await new ScidVhMethod({}).create(undefined, { identitySeed: seed });
    const first = made.document.verificationMethod?.[0];
    if (first === undefined || !first.id.endsWith(`#${BOUNDARY_KEY_FRAGMENT}`)) throw new Error('the did:scid:vh document has no #key-1');
    this.did = made.did;
    this.didDocument = made.document;
    this.signer = createEd25519BoundarySigner({ did: made.did, secretKey: made.signingKeyPair.secretKey, fragment: BOUNDARY_KEY_FRAGMENT });
  }

  /** Build (or rebuild over the same database files, for a restart) every moving part. */
  private async build(fresh: boolean): Promise<void> {
    if (fresh) {
      const n = this.seq++;
      this.dbPath = join(this.root, `app-${n}.db`);
      this.txPath = join(this.root, `tx-${n}.db`);
    }
    this.db = new SqliteDataSource(this.dbPath);
    runMigrations(this.db.getRawDb(), getMigrationsDir());
    this.txDb = new SqliteDataSource(this.txPath);
    this.txDb.getRawDb().exec(TX_SCHEMA_SQL);
    await applyTxSchemaAdditions(this.txDb);
    this.db.getRawDb().exec('CREATE TABLE IF NOT EXISTS conformance_widget_runs (id TEXT PRIMARY KEY, at INTEGER NOT NULL)');
    this.db.getRawDb().exec('CREATE TABLE IF NOT EXISTS conformance_trusted (vid TEXT PRIMARY KEY, document TEXT NOT NULL)');

    const did = this.did;
    let identity = await identitiesRepo.findByRealDid(this.db, did);
    if (identity === null) {
      const uuid = await identitiesRepo.create(this.db, { realDid: did, role: 'vta', subjectKind: 'human', custody: 'local', name: 'iut' });
      await didDocumentsRepo.create(this.db, {
        identityUuid: uuid, did, method: did.startsWith('did:scid:vh') ? 'did:scid:vh' : 'did:key',
        documentJson: JSON.stringify(this.didDocument ?? {}), isPrimary: true,
      });
      identity = await identitiesRepo.findByRealDid(this.db, did);
    }
    this.guard = new AcceptedIdStore(this.db, { now: () => this.now() });
    this.pinned = new PinnedDocuments(createLocalKeyResolver({}));
    for (const row of await this.db.all<{ vid: string; document: string }>('SELECT vid, document FROM conformance_trusted')) {
      this.pinned.docs.set(row.vid, JSON.parse(row.document) as DidDocument);
    }
    this.verifier = new DidProofVerifier({ resolver: this.pinned });
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
    this.txManager = new TransactionManager(new TransactionCoordinator(new TransactionLog(new DataSourceLogSink(this.txDb))), new CompensationExecutor());
    const noResolver = {} as IdentityResolver;
    this.receive = new VrcReceiveParticipant(`peer:${did}`, this.db, this.txDb, new VtcStore(this.db.getRawDb(), noResolver), noResolver);
    this.receive.setInnerProofVerifier(this.verifier, () => this.now());
    this.witnessShare = new WitnessShareParticipant(`peer:${did}`, this.db, this.txDb);
    this.witnessShare.setVerifier(this.verifier, () => this.now());
    const witness = this.options.witness === true ? [createWitnessShareHandler({
      db: this.db,
      txManager: this.txManager,
      participant: this.witnessShare,
      verifier: this.verifier,
      attachTx: (id, txId) => this.guard.attachTx(id, txId),
    })] : [];
    const issue = this.options.issue === false ? [] : [createVrcIssueHandler({
      db: this.db,
      txManager: this.txManager,
      participant: this.receive,
      verifier: this.verifier,
      attachTx: (id, txId) => this.guard.attachTx(id, txId),
    })];
    const registry = new HandlerRegistry([this.propose.handler(), ...issue, ...witness, ...(this.carrierMode() === 'widget' ? [this.widgetHandler()] : [])]);
    registry.register(createDiscoveryHandler(registry));
    this.recorder = new TrustTaskRecorder(this.db, { node: 'agent' });
    this.pipeline = new Pipeline({
      handlers: registry,
      servedVids: [did],
      guard: this.guard,
      now: () => this.now(),
      newId: () => this.newId(),
      proof: { verifier: this.verifier, tier: this.attested ? 2 : 1 },
      signer: this.signer,
      record: (result) => this.recorder.record(result),
      onUnexpected: (err) => console.error('[adapter] unexpected failure:', (err as Error)?.stack ?? err),
    });
  }

  private carrierMode(): 'widget' | 'issue' | 'none' {
    return this.options.carrier ?? 'widget';
  }

  /** The suite's generic carrier: consequential, `{subject}` payload, empty response; every execution is a durable row. */
  private widgetHandler(): PipelineHandler {
    const spec: SpecPolicy = {
      typeUri: WIDGET_TYPE,
      isBearer: false,
      isProofRequired: this.attested,
      isRecipientRequired: true,
      isIssuedAtRequired: true,
      payloadSchema: { type: 'object', required: ['subject'], properties: { subject: { type: 'string' } }, additionalProperties: !this.attested },
    };
    return {
      types: [WIDGET_TYPE],
      spec,
      consequential: true,
      handle: async (doc, ctx) => {
        await this.db.run('INSERT INTO conformance_widget_runs (id, at) VALUES (?, ?)', doc.id, ctx.now);
        return {
          id: ctx.newId(),
          type: WIDGET_RESPONSE_TYPE,
          threadId: typeof doc.threadId === 'string' && doc.threadId !== '' ? doc.threadId : doc.id,
          issuer: ctx.myVid ?? doc.recipient,
          recipient: doc.issuer,
          issuedAt: ctx.clock(),
          payload: {},
        } as unknown as TrustTaskDocument<unknown>;
      },
    };
  }

  async init(): Promise<this> {
    await this.makeIdentity();
    await this.build(true);
    return this;
  }

  async dispose(): Promise<void> {
    await this.closeDbs();
    rmSync(this.root, { recursive: true, force: true });
  }

  private async closeDbs(): Promise<void> {
    for (const d of [this.db, this.txDb]) {
      try {
        await d?.close();
      } catch {
        /* already closed */
      }
    }
  }

  private now(): number {
    return this.nowMs ?? Date.now();
  }
  private newId(): string {
    const n = this.counter++;
    const hex = (n.toString(16)).padStart(12, '0');
    return `urn:uuid:00000000-0000-4000-8000-${hex}`;
  }

  async capabilities(): Promise<Capabilities> {
    const mode = this.carrierMode();
    return {
      name: this.name,
      version: '0.0.0-p8',
      tierMax: (this.attested ? 2 : 1) as 1 | 2,
      bindings: ['in-process'],
      supportedTypes: [
        PROPOSE_TYPE,
        ...(this.options.issue === false ? [] : [ISSUE_TYPE]),
        ...(this.options.witness === true ? [WITNESS_SHARE_TYPE] : []),
        ...(mode === 'widget' ? [WIDGET_TYPE] : []),
      ],
      carriers: mode === 'widget'
        ? [{ typeUri: WIDGET_TYPE, class: 'consequential' as const, validPayload: { subject: 'did:web:alice.example' } }]
        : mode === 'issue' ? [{ typeUri: ISSUE_TYPE, class: 'consequential' as const, validPayload: {} }] : [],
      cryptosuites: ['eddsa-jcs-2022'],
      optional: ['trigger.consent', 'clock', 'restart', 'proofVerify', ...(this.attested ? ['attested'] : [])],
      pins: { framework: FRAMEWORK_VERSION, error: ERROR_SPEC_VERSION, binding: 'none' },
    };
  }

  async provision(roles: string[]): Promise<Record<string, ProvisionedRole>> {
    return Object.fromEntries(roles.map((r) => [r, {
      vid: this.did,
      ...(this.didDocument === undefined ? {} : { didDocument: this.didDocument }),
      transportAddress: 'in-process',
      keyCustody: 'iut' as const,
    }]));
  }
  async trust(vid: string, didDocument?: unknown): Promise<void> {
    // did:key peers resolve locally and did:peer:4 from the identifier; an unknown peer may still propose
    // (the human decides). A document the harness hands over is pinned for key lookup and kept across restarts.
    if (didDocument === undefined || didDocument === null) return;
    const text = JSON.stringify(didDocument);
    this.pinned?.docs.set(vid, didDocument as DidDocument);
    await this.db.run('DELETE FROM conformance_trusted WHERE vid = ?', vid);
    await this.db.run('INSERT INTO conformance_trusted (vid, document) VALUES (?, ?)', vid, text);
  }
  async setClock(iso: string): Promise<void> {
    const ms = Date.parse(iso);
    if (Number.isNaN(ms)) throw new Error(`unreadable clock value: ${iso}`);
    this.nowMs = ms;
  }
  async advance(ms: number): Promise<void> {
    if (typeof ms !== 'number' || !Number.isFinite(ms)) throw new Error('advance needs a number of milliseconds');
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

  /** A new process over the same files: the databases are closed and reopened, every service rebuilt. */
  async restart(): Promise<void> {
    await this.closeDbs();
    await this.build(false);
  }
  async reset(): Promise<void> {
    const old = [this.dbPath, this.txPath];
    await this.closeDbs();
    this.counter = 0;
    this.nowMs = undefined;
    this.policy = { propose: 'hold', witnessed: false };
    this.snapshots.clear();
    await this.build(true);
    for (const p of old) for (const f of [p, `${p}-wal`, `${p}-shm`]) if (existsSync(f)) rmSync(f, { force: true });
  }

  private async count(sql: string): Promise<number> {
    return Number((await this.db.get<{ n: number | string }>(sql))!.n);
  }
  async storedCount(): Promise<number> {
    return this.count("SELECT COUNT(*) AS n FROM credentials WHERE vc_type = 'vrc'");
  }
  async witnessCount(): Promise<number> {
    return this.count('SELECT COUNT(*) AS n FROM witnessed_credentials');
  }
  async widgetCount(): Promise<number> {
    return this.count('SELECT COUNT(*) AS n FROM conformance_widget_runs');
  }
  private async handledCount(): Promise<number> {
    const accepted = await this.count("SELECT COUNT(*) AS n FROM vrc_exchange_relationship_dids WHERE role = 'acceptor' AND state IN ('accepted','received','issued-by-me')");
    return accepted + (await this.storedCount()) + (await this.widgetCount());
  }

  async observe(q: ObserveQuery): Promise<ObserveResult> {
    if (q.query === 'handled') return { value: await this.handledCount() };
    if (q.query === 'stored') {
      if (q.kind === 'vrc') return { value: await this.storedCount() };
      if (q.kind === 'vwc') return { value: await this.witnessCount() };
      return { value: await this.handledCount() };
    }
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
  async diff(snapshotId: string): Promise<{ changed: boolean; detail?: string }> {
    const before = this.snapshots.get(snapshotId);
    if (before === undefined) throw new Error(`unknown snapshot: ${snapshotId}`);
    const now = await this.stateText();
    return before === now ? { changed: false } : { changed: true, detail: `${before} -> ${now}` };
  }
  private async stateText(): Promise<string> {
    return JSON.stringify({
      handled: await this.handledCount(),
      exchanges: await this.db.all('SELECT exchange_id, state FROM vrc_exchange_relationship_dids ORDER BY exchange_id'),
      credentials: await this.storedCount(),
      witnessed: await this.witnessCount(),
    });
  }

  async verifyProof(params: { bytes: string }): Promise<ProofVerifyResult> {
    try {
      return { valid: (await this.verifier.verify(JSON.parse(params.bytes), { nowMs: this.now() })).valid };
    } catch {
      return { valid: false };
    }
  }

  async send(params: SendParams): Promise<SendResult> {
    const result = await this.pipeline.process({ raw: params.bytes, sender: params.from.kind === 'none' ? undefined : params.from.vid });
    const replies = result.document === undefined ? [] : [JSON.stringify(result.document)];
    return { replies, transport: { status: result.status, kind: replies.length === 0 ? ('none' as const) : ('document' as const) }, quiescentAfterMs: 0 };
  }
}
