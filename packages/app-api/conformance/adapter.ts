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
import { advertisedTypes, createDiscoveryHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/discovery.js';
import { HandlerRegistry } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import type { SpecPolicy, TrustTaskDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { ACCEPTANCE_WINDOW, ERROR_SPEC_VERSION, FRAMEWORK_VERSION } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pins.js';
import { VrcProposeService } from '../src/runtime/trust-tasks-boundary/vrc-propose.ts';
import { createVrcIssueHandler } from '../src/runtime/trust-tasks-boundary/vrc-issue.ts';
import { VrcReceiveParticipant } from '../src/runtime/tx/vrc-receive-participant.ts';
import { WitnessShareParticipant } from '../src/runtime/tx/witness-share-participant.ts';
import { createWitnessShareHandler } from '../src/runtime/trust-tasks-boundary/witness-share.ts';
import { CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_PROPOSE_WIRE_TYPE, CEREMONY_RESET_WIRE_TYPE, CEREMONY_STATUS_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-spec.js';
import { consentBinding, createCeremonyDocHandlers } from '../src/runtime/trust-tasks-boundary/ceremony-doc.ts';
import { randomBytes } from 'node:crypto';
import { HttpBinding } from './http-binding.ts';
import type { Reason } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import { FaultableParticipant, TwoPhaseFaults, parseReason, parseTwoPhase } from './two-phase.ts';
import { RetainedDocuments } from '../src/runtime/trust-tasks-boundary/retained.ts';
import { CeremonyDocParticipant } from '../src/runtime/tx/ceremony-doc-participant.ts';
import type { CeremonyEffect, CeremonyEstablishment } from '../src/runtime/tx/ceremony-doc-participant.ts';
import { TaskError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import { VtcStore } from '@p2p-trust-stack/core/vtc/store.js';
import type { IdentityResolver } from '@p2p-trust-stack/core/services/identity-resolver.js';
import { CompensationExecutor, DataSourceLogSink, TransactionCoordinator, TransactionLog, TransactionManager, TX_SCHEMA_SQL, applyTxSchemaAdditions } from '@p2p-trust-stack/core/tx/index.js';
import { CredentialReceiveParticipant } from '../src/runtime/tx/credential-receive-participant.ts';
import { CredentialPresentationParticipant } from '../src/runtime/tx/credential-presentation-participant.ts';
import { createCredentialIssueHandler, createCredentialPresentHandler } from '../src/runtime/trust-tasks-boundary/credential-exchange.ts';
import { createTaskConsentDecisionHandler, createTaskConsentRequestHandler } from '../src/runtime/trust-tasks-boundary/task-consent.ts';
import type { ConsentPrompt } from '../src/runtime/trust-tasks-boundary/task-consent.ts';
import type { ProposeConsentPolicy, ProposeDecision } from '../src/runtime/trust-tasks-boundary/vrc-propose.ts';
import { ISSUE_TYPE } from '../src/runtime/trust-tasks-boundary/shared.ts';
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
   * Serve the layer 3b-DTG adapters (conformance P5b; default true): `task-consent/{request,decision}` (the decision only with
   * the ceremony documents, whose hold it approves) and `credential-exchange/{issue,present}`. Declared as capabilities only;
   * the suite has no vector for these groups yet.
   */
  dtg?: boolean;
  /**
   * Serve the ceremony documents (begin, co-sign, status, reset) over the ceremony participant (default true).
   * The establishing effect is a FIXTURE (a unique community name recorded in an adapter-only table): the real
   * establishment (`createVtc`, fan-out) belongs to the hosting server, not to this agent.
   */
  ceremony?: boolean;
  /** Count the begin as the proposer's approval (a measuring flag, not the stack's model). Default false: begin records no approval, every named admin co-signs; the capability declaration `proposerApproves` follows this option. */
  ceremonyProposerApproves?: boolean;
  /** Ceremony deadline in milliseconds from the begin document (default 7 days). */
  ceremonyTtlMs?: number;
  /**
   * The carrier the generic (framework) vectors use. `widget` (default): the suite's conformance widget
   * task, served by a fixture handler behind the same pipeline. `issue`: the issue type itself (P6 style).
   * `none`: no carrier declared, so every vector that needs one is SKIP.
   */
  carrier?: 'widget' | 'issue' | 'none';
  /** The agent's connection DID: `scid-vh` (default, a real did:scid:vh) or `key`. */
  identity?: 'scid-vh' | 'key';
  /**
   * Declare the `https` binding and perform sends that carry an `http` request line over the agent's real listener on a loopback
   * port (default true; false declares in-process only, and the https vectors are SKIP).
   */
  https?: boolean;
  name?: string;
  /** The implementation the capabilities belong to when `name` also names a mode: runs that share it become one matrix row. */
  implementation?: string;
  tmpRoot?: string;
  seed?: number;
}

export type CeremonyPlan = { outcome: 'commit' } | { outcome: 'fail'; reason: Reason } | { outcome: 'unknown' };

/** `trigger ceremonyEffect`: the one-shot plan of the next establishing effect, and whether an `unknown` plan has just been used. */
export class CeremonyPlanSlot {
  private armed: CeremonyPlan = { outcome: 'commit' };
  unknownHit = false;
  arm(plan: CeremonyPlan): void {
    this.armed = plan;
  }
  take(): CeremonyPlan {
    const plan = this.armed;
    this.armed = { outcome: 'commit' };
    return plan;
  }
}

export function parseCeremonyEffect(args: Record<string, unknown>): CeremonyPlan {
  switch (args.outcome) {
    case 'commit':
      return { outcome: 'commit' };
    case 'fail':
      return { outcome: 'fail', reason: parseReason(args) ?? 'storeFailed' };
    case 'unknown':
      return { outcome: 'unknown' };
    default:
      throw new Error('ceremonyEffect outcome must be commit, fail or unknown');
  }
}

/** The ceremony effect the adapter uses: a community name may be established once; the same ceremony again is a no-op. */
class FixtureCommunityEffect implements CeremonyEffect {
  private readonly db: SqliteDataSource;
  private readonly plan: CeremonyPlanSlot;
  constructor(db: SqliteDataSource, plan: CeremonyPlanSlot) {
    this.db = db;
    this.plan = plan;
  }
  async establish(input: CeremonyEstablishment): Promise<void> {
    // `trigger ceremonyEffect` (one-shot): what the effect does when the next ceremony reaches its quorum.
    const plan = this.plan.take();
    if (plan.outcome === 'fail') throw new TaskError({ reason: plan.reason, internalMessage: 'conformance fault: the establishing effect is refused' });
    if (plan.outcome === 'unknown') {
      this.plan.unknownHit = true;
      throw new TaskError({ code: 'indeterminate', retryable: true, internalMessage: 'conformance fault: the effect outcome cannot be read' });
    }
    const row = await this.db.get<{ ceremony_id: string }>('SELECT ceremony_id FROM conformance_communities WHERE name = ?', input.name);
    if (row !== null && row !== undefined) {
      if (row.ceremony_id === input.ceremonyId) return;
      throw new TaskError({ reason: 'nameTaken', internalMessage: 'the community name is taken' });
    }
    await this.db.run('INSERT INTO conformance_communities (name, ceremony_id, kind, admins) VALUES (?, ?, ?, ?)', input.name, input.ceremonyId, input.kind, JSON.stringify(input.adminDids));
  }
}

function documentId(bytes: string): string | undefined {
  try {
    const id = (JSON.parse(bytes) as { id?: unknown }).id;
    return typeof id === 'string' ? id : undefined;
  } catch {
    return undefined;
  }
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
  /** `fault {claimStore: 'unreadable'}`: the duplicate-record table cannot be read or written (the rest of the database still can). */
  private claimStoreUnreadable = false;
  private snapshots = new Map<string, string>();
  /** `trigger twoPhase`: the one-shot fault of the next issue transaction, and the transaction `inflight`/`unknown` left waiting. */
  private readonly faults = new TwoPhaseFaults();
  /** `trigger ceremonyEffect`, and the request whose effect outcome was unknown, answered again by `settle`. */
  private readonly ceremonyPlan = new CeremonyPlanSlot();
  private pendingCeremony: SendParams | undefined;
  /** The `send` whose transaction is parked, answered by `settle`. */
  private pendingSend: Promise<SendResult> | undefined;
  private readonly http = new HttpBinding();
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
  presentation!: CredentialPresentationParticipant;
  /** Consent prompts raised for the (simulated) human by `task-consent/request`. */
  readonly consentPrompts: ConsentPrompt[] = [];
  /** Executors this device is enrolled with (`trigger enrolExecutor`); empty until the suite enrols one. */
  readonly enrolledExecutors = new Set<string>();
  ceremony!: CeremonyDocParticipant;
  retained!: RetainedDocuments;
  verifier!: DidProofVerifier;
  registry!: HandlerRegistry;
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

    this.db.getRawDb().exec('CREATE TABLE IF NOT EXISTS conformance_communities (name TEXT PRIMARY KEY, ceremony_id TEXT NOT NULL, kind TEXT NOT NULL, admins TEXT NOT NULL)');

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
    this.guard = new AcceptedIdStore(this.faultableDb(), { now: () => this.now() });
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
    this.ceremony = new CeremonyDocParticipant(`ceremony:${did}`, this.txDb, new FixtureCommunityEffect(this.db, this.ceremonyPlan), { proposerApproves: this.options.ceremonyProposerApproves === true, ...(this.options.ceremonyTtlMs === undefined ? {} : { ttlMs: this.options.ceremonyTtlMs }) });
    this.retained = new RetainedDocuments(this.db);
    const ceremony = this.options.ceremony === false ? [] : createCeremonyDocHandlers({
      txManager: this.txManager,
      participant: this.ceremony,
      attachTx: (id, txId) => this.guard.attachTx(id, txId),
    });
    this.presentation = new CredentialPresentationParticipant(`peer:${did}`, this.db, this.txDb);
    this.presentation.setVerifier(this.verifier, () => this.now());
    const dtg = this.options.dtg === false ? [] : [
      createCredentialIssueHandler({ db: this.db, txManager: this.txManager, participant: new CredentialReceiveParticipant(`peer:${did}`, this.db, this.txDb), verifier: this.verifier, attachTx: (id, txId) => this.guard.attachTx(id, txId) }),
      createCredentialPresentHandler({ txManager: this.txManager, participant: this.presentation, verifier: this.verifier, attachTx: (id, txId) => this.guard.attachTx(id, txId) }),
      createTaskConsentRequestHandler({ isEnrolledExecutor: (did) => this.enrolledExecutors.has(did), prompt: (p) => { this.consentPrompts.push(p); } }),
      ...(this.options.ceremony === false ? [] : [createTaskConsentDecisionHandler({ txManager: this.txManager, participant: this.ceremony, attachTx: (id, txId) => this.guard.attachTx(id, txId) })]),
    ];
    const issue = this.options.issue === false ? [] : [createVrcIssueHandler({
      db: this.db,
      txManager: this.txManager,
      participant: new FaultableParticipant(this.receive, this.faults),
      verifier: this.verifier,
      attachTx: (id, txId) => this.guard.attachTx(id, txId),
    })];
    const registry = this.registry = new HandlerRegistry([this.propose.handler(), ...issue, ...witness, ...ceremony, ...dtg, ...(this.carrierMode() === 'widget' ? [this.widgetHandler()] : [])]);
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
    // The listener hands documents to whatever pipeline the adapter has now, so reset and restart need no new listener.
    if (this.options.https !== false) await this.http.start((input) => this.pipeline.process(input));
    return this;
  }

  async dispose(): Promise<void> {
    await this.http.stop();
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
      ...(this.options.implementation === undefined ? {} : { implementation: this.options.implementation }),
      version: '0.0.0-p8',
      tierMax: (this.attested ? 2 : 1) as 1 | 2,
      bindings: this.options.https === false ? ['in-process'] : ['in-process', 'https'],
      // Discovery 0.4 (docs/04 section 11.2): every served task's Type URI, discovery's own included, exactly as the
      // discovery answer lists them (registry form for the https types, URN form for the private ceremony types).
      supportedTypes: advertisedTypes(this.registry).map((t) => t.type),
      carriers: mode === 'widget'
        ? [{ typeUri: WIDGET_TYPE, class: 'consequential' as const, validPayload: { subject: 'did:web:alice.example' } }]
        : mode === 'issue' ? [{ typeUri: ISSUE_TYPE, class: 'consequential' as const, validPayload: {} }] : [],
      cryptosuites: ['eddsa-jcs-2022'],
      optional: ['trigger.consent', 'clock', 'restart', 'fault.claimStore', 'trigger.twoPhase', ...(this.options.ceremony === false ? [] : ['ceremony', 'ceremony.status', 'trigger.ceremonyDeadline', 'trigger.ceremonyEffect', 'observe.retained']), 'discovery.acceptanceWindow', 'discovery.expiryHorizon', 'proofVerify', ...(this.options.dtg === false ? [] : ['trigger.consentEnrol', 'trigger.presentationNonce', ...(this.options.ceremony === false ? [] : ['trigger.consentBinding'])]), ...(this.attested ? ['attested'] : [])],
      ...(this.options.ceremony === false ? {} : {
        ceremony: {
          beginType: CEREMONY_PROPOSE_WIRE_TYPE, approveType: CEREMONY_CO_SIGN_WIRE_TYPE, resetType: CEREMONY_RESET_WIRE_TYPE, statusType: CEREMONY_STATUS_WIRE_TYPE, statusPayload: {}, proposerApproves: this.options.ceremonyProposerApproves === true,
          beginPayload: { name: 'fixture-community', kind: 'vtc', threshold: 2, adminDids: ['$A', '$X'] }, approvePayload: {}, resetPayload: {},
        },
      }),
      // The window the pipeline enforces (the same constants the discovery answer states), so a vector measures this
      // implementation against its own window, not a number the suite assumes (suite docs/04 section 6).
      window: {
        maxAgeSeconds: ACCEPTANCE_WINDOW.maxAgeMs / 1000,
        clockSkewSeconds: ACCEPTANCE_WINDOW.skewMs / 1000,
        expiryHorizonSeconds: ACCEPTANCE_WINDOW.expiryHorizonMs / 1000,
      },
      pins: { framework: FRAMEWORK_VERSION, error: ERROR_SPEC_VERSION, binding: this.options.https === false ? 'none' : 'https/0.3' },
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

  /** The database as the duplicate-record store sees it: every call fails while the claim-store fault is on. */
  private faultableDb(): SqliteDataSource {
    const real = this.db;
    return new Proxy(real, {
      get: (target, prop) => {
        const value = Reflect.get(target, prop, target) as unknown;
        if (typeof value !== 'function') return value;
        if (prop === 'all' || prop === 'get' || prop === 'run' || prop === 'transaction') {
          return (...a: unknown[]) => {
            if (this.claimStoreUnreadable) return Promise.reject(new Error('conformance fault: duplicate record unreadable'));
            return (value as (...x: unknown[]) => unknown).apply(target, a);
          };
        }
        return (value as (...x: unknown[]) => unknown).bind(target);
      },
    });
  }

  async trigger(action: string, args: Record<string, unknown>): Promise<{ documents: string[] }> {
    if (action === 'fault') {
      if (args.claimStore !== 'unreadable' && args.claimStore !== 'ok') throw new Error('fault.claimStore must be unreadable or ok');
      this.claimStoreUnreadable = args.claimStore === 'unreadable';
      return { documents: [] };
    }
    if (action === 'twoPhase') {
      this.faults.arm(parseTwoPhase(args));
      return { documents: [] };
    }
    if (action === 'ceremonyDeadline') {
      const sec = args.seconds;
      if (typeof sec !== 'number' || !Number.isInteger(sec) || sec < 1) throw new Error('ceremonyDeadline seconds must be a positive whole number');
      this.ceremony.setTtlMs(sec * 1000);
      return { documents: [] };
    }
    if (action === 'ceremonyEffect') {
      this.ceremonyPlan.arm(parseCeremonyEffect(args));
      return { documents: [] };
    }
    if (action === 'settle' && this.pendingCeremony !== undefined) {
      // The effect's outcome was unknown (the ceremony stayed pending): the outcome is now known, and the approval that reached the
      // quorum is processed again (a repeated approval retries the effect), so the reply is the stack's own answer to it.
      if (args.outcome !== 'commit' && args.outcome !== 'abort') throw new Error('settle outcome must be commit or abort');
      const again = this.pendingCeremony;
      this.pendingCeremony = undefined;
      this.ceremonyPlan.arm(args.outcome === 'commit' ? { outcome: 'commit' } : { outcome: 'fail', reason: parseReason(args) ?? 'storeFailed' });
      return { documents: (await this.deliver(again)).replies };
    }
    if (action === 'settle') {
      if (args.outcome !== 'commit' && args.outcome !== 'abort') throw new Error('settle outcome must be commit or abort');
      const pending = this.pendingSend;
      if (pending === undefined || !this.faults.isParked) throw new Error('no transaction is waiting to be settled');
      this.pendingSend = undefined;
      this.faults.release(args.outcome === 'commit' ? 'yes' : 'no', args.outcome === 'abort' ? parseReason(args) : undefined);
      return { documents: (await pending).replies };
    }
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
    // Helper actions of the 3b-DTG groups (suite docs/04 section 4.4): the JSON value travels in documents[0].
    if (action === 'enrolExecutor' && this.options.dtg !== false) {
      if (typeof args.vid !== 'string' || args.vid === '') throw new Error('enrolExecutor needs a vid');
      this.enrolledExecutors.add(args.vid);
      return { documents: [] };
    }
    if (action === 'consentBinding' && this.options.dtg !== false && this.options.ceremony !== false) {
      if (typeof args.thread !== 'string' || args.thread === '') throw new Error('consentBinding needs a thread');
      const held = await this.ceremony.store.getProposal(args.thread);
      if (held === null) throw new Error(`no held consent for thread ${args.thread}`);
      const { challenge, payloadDigest } = consentBinding(held);
      return { documents: [JSON.stringify({ challenge, payloadDigest })] };
    }
    if (action === 'presentationNonce' && this.options.dtg !== false) {
      // The verifier opens the thread and names the nonce: the nonce IS the thread (single use; credential-exchange/present).
      const nonce = `nonce-${randomBytes(16).toString('hex')}`;
      return { documents: [JSON.stringify({ nonce, threadId: nonce })] };
    }
    throw new Error(`unknown trigger ${action}`);
  }

  /** A new process over the same files: the databases are closed and reopened, every service rebuilt. */
  async restart(): Promise<void> {
    await this.closeDbs();
    await this.build(false);
  }
  async reset(): Promise<void> {
    const waiting = this.pendingSend;
    this.pendingSend = undefined;
    this.faults.clear();
    this.pendingCeremony = undefined;
    await waiting?.catch(() => undefined);
    const old = [this.dbPath, this.txPath];
    await this.closeDbs();
    this.counter = 0;
    this.nowMs = undefined;
    this.consentPrompts.length = 0;
    this.enrolledExecutors.clear();
    this.policy = { propose: 'hold', witnessed: false };
    this.claimStoreUnreadable = false;
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
  /** Communities established by a met ceremony quorum. */
  async communityCount(): Promise<number> {
    return this.count('SELECT COUNT(*) AS n FROM conformance_communities');
  }
  private async handledCount(): Promise<number> {
    const accepted = await this.count("SELECT COUNT(*) AS n FROM vrc_exchange_relationship_dids WHERE role = 'acceptor' AND state IN ('accepted','received','issued-by-me')");
    return accepted + (await this.storedCount()) + (await this.widgetCount()) + (await this.communityCount()) + this.consentPrompts.length;
  }

  async observe(q: ObserveQuery): Promise<ObserveResult> {
    if (q.query === 'handled') return { value: await this.handledCount() };
    if (q.query === 'retained') {
      // The boundary's append-only record: the request exactly as delivered, the reply exactly as sent ('' when there is none).
      const doc = q.side === 'request' ? await this.retained.byId(q.id) : await this.retained.replyTo(q.id);
      return { value: doc?.verbatim ?? '' };
    }
    if (q.query === 'stored') {
      if (q.kind === 'vrc') return { value: await this.storedCount() };
      if (q.kind === 'vwc') return { value: await this.witnessCount() };
      if (q.kind === 'credential') {
        // Credentials kept from credential-exchange/issue: every stored credential that is not a VRC (digest selects one).
        return { value: q.digest === undefined ? await this.count("SELECT COUNT(*) AS n FROM credentials WHERE vc_type <> 'vrc'") : Number((await this.db.get<{ n: number | string }>("SELECT COUNT(*) AS n FROM credentials WHERE vc_type <> 'vrc' AND credential_digest = ?", q.digest))!.n) };
      }
      if (q.kind === 'presentation') return { value: await this.count('SELECT COUNT(*) AS n FROM credential_presentations') };
      if (q.kind === 'ceremony-effect') return { value: await this.communityCount() };
      return { value: await this.handledCount() };
    }
    // A document whose effect outcome is unknown was answered with a retryable indeterminate and its claim released, but it is not
    // finished: it is accepted until `settle` resolves it (lifecycle: unknown is never reported as responded or errored).
    if (this.pendingCeremony !== undefined && documentId(this.pendingCeremony.bytes) === String(q.id)) return { value: 'accepted' };
    const row = await exchangeDids.findByExchangeId(this.db, String(q.id));
    if (row !== null) {
      if (row.state === 'held') return { value: 'accepted' };
      if (row.state === 'declined' || row.state === 'expired') return { value: 'errored' };
      return { value: 'responded' };
    }
    const ceremony = await this.ceremony.store.getProposal(String(q.id));
    if (ceremony !== null) return { value: ceremony.status === 'pending' ? 'accepted' : ceremony.status === 'crystallized' ? 'responded' : 'errored' };
    const claim = await this.guard.find(String(q.id));
    if (claim !== null) {
      if (claim.state !== 'completed') return { value: 'accepted' };
      // A completed document ends responded, or errored when the retained answer is an error document.
      let type: unknown;
      try {
        type = (JSON.parse(claim.response ?? 'null') as { type?: unknown } | null)?.type;
      } catch {
        type = undefined;
      }
      return { value: typeof type === 'string' && type.startsWith('https://trusttasks.org/spec/trust-task-error/') ? 'errored' : 'responded' };
    }
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
      ceremonies: await this.txDb.all('SELECT proposal_id, status FROM ceremony_proposals ORDER BY proposal_id'),
      approvals: await this.txDb.all('SELECT proposal_id, approver_did FROM ceremony_approvals ORDER BY proposal_id, approver_did'),
      communities: await this.communityCount(),
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
    const parked = this.faults.parkSignal();
    const work = this.deliver(params);
    const first = await Promise.race([work, parked]);
    if (first === 'parked') {
      // The transaction is prepared and waiting (`twoPhase inflight|unknown`): nothing comes back yet. `settle` collects the answer.
      this.pendingSend = work;
      work.catch(() => undefined);
      return { replies: [], transport: { kind: 'none' }, quiescentAfterMs: 0 };
    }
    // `twoPhase commit` with `deliver: false`: the transaction committed and the reply was lost on the way back.
    if (this.faults.takeDroppedReply()) return { replies: [], transport: { kind: 'none' }, quiescentAfterMs: 0 };
    return first;
  }

  private async deliver(params: SendParams): Promise<SendResult> {
    if (params.http !== undefined && this.options.https !== false) return this.http.send(params.from, params.bytes, params.http);
    const result = await this.pipeline.process({ raw: params.bytes, sender: params.from.kind === 'none' ? undefined : params.from.vid });
    if (this.ceremonyPlan.unknownHit) {
      // The effect's outcome was unknown: the answer was a retryable indeterminate; `settle` processes this document again.
      this.ceremonyPlan.unknownHit = false;
      this.pendingCeremony = params;
    }
    const replies = result.document === undefined ? [] : [JSON.stringify(result.document)];
    return { replies, transport: { status: result.status, kind: replies.length === 0 ? ('none' as const) : ('document' as const) }, quiescentAfterMs: 0 };
  }
}
