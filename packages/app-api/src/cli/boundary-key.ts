// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Operator CLI for an agent's dedicated `#key-boundary` key (gate G2), a thin wrapper over the
 * `ScidVhAgent` operations. did:scid:vh agents only (a did:peer:4 agent cannot gain the key in place).
 *
 *   node --conditions=development --experimental-strip-types boundary-key.ts <command> --agent NAME [--generation N] [--execute]
 *
 *   provision --generation N   generate generation N into the agent's encrypted keystore (never overwrites)
 *   publish   --generation N   first publication of #key-boundary in the agent's DID document
 *   rotate    --generation N   replace the published key with a NEW generation N
 *   retire                     remove #key-boundary (retirement, cutover rollback)
 *   destroy   --generation N   delete the stored secret of a generation the document does not publish
 *   status                     what is published and which generations are held (read-only)
 *
 * Mutating commands are a DRY RUN unless `--execute` is given: the log entry is built and chain-validated
 * and nothing is stored, pushed or provisioned. The agent passphrase is read ONLY from
 * P2PTS_AGENT_PASSPHRASE (never from an argument); without it every command refuses. The agent is started
 * for the operation only with the Trust Task listener forced off, and stopped afterwards. Output carries
 * generations, fingerprints (a hash prefix of the public key), versions and notes: never a key, seed or
 * passphrase. Exit status 0 on success, 1 on any refusal. No network or UI route exists for these operations.
 *
 * Environment: P2PTS_AGENT_PASSPHRASE (required), P2PTS_HOME (agent registry location).
 */
import { fileURLToPath } from 'node:url';
import { BOUNDARY_VM_ID } from '@p2p-trust-stack/core/did/document-carry-forward.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { boundaryKeyFingerprint, loadBoundaryKey, BoundaryKeyError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import { encodeEd25519Multikey } from '@p2p-trust-stack/core/did/create.js';
import { AgentRegistry, defaultRegistry } from '../runtime/agent-registry.js';
import { ScidVhAgent } from '../runtime/scid-vh-agent.js';

export type AgentBoundaryCommand = 'provision' | 'publish' | 'rotate' | 'retire' | 'destroy' | 'status';
const COMMANDS: readonly AgentBoundaryCommand[] = ['provision', 'publish', 'rotate', 'retire', 'destroy', 'status'];
const NEEDS_GENERATION = new Set<AgentBoundaryCommand>(['provision', 'publish', 'rotate', 'destroy']);
const USAGE = `usage: boundary-key <${COMMANDS.join('|')}> --agent NAME [--generation N] [--execute]\n(mutating commands are a dry run without --execute; the passphrase comes from P2PTS_AGENT_PASSPHRASE)`;

export interface AgentArgs { command: AgentBoundaryCommand; agent: string; generation?: number; execute: boolean }

export function parseAgentArgs(argv: readonly string[]): AgentArgs {
  const [command, ...rest] = argv;
  if (command === undefined || !(COMMANDS as readonly string[]).includes(command)) throw new Error(`unknown or missing command\n${USAGE}`);
  let generation: number | undefined;
  let agent: string | undefined;
  let execute = false;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === '--execute') execute = true;
    else if (a === '--agent') {
      agent = rest[++i];
      if (agent === undefined || agent === '' || agent.startsWith('--')) throw new Error('--agent needs a name');
    } else if (a === '--generation') {
      const v = rest[++i];
      if (v === undefined || !/^[1-9][0-9]*$/.test(v)) throw new Error('--generation needs a positive integer');
      generation = Number(v);
    } else throw new Error(`unknown argument ${a}\n${USAGE}`);
  }
  const cmd = command as AgentBoundaryCommand;
  if (agent === undefined) throw new Error(`--agent NAME is required\n${USAGE}`);
  if (NEEDS_GENERATION.has(cmd) && generation === undefined) throw new Error(`${cmd} needs --generation N`);
  if (!NEEDS_GENERATION.has(cmd) && generation !== undefined) throw new Error(`${cmd} takes no --generation`);
  return { command: cmd, agent, ...(generation === undefined ? {} : { generation }), execute };
}

/** The multibase key published at `#key-boundary`, or null. */
function publishedOf(doc: { verificationMethod: Array<{ id: string; publicKeyMultibase: string }> }): string | null {
  return doc.verificationMethod.find((v) => v.id === BOUNDARY_VM_ID)?.publicKeyMultibase ?? null;
}
const isPublished = (published: string | null, publicKey: Uint8Array): boolean => published !== null && published === encodeEd25519Multikey(publicKey);

export interface AgentCliDeps { registry?: AgentRegistry }

export async function runAgentCli(argv: readonly string[], env: Readonly<Record<string, string | undefined>>, out: (l: string) => void, err: (l: string) => void, deps: AgentCliDeps = {}): Promise<number> {
  let args: AgentArgs;
  try {
    args = parseAgentArgs(argv);
  } catch (e) {
    err((e as Error).message);
    return 1;
  }
  const passphrase = (env.P2PTS_AGENT_PASSPHRASE ?? '').trim();
  if (passphrase === '') {
    err('refused: P2PTS_AGENT_PASSPHRASE is required; there is no default passphrase');
    return 1;
  }
  const registry = deps.registry ?? defaultRegistry;
  let agent: ScidVhAgent | undefined;
  let started = false;
  try {
    if (!registry.agentExists(args.agent)) throw new Error(`agent "${args.agent}" not found`);
    // The listener must stay off for an operator run, whatever the environment says.
    delete process.env.TRUST_TASKS_LISTENER;
    agent = await ScidVhAgent.unlock({ name: args.agent, passphrase, trustTasksListener: { enabled: false } }, registry);
    const did = agent.getDid();
    const keystorePath = registry.getKeystorePath(args.agent);
    const withKeystore = async <T>(fn: (ks: SqliteKeyStore) => Promise<T> | T): Promise<T> => {
      const ks = new SqliteKeyStore(keystorePath);
      try { return await fn(ks); } finally { ks.close(); }
    };
    const held = (generation: number) => withKeystore((ks) => loadBoundaryKey({ store: ks, vid: did, passphrase, generation }));
    const heldGenerations = async (): Promise<number[]> => {
      const gens: number[] = [];
      for (let g = 1; g <= 16; g++) {
        try { await held(g); gens.push(g); } catch (e) { if (!(e instanceof BoundaryKeyError && e.code === 'missing')) throw e; }
      }
      return gens;
    };
    const needLog = async () => {
      await agent!.start();
      started = true;
      const log = agent!.listRotationLog();
      if (log.length === 0) throw new Error('the agent has no rotation log (not a did:scid:vh agent)');
      return log[log.length - 1]!.didDocument;
    };
    const base = { command: args.command, agent: args.agent, did, executed: args.execute } as const;
    const gen = args.generation;
    let result: Record<string, unknown>;

    if (args.command === 'status') {
      const doc = await needLog();
      const pub = publishedOf(doc);
      const gens = await heldGenerations();
      let publishedGeneration: number | null = null;
      let publishedFingerprint: string | null = null;
      for (const g of gens) {
        const pair = await held(g);
        if (isPublished(pub, pair.publicKey)) { publishedGeneration = g; publishedFingerprint = boundaryKeyFingerprint(pair.publicKey); }
      }
      result = { ...base, executed: false, published: pub === null ? null : { generation: publishedGeneration, fingerprint: publishedFingerprint }, generationsHeld: gens, note: pub === null ? 'no #key-boundary published' : publishedGeneration === null ? '#key-boundary published, but no held generation matches it' : '#key-boundary published' };
    } else if (args.command === 'provision') {
      if (args.execute) {
        const out1 = await agent.provisionBoundaryKey(gen!);
        result = { ...base, generation: gen, fingerprint: out1.fingerprint, note: 'provisioned; publish it next' };
      } else {
        try { await held(gen!); } catch (e) {
          if (e instanceof BoundaryKeyError && e.code === 'missing') { out(JSON.stringify({ ...base, generation: gen, note: `dry run: generation ${gen} is absent and would be provisioned (nothing written)` })); return 0; }
          throw e;
        }
        throw new BoundaryKeyError('exists', `generation ${gen} already exists for ${did}; it is never overwritten`);
      }
    } else if (args.command === 'publish' || args.command === 'rotate') {
      const doc = await needLog();
      const pub = publishedOf(doc);
      const pair = await held(gen!);
      if (args.command === 'publish' && pub !== null) throw new BoundaryKeyError('exists', `${BOUNDARY_VM_ID} is already published; use rotate to replace it`);
      if (args.command === 'rotate' && pub === null) throw new BoundaryKeyError('notPublished', `${BOUNDARY_VM_ID} is not published yet; use publish for the first publication`);
      if (isPublished(pub, pair.publicKey)) throw new BoundaryKeyError('exists', `generation ${gen} is already the published key; a generation is never re-published`);
      const entry = await agent.publishBoundaryKey(gen!, { dryRun: !args.execute });
      const next = args.command === 'rotate' ? `; the log is pushed to the utility server when the agent next runs connected (confirm through the resolver); then set BOUNDARY_KEY_GENERATION=${gen} and restart` : '; the log is pushed to the utility server when the agent next runs connected (confirm through the resolver); after propagation set TRUST_TASKS_BOUNDARY_KEY=dedicated and BOUNDARY_KEY_CUTOVER_AT, then restart';
      result = { ...base, generation: gen, fingerprint: boundaryKeyFingerprint(pair.publicKey), version: entry.version, note: args.execute ? `published${next}` : 'dry run: entry built and validated, nothing written or pushed' };
    } else if (args.command === 'retire') {
      const doc = await needLog();
      if (publishedOf(doc) === null) throw new BoundaryKeyError('notPublished', `${BOUNDARY_VM_ID} is not published; nothing to retire`);
      const entry = await agent.retireBoundaryKey({ dryRun: !args.execute });
      result = { ...base, version: entry.version, note: args.execute ? 'retired: #key-boundary removed from the document; the log is pushed to the utility server when the agent next runs connected' : 'dry run: would remove #key-boundary (nothing written)' };
    } else {
      const doc = await needLog();
      const pub = publishedOf(doc);
      const pair = await held(gen!);
      if (isPublished(pub, pair.publicKey)) throw new BoundaryKeyError('exists', `generation ${gen} is the key the document publishes; retire or rotate first`);
      if (args.execute) agent.destroyBoundaryKeySecret(gen!);
      result = { ...base, generation: gen, fingerprint: boundaryKeyFingerprint(pair.publicKey), note: args.execute ? 'secret destroyed' : 'dry run: would destroy the stored secret (nothing written)' };
    }
    out(JSON.stringify(result));
    return 0;
  } catch (e) {
    err(`refused: ${(e as Error).message}`);
    return 1;
  } finally {
    if (agent !== undefined && started) await agent.stop();
  }
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  runAgentCli(process.argv.slice(2), process.env, (l) => console.log(l), (l) => console.error(l)).then((code) => process.exit(code));
}
