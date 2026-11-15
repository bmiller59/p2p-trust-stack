// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers


/**
 * Custody of the dedicated `#key-boundary` signing key (gate G2).
 *
 * Storage is the stack's existing encrypted key store (`KeyStore`: Argon2id + AES-256-GCM under the
 * process passphrase, the same encryption the per-exchange relationship DID keys use). A generation
 * `N` of the key lives under the key type `boundary-ed25519-gN` for the identifier's own VID, so a
 * rotation provisions generation N+1 beside N and the process selects one with
 * `BOUNDARY_KEY_GENERATION`. No new secret store, no derived key, no plaintext copy.
 *
 * FAIL CLOSED. When the dedicated mode is on, a key that is missing, cannot be decrypted, is
 * damaged, or is not the key the identifier's document publishes at `#key-boundary` is an error
 * (`BoundaryKeyError`), never a silent fallback to `#key-1`. When the mode is off nothing here runs
 * and the process is exactly the pre-G2 process.
 *
 * Nothing in this file logs, and no error message or fingerprint carries secret material: errors name
 * the identifier, the generation and the reason; the fingerprint is a hash prefix of the PUBLIC key.
 */
import { generateEd25519KeyPairFromSeed, sha256 } from '../../../../crypto/primitives.js';
import type { DidDocument } from '../../../../did/types.js';
import type { KeyStore, RawKeyPair } from '../../../../keystore/types.js';
import { randomBytes } from 'node:crypto';
import { resolveBoundaryKeyConfig } from './key-config.js';
import type { BoundaryKeyConfig } from './key-config.js';
import { installBoundarySigner } from './install.js';
import { getBoundarySigner, setBoundarySigner } from './signer.js';

export type BoundaryKeyErrorCode = 'config' | 'missing' | 'corrupt' | 'exists' | 'notPublished' | 'mismatch';

export class BoundaryKeyError extends Error {
  readonly code: BoundaryKeyErrorCode;
  constructor(code: BoundaryKeyErrorCode, message: string) {
    super(`dedicated boundary key (${code}): ${message}`);
    this.name = 'BoundaryKeyError';
    this.code = code;
  }
}

/** A key store that can also remove an entry (the SQLite key store can). */
export type BoundaryKeyStore = KeyStore & { deleteKeyPair?(vid: string, keyType: string): boolean };

export const boundaryKeyType = (generation: number): string => `boundary-ed25519-g${generation}`;

function assertGeneration(generation: number): void {
  if (!Number.isInteger(generation) || generation < 1) throw new BoundaryKeyError('config', `generation must be a positive integer, got ${String(generation)}`);
}

/** A short hash of the PUBLIC key for logs and the runbook: identifies a key without being secret. */
export function boundaryKeyFingerprint(publicKey: Uint8Array): string {
  return Buffer.from(sha256(publicKey)).subarray(0, 8).toString('hex');
}

export interface BoundaryProcessKeyConfig {
  config: BoundaryKeyConfig;
  generation: number;
}

/**
 * The process-level reading of the gate. Unlike `resolveBoundaryKeyConfig` (which downgrades a bad
 * setting to `#key-1` and returns a `problem`), a process that was ASKED for the dedicated mode and
 * got a bad setting refuses: a typo must not leave it on `#key-1` while the operator believes the
 * dedicated key is live. Unset or `key-1` is the default and never throws.
 */
export function resolveBoundaryProcessKeyConfig(env: Readonly<Record<string, string | undefined>>): BoundaryProcessKeyConfig {
  const { config, problem } = resolveBoundaryKeyConfig(env);
  if (problem !== undefined) throw new BoundaryKeyError('config', problem.replace(/; using #key-1$/, ''));
  if (config.mode === 'key-1') return { config, generation: 1 };
  const raw = env.BOUNDARY_KEY_GENERATION?.trim();
  const generation = raw === undefined || raw === '' ? 1 : Number(raw);
  assertGeneration(generation);
  return { config, generation };
}

/** Generate a fresh random key (not derived from any other key) and store it encrypted. Refuses to overwrite. */
export async function provisionBoundaryKey(options: { store: BoundaryKeyStore; vid: string; passphrase: string; generation: number }): Promise<{ publicKey: Uint8Array; fingerprint: string }> {
  assertGeneration(options.generation);
  if (typeof options.passphrase !== 'string' || options.passphrase.length === 0) {
    throw new BoundaryKeyError('config', 'a key passphrase is required (no default is applied)');
  }
  const type = boundaryKeyType(options.generation);
  let present = true;
  try {
    await options.store.retrieveKeyPairAsync(options.vid, type, options.passphrase);
  } catch (err) {
    present = !/no key found/.test((err as Error).message);
  }
  if (present) throw new BoundaryKeyError('exists', `generation ${options.generation} already exists for ${options.vid}; it is never overwritten`);
  const pair = generateEd25519KeyPairFromSeed(new Uint8Array(randomBytes(32)));
  await options.store.storeKeyPairAsync(options.vid, type, pair, options.passphrase);
  return { publicKey: pair.publicKey, fingerprint: boundaryKeyFingerprint(pair.publicKey) };
}

/** Load a generation. Throws `BoundaryKeyError` (`missing`, `corrupt`, `mismatch`); never returns a substitute. */
export async function loadBoundaryKey(options: { store: BoundaryKeyStore; vid: string; passphrase: string; generation: number }): Promise<RawKeyPair> {
  assertGeneration(options.generation);
  if (typeof options.passphrase !== 'string' || options.passphrase.length === 0) {
    throw new BoundaryKeyError('config', 'a key passphrase is required (no default is applied)');
  }
  let pair: RawKeyPair;
  try {
    pair = await options.store.retrieveKeyPairAsync(options.vid, boundaryKeyType(options.generation), options.passphrase);
  } catch (err) {
    if (/no key found/.test((err as Error).message)) {
      throw new BoundaryKeyError('missing', `no key for generation ${options.generation} of ${options.vid}; provision it (see the boundary key runbook)`);
    }
    throw new BoundaryKeyError('corrupt', `generation ${options.generation} of ${options.vid} could not be decrypted (wrong passphrase or damaged record)`);
  }
  if (pair.secretKey.length !== 32 || pair.publicKey.length !== 32) {
    throw new BoundaryKeyError('corrupt', `generation ${options.generation} of ${options.vid} has a malformed key record`);
  }
  const derived = generateEd25519KeyPairFromSeed(pair.secretKey).publicKey;
  if (Buffer.compare(Buffer.from(derived), Buffer.from(pair.publicKey)) !== 0) {
    throw new BoundaryKeyError('corrupt', `generation ${options.generation} of ${options.vid}: the stored public key does not belong to the stored secret`);
  }
  return pair;
}

/** Delete the secret of a generation (retirement, after the document no longer lists it). Returns whether one existed. */
export function destroyBoundaryKey(options: { store: BoundaryKeyStore; vid: string; generation: number }): boolean {
  assertGeneration(options.generation);
  if (options.store.deleteKeyPair === undefined) throw new BoundaryKeyError('config', 'the key store cannot delete entries');
  return options.store.deleteKeyPair(options.vid, boundaryKeyType(options.generation));
}

export interface ProcessSignerOptions {
  env: Readonly<Record<string, string | undefined>>;
  did: string;
  didDocument: DidDocument | undefined;
  /** The `#key-1` pair, read at every signature. */
  keys: () => RawKeyPair;
  /** Where the dedicated key lives and the passphrase protecting it; only touched when the dedicated mode is on. */
  custody?: { store: BoundaryKeyStore; passphrase: string };
}

export type ProcessSignerResult =
  | { mode: 'key-1'; installed: boolean; reason?: string }
  | { mode: 'dedicated'; installed: true; generation: number; fingerprint: string; cutoverAtMs: number };

/**
 * Install the process's boundary signer. Mode `key-1` (the default) is exactly `installBoundarySigner`
 * without the dedicated option. Mode `dedicated` loads the key, requires the identifier's own document
 * to publish it, and either installs the cutover signer or throws: on any failure NO signer is left
 * installed (a previously installed `#key-1` signer is removed) so nothing can be signed under the
 * wrong key.
 */
export async function installProcessBoundarySigner(options: ProcessSignerOptions): Promise<ProcessSignerResult> {
  const { config, generation } = resolveBoundaryProcessKeyConfig(options.env);
  if (config.mode === 'key-1') {
    const r = installBoundarySigner({ did: options.did, didDocument: options.didDocument, keys: options.keys });
    return r.reason === undefined ? { mode: 'key-1', installed: r.installed } : { mode: 'key-1', installed: r.installed, reason: r.reason };
  }
  setBoundarySigner(undefined);
  if (options.custody === undefined) throw new BoundaryKeyError('config', 'no key store or passphrase is available to the process');
  const pair = await loadBoundaryKey({ store: options.custody.store, vid: options.did, passphrase: options.custody.passphrase, generation });
  const r = installBoundarySigner({
    did: options.did,
    didDocument: options.didDocument,
    keys: options.keys,
    dedicated: { keys: () => pair, cutoverAtMs: config.cutoverAtMs },
  });
  if (!r.installed || r.key !== 'dedicated') {
    setBoundarySigner(undefined);
    throw new BoundaryKeyError('notPublished', `${r.reason ?? 'the dedicated signer was not installed'} (generation ${generation}); publish the key first or turn the dedicated mode off`);
  }
  if (getBoundarySigner() === undefined) throw new BoundaryKeyError('notPublished', 'the signer was not installed');
  return { mode: 'dedicated', installed: true, generation, fingerprint: boundaryKeyFingerprint(pair.publicKey), cutoverAtMs: config.cutoverAtMs };
}
