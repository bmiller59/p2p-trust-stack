// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * DID key resolution for the document verifier (conformance plan P4, sections 3.2 and 3.3).
 *
 * The verifier needs, for a DID, the set of keys with the verification relationships that list
 * each. Three methods are served:
 *
 *  - `did:key` (Ed25519): offline, the key is in the identifier. One method, listed for every
 *    signing relationship (as DID Core's did:key derivation does); used by the suite's reference
 *    signer and the registry proof fixtures.
 *  - `did:peer:4`: offline, the document is embedded in the identifier (core `DidResolver`).
 *  - `did:scid:vh`: needs the rotation log. The core `DidResolver` replays and validates it from a
 *    `RotationLogSource`; the source is bounded here (timeout, size cap, cache, rate limit).
 *
 * Failure rules. A resolution that could not be completed (log not held, source down, over the
 * rate limit, a result flagged as coming from a cache with no validated log) is
 * `ResolutionUnavailable`: the verifier answers `unavailable` (retryable), never `proofInvalid`.
 * A DID of a method we do not serve, or one that is malformed, is a definite `null`.
 *
 * Time. `resolve(did, atMs)` carries the instant a key set is wanted for (`proof.created`). The
 * resolvers in this file answer the LATEST key set (`keySetAt: 'latest'`); `time-pinned.ts`
 * (`TimePinnedKeyResolver`) answers the key set in force at `atMs` from the validated rotation log,
 * which the dedicated-key cutover (gate G2) needs. Neither ever uses a cache-sourced result.
 */
import { base58btc } from 'multiformats/bases/base58';
import { DidResolver } from '../../../../did/did-resolver.js';
import type { RotationLogSource } from '../../../../did/rotation-log-source.js';
import type { RotationLogEntry } from '../../../../did/rotation-types.js';
import type { DidDocument } from '../../../../did/types.js';

export type KeySource = 'offline' | 'log' | 'local';

export interface ResolvedKey {
  /** The fragment without `#` (for example `key-1`). */
  readonly fragment: string;
  /** Raw 32-byte Ed25519 public key. */
  readonly publicKey: Uint8Array;
  /** Verification relationships that list this key (`authentication`, `assertionMethod`, `keyAgreement`). */
  readonly relationships: readonly string[];
}

export interface ResolvedKeySet {
  readonly did: string;
  readonly source: KeySource;
  /**
   * `latest`: the newest validated document (no time pin). `created`: the document of the log entry
   * in force at the requested instant (`TimePinnedKeyResolver`, gate G2).
   */
  readonly keySetAt: 'latest' | 'created';
  /** `created` only: the log version whose document this key set is. */
  readonly version?: number;
  readonly keys: readonly ResolvedKey[];
}

/** The resolution could not be completed: not a verdict on the proof. */
export class ResolutionUnavailable extends Error {
  readonly retryAfterSeconds: number | undefined;
  constructor(message: string, retryAfterSeconds?: number) {
    super(message);
    this.name = 'ResolutionUnavailable';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export interface KeyResolver {
  /** The key set of a DID; null when the DID is of a method not served or is malformed. May throw `ResolutionUnavailable`. */
  resolve(did: string, atMs?: number): Promise<ResolvedKeySet | null>;
}

// ---------------------------------------------------------------------------
// did:key (Ed25519)
// ---------------------------------------------------------------------------

/** The raw key of an Ed25519 did:key identifier (`did:key:z6Mk...`), or null. */
export function ed25519FromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith('did:key:z')) return null;
  try {
    const raw = base58btc.decode(did.slice('did:key:'.length));
    if (raw.length === 34 && raw[0] === 0xed && raw[1] === 0x01) return raw.slice(2);
  } catch {
    /* not decodable */
  }
  return null;
}

export function didKeyFromEd25519(publicKey: Uint8Array): string {
  const raw = new Uint8Array(34);
  raw.set([0xed, 0x01], 0);
  raw.set(publicKey, 2);
  return `did:key:${base58btc.encode(raw)}`;
}

export class DidKeyResolver implements KeyResolver {
  async resolve(did: string): Promise<ResolvedKeySet | null> {
    const key = ed25519FromDidKey(did);
    if (key === null) return null;
    return {
      did,
      source: 'offline',
      keySetAt: 'latest',
      keys: [{ fragment: did.slice('did:key:'.length), publicKey: key, relationships: ['authentication', 'assertionMethod'] }],
    };
  }
}

// ---------------------------------------------------------------------------
// did:peer:4 and did:scid:vh through the core DidResolver
// ---------------------------------------------------------------------------

export function keysOfDocument(did: string, doc: DidDocument, source: KeySource): ResolvedKeySet {
  const rel = (list: readonly string[] | undefined): Set<string> => new Set((list ?? []).map((r) => (r.startsWith('#') ? r.slice(1) : r)));
  const authentication = rel(doc.authentication);
  const assertionMethod = rel(doc.assertionMethod);
  const keyAgreement = rel(doc.keyAgreement);
  const keys: ResolvedKey[] = [];
  for (const vm of doc.verificationMethod ?? []) {
    const fragment = vm.id.includes('#') ? vm.id.slice(vm.id.indexOf('#') + 1) : vm.id;
    let raw: Uint8Array;
    try {
      raw = base58btc.decode(vm.publicKeyMultibase);
    } catch {
      continue;
    }
    // Only Ed25519 (multicodec 0xed01) can verify an eddsa-jcs-2022 proof; X25519 keys and post-quantum keys are not signers here.
    if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) continue;
    const relationships: string[] = [];
    if (authentication.has(fragment)) relationships.push('authentication');
    if (assertionMethod.has(fragment)) relationships.push('assertionMethod');
    if (keyAgreement.has(fragment)) relationships.push('keyAgreement');
    keys.push({ fragment, publicKey: raw.slice(2), relationships });
  }
  return { did, source, keySetAt: 'latest', keys };
}

/**
 * Resolves `did:peer:4` (offline) and `did:scid:vh` (from a rotation-log source) through the core
 * `DidResolver`. The resolver itself never labels a result as cache-sourced (it replays a log or
 * finds none); a source that can fall back to an unvalidated snapshot must throw rather than
 * return it, and `refuseCachedResolution` below is the guard for resolvers that report a source.
 */
export class DidResolverKeyResolver implements KeyResolver {
  private readonly resolver: DidResolver;
  constructor(resolver: DidResolver) {
    this.resolver = resolver;
  }

  async resolve(did: string): Promise<ResolvedKeySet | null> {
    if (!did.startsWith('did:peer:4') && !did.startsWith('did:scid:vh')) return null;
    let result;
    try {
      result = await this.resolver.resolve(did);
    } catch (err) {
      if (err instanceof ResolutionUnavailable) throw err;
      throw new ResolutionUnavailable(`resolution failed: ${(err as Error)?.message ?? 'unknown'}`);
    }
    const error = result.didResolutionMetadata.error;
    if (result.didDocument === null) {
      if (error === 'invalidDid' || error === 'methodNotSupported') return null;
      throw new ResolutionUnavailable(`could not resolve (${error ?? 'no document'})`);
    }
    return keysOfDocument(did, result.didDocument, did.startsWith('did:peer:4') ? 'offline' : 'log');
  }
}

/**
 * Adapts a resolver that reports where the document came from (the server's `DidResolutionService`:
 * `log`, `cache`, `offline`) and REFUSES a `cache` result: a snapshot with no validated rotation
 * log is an unvalidated key set and must never verify a proof.
 */
export interface SourcedResolution {
  source: 'log' | 'cache' | 'offline' | 'none';
  didDocument: DidDocument | null;
  error?: string | undefined;
}

export class SourcedKeyResolver implements KeyResolver {
  private readonly fn: (did: string) => Promise<SourcedResolution>;
  constructor(fn: (did: string) => Promise<SourcedResolution>) {
    this.fn = fn;
  }

  async resolve(did: string): Promise<ResolvedKeySet | null> {
    if (!did.startsWith('did:peer:4') && !did.startsWith('did:scid:vh')) return null;
    let r: SourcedResolution;
    try {
      r = await this.fn(did);
    } catch (err) {
      if (err instanceof ResolutionUnavailable) throw err;
      throw new ResolutionUnavailable(`resolution failed: ${(err as Error)?.message ?? 'unknown'}`);
    }
    if (r.source === 'cache') throw new ResolutionUnavailable('only a cached, unvalidated document is held');
    if (r.didDocument === null) {
      if (r.error === 'invalidDid' || r.error === 'methodNotSupported') return null;
      throw new ResolutionUnavailable(`could not resolve (${r.error ?? 'no document'})`);
    }
    return keysOfDocument(did, r.didDocument, r.source === 'offline' ? 'offline' : 'log');
  }
}

/** Serves several methods: the first resolver that knows the method answers. */
export class CompositeKeyResolver implements KeyResolver {
  private readonly resolvers: readonly KeyResolver[];
  constructor(resolvers: readonly KeyResolver[]) {
    this.resolvers = resolvers;
  }
  async resolve(did: string, atMs?: number): Promise<ResolvedKeySet | null> {
    for (const r of this.resolvers) {
      const got = await r.resolve(did, atMs);
      if (got !== null) return got;
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Bounds: rate limit, cache, timeout and size cap on remote log sources
// ---------------------------------------------------------------------------

export interface RateLimitOptions {
  /** Resolutions of one DID allowed per window. Default 6. */
  perKey?: number;
  /** Resolutions of any DID allowed per window. Default 60. */
  global?: number;
  /** Window length, ms. Default 60000. */
  windowMs?: number;
  now?: () => number;
}

/**
 * Fixed-window limiter consulted BEFORE any remote resolution, so an unauthenticated sender naming
 * arbitrary DIDs cannot turn the verifier into a fetch amplifier. The global bucket bounds the
 * damage of many distinct DIDs; the per-key bucket bounds repeats of one.
 */
export class ResolutionRateLimiter {
  private readonly perKey: number;
  private readonly global: number;
  private readonly windowMs: number;
  private readonly now: () => number;
  private windowStart = 0;
  private total = 0;
  private readonly keys = new Map<string, number>();

  constructor(options: RateLimitOptions = {}) {
    this.perKey = options.perKey ?? 6;
    this.global = options.global ?? 60;
    this.windowMs = options.windowMs ?? 60_000;
    this.now = options.now ?? Date.now;
  }

  /** Counts one attempt; throws `ResolutionUnavailable` (with a retry hint) when over a limit. */
  take(key: string): void {
    const t = this.now();
    if (t - this.windowStart >= this.windowMs || t < this.windowStart) {
      this.windowStart = t;
      this.total = 0;
      this.keys.clear();
    }
    const retry = Math.max(1, Math.ceil((this.windowStart + this.windowMs - t) / 1000));
    if (this.total >= this.global) throw new ResolutionUnavailable('resolution rate limit', retry);
    const n = this.keys.get(key) ?? 0;
    if (n >= this.perKey) throw new ResolutionUnavailable('resolution rate limit', retry);
    this.total++;
    this.keys.set(key, n + 1);
  }
}

export interface BoundedSourceOptions {
  /** Per fetch. Default 5000. */
  timeoutMs?: number;
  /** Largest log accepted, entries. Default 256. */
  maxEntries?: number;
  /** Cache lifetime of a fetched log, ms. Default 60000; 0 disables. */
  ttlMs?: number;
  /** Cache capacity, DIDs. Default 256. */
  maxCached?: number;
  /** Consulted before every fetch that misses the cache (never for a cache hit or an offline method). */
  limiter?: ResolutionRateLimiter;
  now?: () => number;
}

/**
 * Wraps a rotation-log source with a timeout, an entry cap and a short cache and a rate limit before
 * each fetch (the cache holds only what the source returned; the resolver still replays and validates it on
 * every use, so a cached log is never trusted unchecked). A fetch error is not cached.
 */
export class BoundedRotationLogSource implements RotationLogSource {
  private readonly inner: RotationLogSource;
  private readonly timeoutMs: number;
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly maxCached: number;
  private readonly limiter: ResolutionRateLimiter | undefined;
  private readonly now: () => number;
  private readonly cache = new Map<string, { at: number; log: RotationLogEntry[] }>();

  constructor(inner: RotationLogSource, options: BoundedSourceOptions = {}) {
    this.inner = inner;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.maxEntries = options.maxEntries ?? 256;
    this.ttlMs = options.ttlMs ?? 60_000;
    this.maxCached = options.maxCached ?? 256;
    this.limiter = options.limiter;
    this.now = options.now ?? Date.now;
  }

  async getLog(did: string, src?: string): Promise<RotationLogEntry[]> {
    const key = `${did}|${src ?? ''}`;
    const hit = this.cache.get(key);
    if (hit !== undefined && this.now() - hit.at < this.ttlMs) return hit.log;
    this.limiter?.take(did);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const log = await Promise.race([
        this.inner.getLog(did, src),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('rotation log fetch timed out')), this.timeoutMs);
        }),
      ]);
      if (log.length > this.maxEntries) throw new Error('rotation log is larger than allowed');
      if (this.ttlMs > 0 && log.length > 0) {
        if (this.cache.size >= this.maxCached) this.cache.delete(this.cache.keys().next().value as string);
        this.cache.set(key, { at: this.now(), log });
      }
      return log;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
}
