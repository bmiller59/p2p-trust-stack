// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Process wiring for the boundary signer and verifier (conformance plan P4). The agent and the
 * utility server each call these once at startup, beside the operation-proof signer
 * (`setLocalOperationSigner`).
 */
import { base58btc } from 'multiformats/bases/base58';
import { ed25519 } from '@noble/curves/ed25519.js';
import { DidResolver } from '../../../../did/did-resolver.js';
import type { DidResolutionService } from '../../../../did/did-resolution-service.js';
import type { RotationLogSource } from '../../../../did/rotation-log-source.js';
import type { DidDocument } from '../../../../did/types.js';
import { BOUNDARY_KEY_FRAGMENT, DEDICATED_BOUNDARY_KEY_FRAGMENT, createCutoverBoundarySigner, setBoundarySigner } from './signer.js';
import type { BoundarySigner } from './signer.js';
import {
  BoundedRotationLogSource, CompositeKeyResolver, DidKeyResolver, DidResolverKeyResolver, ResolutionRateLimiter, SourcedKeyResolver,
} from './resolver.js';
import { TimePinnedKeyResolver } from './time-pinned.js';
import type { BoundedSourceOptions, KeyResolver, RateLimitOptions } from './resolver.js';

export interface BoundarySignerInstall {
  /** The identifier documents are issued as (the connection identifier). */
  did: string;
  /** The current signing key pair, read at every signature (an agent's identity key rotates). */
  keys: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  /** The identifier's own DID document, to check `#key-1` against the key before installing. */
  didDocument: DidDocument | undefined;
  /**
   * The dedicated boundary key (gate G2). Absent (the default): the signer is `#key-1` only. Present:
   * the signer is `#key-1` for proofs created before `cutoverAtMs` and `#key-boundary` from it on,
   * but ONLY when the document publishes `#key-boundary` equal to the key held AND lists it under
   * `authentication`; otherwise the signer stays `#key-1` and the reason is returned.
   */
  dedicated?: { keys: () => { publicKey: Uint8Array; secretKey: Uint8Array }; cutoverAtMs: number };
}

/** The raw Ed25519 key published at `#key-1`, or null. */
function key1Of(doc: DidDocument | undefined, fragment: string = BOUNDARY_KEY_FRAGMENT): Uint8Array | null {
  const vm = doc?.verificationMethod?.find((m) => m.id === `#${fragment}` || m.id.endsWith(`#${fragment}`));
  if (vm === undefined) return null;
  try {
    const raw = base58btc.decode(vm.publicKeyMultibase);
    return raw.length === 34 && raw[0] === 0xed && raw[1] === 0x01 ? raw.slice(2) : null;
  } catch {
    return null;
  }
}

/**
 * Install the boundary signer as `did#key-1` for this process, only when the key we hold is the key
 * the identifier's document publishes at `#key-1` (a signer whose key peers cannot find would sign
 * documents nobody can verify). Returns whether it installed and, if not, why.
 */
export function installBoundarySigner(options: BoundarySignerInstall): { installed: boolean; reason?: string; key?: 'key-1' | 'dedicated' } {
  const published = key1Of(options.didDocument);
  if (published === null) return { installed: false, reason: 'the identifier document publishes no Ed25519 #key-1' };
  const held = options.keys().publicKey;
  if (Buffer.compare(Buffer.from(published), Buffer.from(held)) !== 0) {
    return { installed: false, reason: 'the signing key held is not the key published at #key-1' };
  }
  const { did, keys } = options;
  let dedicatedNote: string | undefined;
  if (options.dedicated !== undefined) {
    const { dedicated } = options;
    const publishedDedicated = key1Of(options.didDocument, DEDICATED_BOUNDARY_KEY_FRAGMENT);
    const listed = options.didDocument?.authentication?.some((a) => a === `#${DEDICATED_BOUNDARY_KEY_FRAGMENT}` || a.endsWith(`#${DEDICATED_BOUNDARY_KEY_FRAGMENT}`)) === true;
    if (publishedDedicated === null || !listed) dedicatedNote = 'the identifier document does not publish #key-boundary under authentication; staying on #key-1';
    else if (Buffer.compare(Buffer.from(publishedDedicated), Buffer.from(dedicated.keys().publicKey)) !== 0) dedicatedNote = 'the dedicated key held is not the key published at #key-boundary; staying on #key-1';
    else {
      setBoundarySigner(createCutoverBoundarySigner({
        did,
        legacySecretKey: () => keys().secretKey,
        dedicatedSecretKey: () => dedicated.keys().secretKey,
        cutoverAtMs: dedicated.cutoverAtMs,
      }));
      return { installed: true, key: 'dedicated' };
    }
  }
  const signer: BoundarySigner = {
    did,
    verificationMethod: `${did}#${BOUNDARY_KEY_FRAGMENT}`,
    get publicKey() {
      return keys().publicKey;
    },
    sign: (message) => ed25519.sign(message, keys().secretKey),
  };
  setBoundarySigner(signer);
  return dedicatedNote === undefined ? { installed: true } : { installed: true, key: 'key-1', reason: dedicatedNote };
}

export interface VerifierResolverOptions {
  /** The local rotation-log source (an agent's own database); did:scid:vh peers whose log is held resolve through it. */
  localSource?: RotationLogSource;
  /** A remote source (`HttpRotationLogSource`), consulted after the local one; bounded here. */
  remoteSource?: RotationLogSource;
  bounds?: BoundedSourceOptions;
  rateLimit?: RateLimitOptions;
  /** Resolve did:scid:vh key sets AT `proof.created` from the validated log (gate G2). Default false: latest. */
  timePinned?: boolean;
}

class FallbackSource implements RotationLogSource {
  private readonly sources: readonly RotationLogSource[];
  constructor(sources: readonly RotationLogSource[]) {
    this.sources = sources;
  }
  async getLog(did: string, src?: string) {
    let last: unknown;
    for (const s of this.sources) {
      try {
        const log = await s.getLog(did, src);
        if (log.length > 0) return log;
      } catch (err) {
        last = err;
      }
    }
    if (last !== undefined) throw last;
    return [];
  }
}

/**
 * The verifier's key resolver for a process with its own rotation-log store (the agent): did:key and
 * did:peer:4 offline; did:scid:vh through the local log, then, when configured, a bounded remote
 * source (timeout, entry cap, cache, rate limit). No remote source means a peer's did:scid:vh log
 * must already be held (the peer introduced first); otherwise the answer is `unavailable`.
 */
export function createLocalKeyResolver(options: VerifierResolverOptions): KeyResolver {
  const sources: RotationLogSource[] = [];
  if (options.localSource !== undefined) sources.push(options.localSource);
  if (options.remoteSource !== undefined) {
    sources.push(new BoundedRotationLogSource(options.remoteSource, { ...options.bounds, limiter: new ResolutionRateLimiter(options.rateLimit) }));
  }
  const logSource: RotationLogSource = sources.length === 1 ? sources[0]! : new FallbackSource(sources);
  if (options.timePinned === true) {
    // did:scid:vh answered at `created`; the DidResolver entry stays for did:peer:4 (offline).
    return new CompositeKeyResolver([new DidKeyResolver(), new TimePinnedKeyResolver({ source: logSource }), new DidResolverKeyResolver(new DidResolver({}))]);
  }
  return new CompositeKeyResolver([new DidKeyResolver(), new DidResolverKeyResolver(new DidResolver(sources.length === 0 ? {} : { logSource }))]);
}

/**
 * The server's TIME-PINNED key resolver (gate G2): did:scid:vh key sets are taken from the validated
 * rotation-log rows (`DidResolutionService.resolveLog`), never from the cached `document_json`
 * snapshot, and are pinned to `proof.created`. did:peer:4 resolves offline.
 */
export function createTimePinnedServerKeyResolver(service: Pick<DidResolutionService, 'resolveLog'>): KeyResolver {
  const source: RotationLogSource = {
    async getLog(did) {
      return (await service.resolveLog(did))?.entries ?? [];
    },
  };
  return new CompositeKeyResolver([new DidKeyResolver(), new TimePinnedKeyResolver({ source }), new DidResolverKeyResolver(new DidResolver({}))]);
}

/** The verifier's key resolver for the server, from its database-backed resolution service (a cache-sourced result is refused). */
export function createServerKeyResolver(service: Pick<DidResolutionService, 'resolve'>): KeyResolver {
  return new CompositeKeyResolver([
    new DidKeyResolver(),
    new SourcedKeyResolver(async (did) => {
      const report = await service.resolve(did);
      return { source: report.source, didDocument: report.result.didDocument, error: report.result.didResolutionMetadata.error };
    }),
  ]);
}
