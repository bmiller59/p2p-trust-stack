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
import { BOUNDARY_KEY_FRAGMENT, setBoundarySigner } from './signer.js';
import type { BoundarySigner } from './signer.js';
import {
  BoundedRotationLogSource, CompositeKeyResolver, DidKeyResolver, DidResolverKeyResolver, ResolutionRateLimiter, SourcedKeyResolver,
} from './resolver.js';
import type { BoundedSourceOptions, KeyResolver, RateLimitOptions } from './resolver.js';

export interface BoundarySignerInstall {
  /** The identifier documents are issued as (the connection identifier). */
  did: string;
  /** The current signing key pair, read at every signature (an agent's identity key rotates). */
  keys: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  /** The identifier's own DID document, to check `#key-1` against the key before installing. */
  didDocument: DidDocument | undefined;
}

/** The raw Ed25519 key published at `#key-1`, or null. */
function key1Of(doc: DidDocument | undefined): Uint8Array | null {
  const vm = doc?.verificationMethod?.find((m) => m.id === `#${BOUNDARY_KEY_FRAGMENT}` || m.id.endsWith(`#${BOUNDARY_KEY_FRAGMENT}`));
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
export function installBoundarySigner(options: BoundarySignerInstall): { installed: boolean; reason?: string } {
  const published = key1Of(options.didDocument);
  if (published === null) return { installed: false, reason: 'the identifier document publishes no Ed25519 #key-1' };
  const held = options.keys().publicKey;
  if (Buffer.compare(Buffer.from(published), Buffer.from(held)) !== 0) {
    return { installed: false, reason: 'the signing key held is not the key published at #key-1' };
  }
  const { did, keys } = options;
  const signer: BoundarySigner = {
    did,
    verificationMethod: `${did}#${BOUNDARY_KEY_FRAGMENT}`,
    get publicKey() {
      return keys().publicKey;
    },
    sign: (message) => ed25519.sign(message, keys().secretKey),
  };
  setBoundarySigner(signer);
  return { installed: true };
}

export interface VerifierResolverOptions {
  /** The local rotation-log source (an agent's own database); did:scid:vh peers whose log is held resolve through it. */
  localSource?: RotationLogSource;
  /** A remote source (`HttpRotationLogSource`), consulted after the local one; bounded here. */
  remoteSource?: RotationLogSource;
  bounds?: BoundedSourceOptions;
  rateLimit?: RateLimitOptions;
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
  return new CompositeKeyResolver([new DidKeyResolver(), new DidResolverKeyResolver(new DidResolver(sources.length === 0 ? {} : { logSource }))]);
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
