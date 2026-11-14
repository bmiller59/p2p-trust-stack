// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Time-pinned key resolution (gate G2, K5): the key set valid at a proof's `created` time, from the
 * validated rotation log of a did:scid:vh identifier.
 *
 * Why. After the dedicated boundary key is added and `#key-1` retired from signing, a document
 * signed with `#key-1` before the cutover must stay verifiable while `#key-1` is refused afterwards;
 * "latest" resolution cannot tell the two apart. It also keeps a key that a LATER entry added from
 * verifying documents created before that entry.
 *
 * Rule (decided here, see docs/P11 notes in the commit): the effective time of a log entry is its
 * signer-asserted `createdAt` made monotone along the chain (never earlier than the previous
 * entry's). The key set at proof time T (whole seconds, floor of `created`) is the document of the
 * LAST validated entry whose effective time is STRICTLY earlier than T: at an equal second the OLD
 * set applies. The genesis entry applies from its own second (`<=`); a proof created before the
 * genesis has an empty key set. Only the validated chain (`ScidVhMethod.validateEntries`: digest,
 * hash chain, committed signing key, Ed25519 and ML-DSA-65 signatures) is consulted, never a cached
 * `document_json` snapshot, so a `source: 'cache'` result cannot occur here by construction. An
 * unavailable, empty or wholly invalid log is `ResolutionUnavailable`, never an empty key set.
 *
 * What it does NOT give. `createdAt` is asserted by the identity's controller and is inside the
 * signed digest; no witness or insertion-time anchor exists (`rotation_log.created_at` stores the
 * entry's own `createdAt`). A controller can therefore backdate an entry it appends. The verifier's
 * freshness bound on `proof.created` (`verify.ts`, `BoundaryKeyPolicy.maxProofAgeMs`) is what stops a
 * backdated `created` from extending an old key's life; the residual risk is documented there.
 */
import { ScidVhMethod, scidMatchesGenesis } from '../../../../did/scid-vh-method.js';
import type { RotationLogEntry } from '../../../../did/rotation-types.js';
import type { RotationLogSource } from '../../../../did/rotation-log-source.js';
import { keysOfDocument, ResolutionUnavailable } from './resolver.js';
import type { KeyResolver, ResolvedKeySet } from './resolver.js';

/**
 * The entry of an already VALIDATED chain in force at `atMs`, or null (the proof predates the
 * identifier). See the rule in the file header.
 */
export function entryInForceAt(validated: readonly RotationLogEntry[], atMs: number): RotationLogEntry | null {
  const t = Math.floor(atMs / 1000);
  let effective = 0;
  let inForce: RotationLogEntry | null = null;
  for (let i = 0; i < validated.length; i++) {
    const entry = validated[i]!;
    effective = Math.max(effective, entry.createdAt);
    const applies = i === 0 ? effective <= t : effective < t;
    if (!applies) break;
    inForce = entry;
  }
  return inForce;
}

export { scidMatchesGenesis };

export interface TimePinnedKeyResolverOptions {
  /** Where did:scid:vh logs come from (local store, bounded HTTP source, the server's tables). */
  source: RotationLogSource;
  method?: ScidVhMethod;
}

/** did:scid:vh only: answers `null` for every other method, so it composes before the offline resolvers. */
export class TimePinnedKeyResolver implements KeyResolver {
  private readonly source: RotationLogSource;
  private readonly method: ScidVhMethod;

  constructor(options: TimePinnedKeyResolverOptions) {
    this.source = options.source;
    this.method = options.method ?? new ScidVhMethod({});
  }

  async resolve(did: string, atMs?: number): Promise<ResolvedKeySet | null> {
    if (!did.startsWith('did:scid:vh')) return null;
    let log: RotationLogEntry[];
    try {
      log = await this.source.getLog(did);
    } catch (err) {
      if (err instanceof ResolutionUnavailable) throw err;
      throw new ResolutionUnavailable(`resolution failed: ${(err as Error)?.message ?? 'unknown'}`);
    }
    if (log.length === 0) throw new ResolutionUnavailable('no rotation log is held for this identifier');
    const validated = this.method.validateEntries(log);
    if (validated.length === 0) throw new ResolutionUnavailable('the rotation log does not validate');
    // Self-certification: the identifier must BE the hash of the genesis entry. `validateChain` checks
    // the chain's internal consistency but not this, so without it a self-consistent log with
    // arbitrary keys could be served under any identifier.
    if (!scidMatchesGenesis(did, validated[0]!)) {
      throw new ResolutionUnavailable('the rotation log does not belong to this identifier (SCID mismatch)');
    }
    if (atMs === undefined) {
      const last = validated[validated.length - 1]!;
      return { ...keysOfDocument(did, last.didDocument, 'log'), version: last.version };
    }
    const entry = entryInForceAt(validated, atMs);
    if (entry === null) return { did, source: 'log', keySetAt: 'created', keys: [] };
    return { ...keysOfDocument(did, entry.didDocument, 'log'), keySetAt: 'created', version: entry.version };
  }
}
