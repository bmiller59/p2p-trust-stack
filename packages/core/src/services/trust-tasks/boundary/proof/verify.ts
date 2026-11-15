// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The DID-resolving proof verifier (conformance plan P4, sections 3.2 and 3.3).
 *
 * Verifies `eddsa-jcs-2022` Data Integrity proofs over the JSON AS RECEIVED (the parsed object is
 * canonicalised; nothing is re-serialised from typed structures), for `did:key`, `did:peer:4` and
 * `did:scid:vh` issuers. It implements the registry runtime's `ProofVerifier` so the consume
 * pipeline calls it unchanged, and keeps the detail the boolean cannot carry (verified signer,
 * purpose, key, why not) for the pipeline and for persistence.
 *
 * Rules, in order (cheap checks first, so nothing remote is resolved for a malformed proof):
 *  1. shape of `proof`; `type` is `DataIntegrityProof`; `proofPurpose` is one of the purposes the
 *     caller allows (Tier 1: authentication and assertionMethod; Tier 2: authentication only, or
 *     assertionMethod only for approver attestations): keyAgreement, absent or unknown are refused;
 *  2. `cryptosuite` is `eddsa-jcs-2022`; anything else is refused, never processed as unsigned;
 *  3. `created` and `expires` are range-valid RFC 3339 stamps (the shared reader, every spelling
 *     accepted), `created` not later than now plus the skew, `expires` not passed;
 *  4. the verification method's identifier equals the document's `issuer` exactly (a relative
 *     reference is resolved against the issuer) and names a fragment;
 *  5. `@context` agreement: a proof `@context` must exist on the document and be equal;
 *  6. the key is resolved from the issuer's DID, the fragment must be a verification method of that
 *     document AND listed under the relationship matching `proofPurpose` (no "first signing key"
 *     fallback);
 *  7. the Ed25519 signature verifies strictly over hashData.
 *
 * A resolution that cannot be completed throws `TaskError` `unavailable` (retryable): "could not
 * check" is never "forged" (the F-031 discipline). Everything else is a definite refusal.
 */
import { TaskError } from '../errors.js';
import { parseDateTimeStamp } from '../datetime.js';
import type { ProofVerifier, TrustTaskDocument } from '../runtime.js';
import { EDDSA_JCS_2022, PROOF_TYPE, decodeProofValue, ed25519VerifyStrict, hashData, jcsBytes } from './data-integrity.js';
import { TIER1_PURPOSES } from './purposes.js';
import { ResolutionUnavailable } from './resolver.js';
import type { KeyResolver } from './resolver.js';

export type ProofFailure =
  | 'malformedProof'
  | 'purposeRefused'
  | 'unsupportedCryptosuite'
  | 'issuerMismatch'
  | 'keyNotListed'
  | 'unresolvableIssuer'
  | 'signatureInvalid'
  | 'createdOutOfBounds';

export interface ProofVerdict {
  readonly valid: boolean;
  readonly failure?: ProofFailure;
  readonly detail?: string;
  /** The identifier whose key verified the proof (equals the issuer). Only when valid. */
  readonly signer?: string;
  readonly purpose?: string;
  /** The verification method as written in the proof. */
  readonly verificationMethod?: string;
  /** Where the key set came from. */
  readonly keySource?: string;
  /** `proof.created`, epoch ms. */
  readonly createdMs?: number;
}

export interface VerifyContext {
  /** The instant to judge freshness of `created`/`expires` at, epoch ms. */
  nowMs: number;
  /** Purposes this document may be proven under. Default: the Tier 1 set. */
  purposes?: readonly string[];
  /** Allowed clock skew for `created`, ms. Default 60000. */
  skewMs?: number;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v !== '';

function refuse(failure: ProofFailure, detail: string, extra: Partial<ProofVerdict> = {}): ProofVerdict {
  return { valid: false, failure, detail, ...extra };
}

/**
 * The dedicated-boundary-key policy (gate G2, K5). Absent by default: the verifier then behaves as
 * before (no lower bound on `created`, `#key-1` always accepted where listed).
 *
 * When present:
 *  - `proof.created` is REQUIRED and must be within `[now - maxProofAgeMs, now + skew]` of the
 *    verifier's OWN clock. `created` is signer-asserted; this bound is what stops a backdated
 *    `created` from making a retired key look current. A `#key-1` proof made after the cutover and
 *    backdated to before it is accepted only while `now - cutover <= maxProofAgeMs`; after that no
 *    `#key-1` proof can pass. To re-verify a STORED document later, pass the time the document was
 *    received as `nowMs`, not the current time.
 *  - the key set is resolved AT `created` (a time-pinned resolver is expected; see
 *    `TimePinnedKeyResolver`), so a key added by a later log entry does not verify earlier documents.
 *  - when `cutoverAtMs` is set and the proof is `created >= cutoverAtMs`, `#key-1` is refused for an
 *    identifier whose key set at `created` lists the dedicated `#key-boundary` under the proof's
 *    purpose. An identifier without a dedicated key (did:peer:4 before its next provisioning, a
 *    server not yet updated) keeps `#key-1`: the policy never leaves an identifier with no signer.
 */
export interface BoundaryKeyPolicy {
  /** Oldest `created` accepted, as an age. Default 600000 (10 minutes). */
  maxProofAgeMs?: number;
  /** `BOUNDARY_KEY_CUTOVER_AT`, epoch ms. Unset: `#key-1` is never retired. */
  cutoverAtMs?: number;
}

export const DEFAULT_MAX_PROOF_AGE_MS = 600_000;
/** The key every identifier signed with before the dedicated one (see `BOUNDARY_KEY_FRAGMENT`). */
const LEGACY_FRAGMENT = 'key-1';
const DEDICATED_FRAGMENT = 'key-boundary';

export interface DidProofVerifierOptions {
  resolver: KeyResolver;
  keyPolicy?: BoundaryKeyPolicy;
}

export class DidProofVerifier {
  private readonly resolver: KeyResolver;
  private readonly keyPolicy: BoundaryKeyPolicy | undefined;

  constructor(options: DidProofVerifierOptions) {
    this.resolver = options.resolver;
    this.keyPolicy = options.keyPolicy;
  }

  /**
   * A registry-runtime `ProofVerifier` bound to one document's context (the pipeline builds one per
   * request). It remembers what happened, because the runtime reports any verifier failure as
   * `proofInvalid`: an `unavailable` (resolution could not be completed) is kept here so the
   * pipeline can answer it as such.
   */
  forContext(context: VerifyContext): BoundProofVerifier {
    return new BoundProofVerifier(this, context);
  }

  /** Verify the proof on a document. Throws `TaskError` `unavailable` when a key set could not be obtained. */
  async verify(doc: unknown, context: VerifyContext): Promise<ProofVerdict> {
    if (!isObject(doc)) return refuse('malformedProof', 'the document is not an object');
    const proof = doc.proof;
    if (!isObject(proof)) return refuse('malformedProof', 'no proof object');
    if (proof.type !== PROOF_TYPE) return refuse('malformedProof', 'proof type');
    for (const k of ['cryptosuite', 'verificationMethod', 'proofPurpose', 'proofValue']) {
      if (!nonEmpty(proof[k])) return refuse('malformedProof', `proof.${k}`);
    }
    const purpose = proof.proofPurpose as string;
    const allowed = context.purposes ?? TIER1_PURPOSES;
    if (!allowed.includes(purpose)) return refuse('purposeRefused', `proofPurpose ${purpose} is not accepted here`, { purpose });
    if (proof.cryptosuite !== EDDSA_JCS_2022) return refuse('unsupportedCryptosuite', String(proof.cryptosuite), { purpose });

    const skew = Math.max(0, context.skewMs ?? 60_000);
    let createdMs: number | undefined;
    if (proof.created !== undefined) {
      createdMs = typeof proof.created === 'string' ? parseDateTimeStamp(proof.created) : undefined;
      if (createdMs === undefined) return refuse('malformedProof', 'proof.created');
      if (createdMs > context.nowMs + skew) return refuse('malformedProof', 'proof.created is in the future');
    }
    const policy = this.keyPolicy;
    if (policy !== undefined) {
      if (createdMs === undefined) return refuse('createdOutOfBounds', 'proof.created is required', { purpose });
      const maxAge = Math.max(0, policy.maxProofAgeMs ?? DEFAULT_MAX_PROOF_AGE_MS);
      if (createdMs < context.nowMs - maxAge) return refuse('createdOutOfBounds', 'proof.created is older than the freshness bound', { purpose, createdMs });
    }
    if (proof.expires !== undefined) {
      const at = typeof proof.expires === 'string' ? parseDateTimeStamp(proof.expires) : undefined;
      if (at === undefined) return refuse('malformedProof', 'proof.expires');
      if (context.nowMs > at) return refuse('malformedProof', 'proof.expires has passed');
    }

    const issuer = doc.issuer;
    if (!nonEmpty(issuer)) return refuse('issuerMismatch', 'no in-band issuer');
    const written = proof.verificationMethod as string;
    const hash = written.indexOf('#');
    const controller = hash === -1 ? written : written.slice(0, hash);
    const fragment = hash === -1 ? '' : written.slice(hash + 1);
    // A relative reference (`#key-1`) is resolved against the issuer; an absolute one must be the issuer's.
    if (controller !== '' && controller !== issuer) return refuse('issuerMismatch', 'the verification method belongs to another identifier');
    if (fragment === '') return refuse('issuerMismatch', 'the verification method names no key');
    if (Object.prototype.hasOwnProperty.call(proof, '@context')) {
      if (!Object.prototype.hasOwnProperty.call(doc, '@context')) return refuse('malformedProof', 'proof @context without document @context');
      if (!Buffer.from(jcsBytes(proof['@context'])).equals(Buffer.from(jcsBytes(doc['@context'])))) return refuse('malformedProof', '@context differs');
    }
    const signature = decodeProofValue(proof.proofValue as string);
    if (signature === null || signature.length !== 64) return refuse('signatureInvalid', 'proofValue encoding');

    // Resolution (the only step that may touch the network).
    let keySet;
    try {
      keySet = await this.resolver.resolve(issuer, createdMs);
    } catch (err) {
      if (err instanceof ResolutionUnavailable) {
        throw new TaskError({
          code: 'unavailable',
          retryable: true,
          internalMessage: err.message,
        });
      }
      throw err;
    }
    if (keySet === null) return refuse('unresolvableIssuer', 'the issuer identifier is not of a served method', { purpose });
    const key = keySet.keys.find((k) => k.fragment === fragment);
    if (key === undefined) return refuse('keyNotListed', 'the key is not a verification method of the issuer', { purpose });
    if (!key.relationships.includes(purpose)) return refuse('keyNotListed', `the key is not listed under ${purpose}`, { purpose });
    if (
      policy?.cutoverAtMs !== undefined && createdMs !== undefined && createdMs >= policy.cutoverAtMs && fragment === LEGACY_FRAGMENT &&
      keySet.keys.some((k) => k.fragment === DEDICATED_FRAGMENT && k.relationships.includes(purpose))
    ) {
      return refuse('keyNotListed', '#key-1 is retired for documents created at or after the cutover', { purpose });
    }

    const { proofValue: _pv, ...config } = proof;
    const { proof: _p, ...body } = doc;
    if (!ed25519VerifyStrict(signature, hashData(config, body), key.publicKey)) {
      return refuse('signatureInvalid', 'the signature does not verify', { purpose });
    }
    return {
      valid: true,
      signer: issuer,
      purpose,
      verificationMethod: written,
      keySource: keySet.source,
      ...(createdMs === undefined ? {} : { createdMs }),
    };
  }
}

export class BoundProofVerifier implements ProofVerifier {
  private readonly parent: DidProofVerifier;
  private readonly context: VerifyContext;
  /** The verdict, once the runtime has called `verify`. */
  verdict: ProofVerdict | undefined;
  /** Set when a key set could not be obtained: not a verdict on the proof. */
  unavailable: TaskError | undefined;

  constructor(parent: DidProofVerifier, context: VerifyContext) {
    this.parent = parent;
    this.context = context;
  }

  async verify<P>(doc: TrustTaskDocument<P>): Promise<boolean> {
    try {
      this.verdict = await this.parent.verify(doc, this.context);
      return this.verdict.valid;
    } catch (err) {
      if (err instanceof TaskError) {
        this.unavailable = err;
        return false;
      }
      throw err;
    }
  }
}
