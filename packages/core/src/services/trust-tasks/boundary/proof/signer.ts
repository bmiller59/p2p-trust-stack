// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The boundary signer (conformance plan P4, section 3.1, decision 18): the ONE place that names the
 * verification method a service signs its Trust Task documents with.
 *
 * Now: the connection identifier's `#key-1` (listed under `authentication`), `proofPurpose`
 * `authentication`. A dedicated boundary key is gate G2 and is not built; when it lands, the signer
 * installed here is the only thing that changes (plus the verifier's key-set-at-created rule).
 *
 * The signer is installed once per process, beside the operation-proof signer
 * (`setLocalOperationSigner`), because the builders of replies are far from the code that loads the
 * key. It signs; it never decides what to sign.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { EDDSA_JCS_2022, PROOF_TYPE, encodeProofValue, hashData, wholeSecondTimestamp } from './data-integrity.js';
import type { ProofPurpose } from './purposes.js';

export interface BoundarySigner {
  /** The identifier documents are issued as (the envelope `issuer`). */
  readonly did: string;
  /** The verification method the proof names (`did#key-1`). */
  readonly verificationMethod: string;
  /** Raw Ed25519 public key (for self-checks). */
  readonly publicKey: Uint8Array;
  /** Signs the 64 bytes of `hashData`. */
  sign(message: Uint8Array): Uint8Array;
  /**
   * Optional: the signer to use for a proof whose `created` is `createdMs`. A signer with a cutover
   * (`createCutoverBoundarySigner`) answers the legacy `#key-1` signer before the cutover instant
   * and the dedicated-key signer from it on. `signDocument` consults it; absent means "this signer".
   */
  at?(createdMs: number): BoundarySigner;
}

/** The fragment used until the dedicated boundary key is switched on (gate G2). */
export const BOUNDARY_KEY_FRAGMENT = 'key-1';
/** The dedicated boundary-signing method's fragment (`BOUNDARY_VM_FRAGMENT` in the DID layer). */
export const DEDICATED_BOUNDARY_KEY_FRAGMENT = 'key-boundary';

/** A signer over an Ed25519 secret key (32-byte seed) for `did`, signing as `did#<fragment>`. */
export function createEd25519BoundarySigner(options: { did: string; secretKey: Uint8Array; fragment?: string; verificationMethod?: string }): BoundarySigner {
  const secretKey = new Uint8Array(options.secretKey);
  const publicKey = ed25519.getPublicKey(secretKey);
  return {
    did: options.did,
    verificationMethod: options.verificationMethod ?? `${options.did}#${options.fragment ?? BOUNDARY_KEY_FRAGMENT}`,
    publicKey,
    sign: (message) => ed25519.sign(message, secretKey),
  };
}

/**
 * A signer that signs as `did#key-1` for proofs created BEFORE `cutoverAtMs` and as
 * `did#key-boundary` (the dedicated key) from it on. The switch is by the proof's `created`, the
 * same instant a time-pinned verifier judges, so a document and the key set it is checked against
 * always agree on which side of the cutover it falls.
 */
export function createCutoverBoundarySigner(options: {
  did: string;
  legacySecretKey: () => Uint8Array;
  dedicatedSecretKey: () => Uint8Array;
  cutoverAtMs: number;
}): BoundarySigner {
  const legacy = (): BoundarySigner => createEd25519BoundarySigner({ did: options.did, secretKey: options.legacySecretKey(), fragment: BOUNDARY_KEY_FRAGMENT });
  const dedicated = (): BoundarySigner => createEd25519BoundarySigner({ did: options.did, secretKey: options.dedicatedSecretKey(), fragment: DEDICATED_BOUNDARY_KEY_FRAGMENT });
  return {
    did: options.did,
    verificationMethod: `${options.did}#${BOUNDARY_KEY_FRAGMENT}`,
    get publicKey() {
      return legacy().publicKey;
    },
    sign: (message) => legacy().sign(message),
    at: (createdMs) => (createdMs >= options.cutoverAtMs ? dedicated() : legacy()),
  };
}

let installed: BoundarySigner | undefined;

/** Install (or clear) this process's boundary signer. */
export function setBoundarySigner(signer: BoundarySigner | undefined): void {
  installed = signer;
}

export function getBoundarySigner(): BoundarySigner | undefined {
  return installed;
}

export interface SignOptions {
  /** Epoch ms for `proof.created`, written in whole seconds. */
  created: number;
  /** Default `authentication`: `assertionMethod` only for approver attestations. */
  purpose?: ProofPurpose | string;
  /** Presentations: the challenge and domain the proof is bound to (written into the signed proof configuration). */
  challenge?: string;
  domain?: string;
  /** Tests only: sign although the document's issuer is not the signer's identifier. */
  allowIssuerMismatch?: boolean;
}

/**
 * Sign a document: `eddsa-jcs-2022` over the document without its top-level proof. The document's
 * own `@context`, if any, is copied into the proof configuration. A document signed here has its
 * `proof` member replaced, never merged.
 */
export function signDocument<T extends Record<string, unknown>>(doc: T, signerOrCutover: BoundarySigner, options: SignOptions): T & { proof: Record<string, unknown> } {
  const signer = signerOrCutover.at?.(options.created) ?? signerOrCutover;
  const { proof: _dropped, ...body } = doc as Record<string, unknown>;
  if (body.issuer !== signer.did && options.allowIssuerMismatch !== true) {
    throw new Error('the document issuer is not the signing identifier');
  }
  const config: Record<string, unknown> = {
    type: PROOF_TYPE,
    cryptosuite: EDDSA_JCS_2022,
    created: wholeSecondTimestamp(options.created),
    verificationMethod: signer.verificationMethod,
    proofPurpose: options.purpose ?? 'authentication',
  };
  if (options.challenge !== undefined) config.challenge = options.challenge;
  if (options.domain !== undefined) config.domain = options.domain;
  if (Object.prototype.hasOwnProperty.call(body, '@context')) config['@context'] = structuredClone(body['@context']);
  const proofValue = encodeProofValue(signer.sign(hashData(config, body)));
  return { ...(body as T), proof: { ...config, proofValue } };
}
