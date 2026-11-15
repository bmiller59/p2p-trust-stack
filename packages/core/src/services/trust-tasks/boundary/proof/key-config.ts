// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The configuration gate for the dedicated boundary key (gate G2, K7).
 *
 * DEFAULT OFF. With nothing configured every process signs and verifies exactly as before (`#key-1`,
 * latest key set). The switch is explicit:
 *
 *   TRUST_TASKS_BOUNDARY_KEY=dedicated       selects the dedicated key; anything else, or unset, is `key-1`
 *   BOUNDARY_KEY_CUTOVER_AT=<RFC 3339 time>  REQUIRED with `dedicated`: the cutover instant
 *   BOUNDARY_KEY_MAX_PROOF_AGE_SECONDS=600   optional freshness bound of the verifier (default 600)
 *
 * The cutover instant is the first `proof.created` that is signed with `#key-boundary`; earlier
 * documents stay valid under `#key-1`. Record it only after the log entry that adds `#key-boundary`
 * is resolvable at the public resolver (propagation), then publish it (docs/P11 cutover runbook).
 * A `dedicated` setting with a missing or unparseable cutover is NOT honoured: the result is the
 * legacy mode plus a `problem` for the caller to log, so a typo can never half-switch a process.
 */
import { generateEd25519KeyPairFromSeed, sha256 } from '../../../../crypto/primitives.js';
import type { BoundaryKeyPolicy } from './verify.js';

export type BoundaryKeyConfig =
  | { readonly mode: 'key-1' }
  | { readonly mode: 'dedicated'; readonly cutoverAtMs: number; readonly maxProofAgeMs: number };

export function resolveBoundaryKeyConfig(env: Readonly<Record<string, string | undefined>>): { config: BoundaryKeyConfig; problem?: string } {
  const legacy: BoundaryKeyConfig = { mode: 'key-1' };
  const requested = env.TRUST_TASKS_BOUNDARY_KEY?.trim();
  if (requested === undefined || requested === '' || requested === 'key-1') return { config: legacy };
  if (requested !== 'dedicated') return { config: legacy, problem: `TRUST_TASKS_BOUNDARY_KEY=${requested} is not recognised; using #key-1` };
  const raw = env.BOUNDARY_KEY_CUTOVER_AT?.trim();
  // An explicit zone is required: a zone-less stamp would be read in the host's local time.
  if (raw === undefined || raw === '' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(raw)) {
    return { config: legacy, problem: 'TRUST_TASKS_BOUNDARY_KEY=dedicated needs BOUNDARY_KEY_CUTOVER_AT as an RFC 3339 time with a zone; using #key-1' };
  }
  const cutoverAtMs = Date.parse(raw);
  if (!Number.isFinite(cutoverAtMs)) return { config: legacy, problem: 'BOUNDARY_KEY_CUTOVER_AT is not a valid time; using #key-1' };
  const ageRaw = env.BOUNDARY_KEY_MAX_PROOF_AGE_SECONDS?.trim();
  const age = ageRaw === undefined || ageRaw === '' ? 600 : Number(ageRaw);
  if (!Number.isFinite(age) || age <= 0) return { config: legacy, problem: 'BOUNDARY_KEY_MAX_PROOF_AGE_SECONDS must be a positive number; using #key-1' };
  return { config: { mode: 'dedicated', cutoverAtMs, maxProofAgeMs: Math.round(age * 1000) } };
}

/** The verifier policy for a configuration; undefined for the default (no policy, behaviour unchanged). */
export function keyPolicyOf(config: BoundaryKeyConfig): BoundaryKeyPolicy | undefined {
  return config.mode === 'dedicated' ? { cutoverAtMs: config.cutoverAtMs, maxProofAgeMs: config.maxProofAgeMs } : undefined;
}

/**
 * The dedicated key pair derived from a 32-byte identity seed, domain-separated from every other key
 * the seed produces (the identity key is the seed itself, the next-key commitment hashes seed || 0x01,
 * the PQ keys use their own derivations): SHA-256 over a fixed label and the seed.
 */
export function deriveBoundaryKeyPair(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const label = new TextEncoder().encode('p2p-trust-stack/boundary-key/v1');
  const material = new Uint8Array(label.length + seed.length);
  material.set(label, 0);
  material.set(seed, label.length);
  return generateEd25519KeyPairFromSeed(sha256(material));
}
