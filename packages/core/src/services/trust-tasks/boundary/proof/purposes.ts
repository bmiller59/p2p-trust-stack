// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Proof purposes: the single source (conformance plan 3.3). Tier 1 accepts `authentication` and
 * `assertionMethod` and refuses `keyAgreement`, an absent purpose and any unrecognised one. Tier 2
 * (the `attested` profile) pins `authentication` for every operational document, and
 * `assertionMethod` only for the approver-attestation slugs.
 */
import { tryParseTypeUri } from '../runtime.js';

export type ProofPurpose = 'authentication' | 'assertionMethod';

export const TIER1_PURPOSES: readonly ProofPurpose[] = ['authentication', 'assertionMethod'];

/**
 * Approver-attestation slugs: documents in which a person (an approver) attests a decision, signed
 * under `assertionMethod` (the identity-key slot). Slug is the type's name without version.
 * Today: the task-consent decision. Extend here only; a drift test pins this list.
 */
export const ATTESTATION_SLUGS: readonly string[] = ['task-consent/decision'];

/** The slug of a Type URI (registry form or the URN form), or undefined when it is not one. */
export function slugOf(typeUri: string): string | undefined {
  const base = typeUri.replace(/#(request|response)$/, '');
  const parsed = tryParseTypeUri(base);
  if (parsed === null) return undefined;
  return (parsed as { slug?: string }).slug;
}

export function isAttestationType(typeUri: string): boolean {
  const slug = slugOf(typeUri);
  return slug !== undefined && ATTESTATION_SLUGS.includes(slug);
}

/** The purposes a document of this type may be proven under at the given tier. */
export function allowedPurposes(typeUri: string, tier: 1 | 2): readonly ProofPurpose[] {
  if (tier === 1) return TIER1_PURPOSES;
  return isAttestationType(typeUri) ? ['assertionMethod'] : ['authentication'];
}
