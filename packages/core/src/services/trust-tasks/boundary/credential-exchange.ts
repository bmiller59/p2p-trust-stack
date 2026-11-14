// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `credential-exchange/{issue,present}` (conformance phase P5b, layer 3b-DTG): the pure parts.
 *
 * Both tasks are fire-and-forget in the registry text: neither defines a response document ("the task
 * returns no response the issuer can correlate against", "no response document to close the exchange"), so an
 * accepted delivery is answered 204 (absorbed) and a refusal is a `trust-task-error`.
 *
 * `issue` (we are the holder): the credential's own issuer must be the verified sender of the delivery
 * (a relayed delivery by a third party is refused: the envelope proves who delivered, the credential proves
 * who issued, and this stack authorises the pair from the verified sender), the subject must be the
 * recipient (us), and the credential proof must verify under `assertionMethod`. Only W3C Data-Integrity
 * credentials in the cleartext form are accepted; `sealed` bundles and SD-JWT-VC strings are refused with
 * `credential-exchange/issue:unsupportedFormat`. Relationship and witness credentials have their own
 * paths (`vrc/relationships/*`) and are refused here so this path cannot bypass the exchange binding.
 *
 * `present` (we are the verifier): the holder is the verified sender; the presentation proof must be the
 * holder's, `authentication`, bound to the verifier's nonce (the document's thread) and audience (our
 * identifier); every credential in it must be about the holder and carry a valid issuer proof. A nonce is
 * single use. Whether an issuer is one we trust is a separate decision this stack does not take here:
 * signature validity is recorded, issuer trust is not asserted.
 */
import { createHash } from 'node:crypto';
import { didToUuid } from '../../../db/uuid-helpers.js';
import { TaskError } from './errors.js';
import { digestMultibaseOf } from './proof/digest.js';
import { canonicalJson } from './runtime.js';

export const CREDENTIAL_ISSUE_TYPE = 'https://trusttasks.org/spec/credential-exchange/issue/0.1';
export const CREDENTIAL_PRESENT_TYPE = 'https://trusttasks.org/spec/credential-exchange/present/0.1';
export const ISSUE_UNSUPPORTED_FORMAT = 'credential-exchange/issue:unsupportedFormat';
export const PRESENT_STALE_NONCE = 'credential-exchange/present:staleNonce';
export const PRESENT_AUDIENCE_MISMATCH = 'credential-exchange/present:audienceMismatch';

/** What the checks need from the boundary's proof verifier (`DidProofVerifier` satisfies it). */
export interface CredentialProofVerifier {
  verify(
    doc: unknown,
    context: { nowMs: number; purposes?: readonly string[]; signerMember?: 'issuer' | 'holder' | 'credential'; challenge?: string; domain?: string },
  ): Promise<{ valid: boolean; failure?: string; signer?: string }>;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === 'string' && v !== '';
const idOf = (v: unknown): string | undefined => (str(v) ? v : isObj(v) && str(v.id) ? v.id : undefined);
const typesOf = (v: unknown): string[] => (Array.isArray(v) ? v.filter(str) : str(v) ? [v] : []);

// ── issue ───────────────────────────────────────────────────────────

export type IssuePayloadShape = { ok: true; credential: Obj } | { ok: false; reason: 'malformed' | 'unsupportedFormat' };

/** `oneOf` credential_response / sealed, and the shape of the cleartext credential. The small schema reader does not enforce `oneOf`. */
export function parseIssuePayload(payload: unknown): IssuePayloadShape {
  if (!isObj(payload)) return { ok: false, reason: 'malformed' };
  const hasResponse = payload.credential_response !== undefined;
  const hasSealed = payload.sealed !== undefined;
  if (hasResponse === hasSealed) return { ok: false, reason: 'malformed' };
  if (hasSealed) return typeof payload.sealed === 'string' && payload.sealed !== '' ? { ok: false, reason: 'unsupportedFormat' } : { ok: false, reason: 'malformed' };
  if (!isObj(payload.credential_response)) return { ok: false, reason: 'malformed' };
  const credential = payload.credential_response.credential;
  if (typeof credential === 'string') return { ok: false, reason: 'unsupportedFormat' };
  return isObj(credential) ? { ok: true, credential } : { ok: false, reason: 'malformed' };
}

/** DTG credential kinds this path stores, and the `credentials.vc_type` each is kept as. */
const VC_TYPE_OF_KIND: Readonly<Record<string, string>> = Object.freeze({
  MembershipCredential: 'vmc',
  EndorsementCredential: 'vec',
  InvitationCredential: 'vic',
  DelegationCredential: 'delegation',
  AuthorizationCredential: 'delegation',
  PersonaCredential: 'custom_endorsement',
});
/** Kinds with their own receive path (the exchange binding applies) or whose meaning lives in a predicate. */
const OWN_PATH_KINDS: readonly string[] = ['RelationshipCredential', 'WitnessCredential', 'StatementCredential', 'RelationshipCard'];

export type IssuedCredentialRefusal = 'malformed' | 'ownPath' | 'unsupportedKind' | 'issuerNotSender' | 'subjectNotHolder' | 'expired' | 'proofInvalid';

export type IssuedCredentialCheck =
  | {
      ok: true;
      vcType: string;
      kind: string;
      issuerDid: string;
      subjectDid: string;
      /** The credential in the canonical (RFC 8785) serialisation: what is stored, and what the proof is over. */
      text: string;
      /** Lower-case hex SHA-256 of `text` (the stored digest form). */
      digestHex: string;
      /** Idempotence key: the same credential always has the same id. */
      credentialUuid: string;
      validFromSec: number | null;
      validUntilSec: number | null;
    }
  | { ok: false; reason: IssuedCredentialRefusal; detail?: string };

const no = (reason: IssuedCredentialRefusal, detail?: string): IssuedCredentialCheck => ({ ok: false, reason, ...(detail === undefined ? {} : { detail }) });
const seconds = (v: unknown): number | null | undefined => {
  if (v === undefined) return null;
  if (typeof v !== 'string') return undefined;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : undefined;
};

export async function checkIssuedCredential(
  vc: Obj,
  expected: { sender: string; holder: string },
  options: { verifier: CredentialProofVerifier; nowMs: number },
): Promise<IssuedCredentialCheck> {
  const types = typesOf(vc.type);
  if (!types.includes('VerifiableCredential') || !isObj(vc.proof)) return no('malformed', 'not a Data-Integrity credential');
  const issuer = idOf(vc.issuer);
  const subject = isObj(vc.credentialSubject) ? idOf(vc.credentialSubject.id) : undefined;
  if (issuer === undefined || subject === undefined) return no('malformed', 'issuer or subject');
  const kind = types.find((t) => t in VC_TYPE_OF_KIND || OWN_PATH_KINDS.includes(t));
  if (kind === undefined) return no('unsupportedKind', 'no known credential kind');
  if (OWN_PATH_KINDS.includes(kind)) return no('ownPath', kind);
  const validFrom = seconds(vc.validFrom);
  const validUntil = seconds(vc.validUntil);
  if (validFrom === undefined || validUntil === undefined) return no('malformed', 'validity dates');
  if (issuer !== expected.sender) return no('issuerNotSender');
  if (subject !== expected.holder) return no('subjectNotHolder');
  if (validUntil !== null && validUntil * 1000 <= options.nowMs) return no('expired');
  const verdict = await options.verifier.verify(vc, { nowMs: options.nowMs, purposes: ['assertionMethod'], signerMember: 'credential' });
  if (!verdict.valid) return no('proofInvalid', verdict.failure);
  const text = canonicalJson(vc);
  const digestHex = createHash('sha256').update(text).digest('hex');
  return {
    ok: true,
    vcType: VC_TYPE_OF_KIND[kind]!,
    kind,
    issuerDid: issuer,
    subjectDid: subject,
    text,
    digestHex,
    credentialUuid: didToUuid(`urn:p2pts:credential:${digestHex}`),
    validFromSec: validFrom,
    validUntilSec: validUntil,
  };
}

// ── present ─────────────────────────────────────────────────────────

export type PresentationRefusal = 'malformed' | 'unsupportedFormat' | 'holderNotSender' | 'staleNonce' | 'audienceMismatch' | 'proofInvalid' | 'credentialInvalid';

export type PresentationCheck =
  | { ok: true; holderDid: string; text: string; digest: string; issuers: string[]; credentialCount: number }
  | { ok: false; reason: PresentationRefusal; detail?: string };

const noP = (reason: PresentationRefusal, detail?: string): PresentationCheck => ({ ok: false, reason, ...(detail === undefined ? {} : { detail }) });
/** Bound on credentials in one presentation (parser hardening). */
export const MAX_PRESENTED_CREDENTIALS = 16;

export async function checkPresentation(
  vpToken: unknown,
  expected: { holder: string; audience: string; nonce: string },
  options: { verifier: CredentialProofVerifier; nowMs: number },
): Promise<PresentationCheck> {
  if (typeof vpToken === 'string') return noP('unsupportedFormat', 'SD-JWT-VC presentations are not verified here');
  if (!isObj(vpToken) || !typesOf(vpToken.type).includes('VerifiablePresentation') || !isObj(vpToken.proof)) return noP('malformed', 'not a Data-Integrity presentation');
  if (vpToken.holder !== expected.holder) return noP('holderNotSender');
  const raw = vpToken.verifiableCredential;
  const credentials = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
  if (credentials.length < 1 || credentials.length > MAX_PRESENTED_CREDENTIALS || !credentials.every(isObj)) return noP('malformed', 'verifiableCredential');
  const proof = await options.verifier.verify(vpToken, { nowMs: options.nowMs, purposes: ['authentication'], signerMember: 'holder', challenge: expected.nonce, domain: expected.audience });
  if (!proof.valid) {
    if (proof.failure === 'challengeMismatch') return noP('staleNonce');
    if (proof.failure === 'domainMismatch') return noP('audienceMismatch');
    return noP('proofInvalid', proof.failure);
  }
  const issuers = new Set<string>();
  for (const c of credentials as Obj[]) {
    const subject = isObj(c.credentialSubject) ? idOf(c.credentialSubject.id) : undefined;
    const issuer = idOf(c.issuer);
    if (subject !== expected.holder || issuer === undefined) return noP('credentialInvalid', 'holder binding');
    const v = await options.verifier.verify(c, { nowMs: options.nowMs, purposes: ['assertionMethod'], signerMember: 'credential' });
    if (!v.valid) return noP('credentialInvalid', v.failure);
    issuers.add(issuer);
  }
  return { ok: true, holderDid: expected.holder, text: canonicalJson(vpToken), digest: digestMultibaseOf(vpToken), issuers: [...issuers].sort(), credentialCount: credentials.length };
}

/** The wire refusal for a failed delivery. */
export function issueRefusal(reason: IssuedCredentialRefusal | 'unsupportedFormat', internal: string): TaskError {
  if (reason === 'unsupportedFormat' || reason === 'unsupportedKind' || reason === 'ownPath') return new TaskError({ code: ISSUE_UNSUPPORTED_FORMAT, retryable: false, internalMessage: internal });
  if (reason === 'malformed') return new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: internal });
  if (reason === 'issuerNotSender' || reason === 'subjectNotHolder') return new TaskError({ code: 'permissionDenied', retryable: false, internalMessage: internal });
  return new TaskError({ reason: 'vcInvalid', internalMessage: internal });
}

export function presentRefusal(reason: PresentationRefusal, internal: string): TaskError {
  switch (reason) {
    case 'staleNonce': return new TaskError({ code: PRESENT_STALE_NONCE, retryable: false, internalMessage: internal });
    case 'audienceMismatch': return new TaskError({ code: PRESENT_AUDIENCE_MISMATCH, retryable: false, internalMessage: internal });
    case 'holderNotSender': return new TaskError({ code: 'permissionDenied', retryable: false, internalMessage: internal });
    case 'malformed': case 'unsupportedFormat': return new TaskError({ code: 'malformedRequest', retryable: false, internalMessage: internal });
    default: return new TaskError({ reason: 'vcInvalid', internalMessage: internal });
  }
}
