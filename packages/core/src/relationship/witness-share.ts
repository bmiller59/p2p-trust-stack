// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The receive check of a witness share (conformance phase P7; suite-local profile, section 4): one
 * pure function the handler and the storing participant both call, so there is a single source of
 * truth for "this bundle may be stored" (plan 2.2). Nothing here stores anything.
 *
 * What it establishes, in order (cheap structural checks first, signature checks last):
 *  - the presentation wraps exactly one credential, is signed by the sharing party's relationship
 *    DID for this exchange (holder = recorded counterparty relationship DID) as a challenge-bound
 *    proof: challenge = the exchange id, domain = `vrc:witness-share`, purpose `authentication`;
 *  - the credential's own proof verifies, independently of the evidence; its subject is the sharing
 *    party's relationship DID; its parties name both relationship DIDs of this exchange; its issuer
 *    (the witness) is not itself a party to the exchange;
 *  - the outcome-interpretability pairing (framework 4.9.3 and 4.9.4): the credential cites the
 *    initiating document (`taskContext` = its id, `taskDigestMultibase` reproduces over it, compared
 *    on decoded bytes), the terminal belongs to the same thread, is a non-error response of the type
 *    the initiating specification declares (`witness/session/submit`, same version), and carries a
 *    proof that verifies under the initiating document's RECIPIENT (the witness).
 *
 * Where the profile is silent the choices are in the P7 report; the stronger-than-reference ones are
 * marked `profile choice` below.
 */
import type { ExchangeDidRow } from '../db/repositories/vrc-exchange-dids-repo.js';
import { TRUST_TASK_ERROR_TYPE_URI, canonicalJson } from '../services/trust-tasks/boundary/runtime.js';
import { checkCitation, digestMultibaseOf } from '../services/trust-tasks/boundary/proof/digest.js';
import { WITNESS_SHARE_DOMAIN } from '../services/trust-tasks/boundary/witness-share-spec.js';

export type WitnessShareRefusal =
  | 'malformedBundle'
  | 'presentationProof'
  | 'challenge'
  | 'domain'
  | 'holder'
  | 'noCredential'
  | 'credentialProof'
  | 'witnessIsParty'
  | 'subject'
  | 'parties'
  | 'citation'
  | 'citationDigest'
  | 'initiatingType'
  | 'terminalThread'
  | 'terminalType'
  | 'terminalUnsigned'
  | 'terminalSigner'
  | 'terminalProof'
  | 'terminalCredential';

export type WitnessShareCheck =
  | { ok: false; reason: WitnessShareRefusal; detail?: string }
  | {
      ok: true;
      /** The credential as it will be stored: RFC 8785 text. */
      vwcJson: string;
      /** Multibase digest of the credential as stored. */
      digest: string;
      witnessDid: string;
      subjectDid: string;
    };

/** The boundary's `DidProofVerifier` satisfies this. */
export interface WitnessProofVerifier {
  verify(
    doc: unknown,
    context: {
      nowMs: number;
      purposes?: readonly string[];
      signerMember?: 'issuer' | 'holder' | 'credential';
      challenge?: string;
      domain?: string;
    },
  ): Promise<{ valid: boolean; failure?: string; signer?: string }>;
}

export interface WitnessShareInput {
  presentation: unknown;
  initiating: unknown;
  terminal: unknown;
}

export interface WitnessShareOptions {
  verifier: WitnessProofVerifier;
  nowMs: number;
  /** The share's `threadId` (the exchange id): the presentation challenge. */
  challenge: string;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === 'string' && v !== '';
const no = (reason: WitnessShareRefusal, detail?: string): WitnessShareCheck => ({ ok: false, reason, ...(detail === undefined ? {} : { detail }) });

const SESSION_TYPE = /^https:\/\/trusttasks\.org\/spec\/witness\/session\/(\d+\.\d+)$/;

/** The id of a DID-valued member that is a string or an object with an `id`. */
const idOf = (v: unknown): string | undefined => (str(v) ? v : isObj(v) && str(v.id) ? v.id : undefined);

/** The party DIDs a `parties` value names: strings, or objects with an `id` or `did`. */
function partiesOf(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: string[] = [];
  for (const p of v) {
    const id = str(p) ? p : isObj(p) ? (str(p.id) ? p.id : str(p.did) ? p.did : undefined) : undefined;
    if (id !== undefined) out.push(id);
  }
  return out;
}

export async function checkWitnessShare(input: WitnessShareInput, exchange: ExchangeDidRow, options: WitnessShareOptions): Promise<WitnessShareCheck> {
  const { presentation, initiating, terminal } = input;
  if (!isObj(presentation) || !isObj(initiating) || !isObj(terminal)) return no('malformedBundle');
  const sharer = exchange.remoteRelationshipDid;
  const mine = exchange.localRelationshipDid;
  if (sharer === null) return no('malformedBundle', 'the exchange has no counterparty relationship DID');

  // The credential the presentation wraps: exactly one, as an object.
  const carried = presentation.verifiableCredential;
  if (!Array.isArray(carried) || carried.length === 0) return no('noCredential');
  if (carried.length !== 1 || !isObj(carried[0])) return no('malformedBundle', 'a presentation wraps exactly one credential'); // profile choice (3.3: one-element array)
  const vwc = carried[0];

  // Subject and parties come from the credential and the cited session document (structural).
  const subject = Array.isArray(vwc.credentialSubject) ? vwc.credentialSubject[0] : vwc.credentialSubject;
  const subjectId = idOf(subject);
  if (subjectId !== sharer) return no('subject');
  const named = partiesOf(isObj(subject) && subject.parties !== undefined ? subject.parties : isObj(initiating.payload) ? initiating.payload.parties : undefined);
  if (named === undefined || !named.includes(sharer) || !named.includes(mine)) return no('parties');

  // The citation: top level or in the subject (both placements are read; a conflict is refused).
  const top = { taskContext: vwc.taskContext, taskDigestMultibase: vwc.taskDigestMultibase };
  const nested = isObj(subject) ? { taskContext: subject.taskContext, taskDigestMultibase: subject.taskDigestMultibase } : { taskContext: undefined, taskDigestMultibase: undefined };
  const useTop = top.taskContext !== undefined || top.taskDigestMultibase !== undefined;
  if (useTop && (nested.taskContext !== undefined || nested.taskDigestMultibase !== undefined) && (nested.taskContext !== top.taskContext || nested.taskDigestMultibase !== top.taskDigestMultibase)) {
    return no('citation', 'the two placements of the citation differ'); // profile choice
  }
  const cite = useTop ? top : nested;
  if (!str(cite.taskContext) || !str(cite.taskDigestMultibase)) return no('citation');
  const cited = checkCitation(initiating, cite);
  if (!cited.ok) return no(cited.reason === 'contextMismatch' || cited.reason === 'malformedCitation' ? 'citation' : 'citationDigest', cited.reason);

  // The terminal belongs to the initiating document (cheap checks first).
  const initiatingThread = str(initiating.threadId) ? initiating.threadId : initiating.id;
  if (!str(initiatingThread) || terminal.threadId !== initiatingThread) return no('terminalThread');
  const sessionVersion = typeof initiating.type === 'string' ? SESSION_TYPE.exec(initiating.type)?.[1] : undefined;
  if (sessionVersion === undefined) return no('initiatingType', 'the initiating document is not a witness session');
  if (typeof terminal.type !== 'string' || terminal.type === TRUST_TASK_ERROR_TYPE_URI || !terminal.type.endsWith('#response')) return no('terminalType');
  // Framework 4.9.4 item 3: the type the initiating specification declares as its outcome evidence.
  if (terminal.type !== `https://trusttasks.org/spec/witness/session/submit/${sessionVersion}#response`) return no('terminalType', 'not the declared outcome evidence type');
  if (!isObj(terminal.proof)) return no('terminalUnsigned');
  // Framework 4.9.4 item 4: signed by the initiating document's recipient (the witness), not merely by its own issuer.
  if (!str(initiating.recipient) || terminal.issuer !== initiating.recipient) return no('terminalSigner');

  const witness = idOf(vwc.issuer);
  if (witness === undefined) return no('credentialProof', 'no credential issuer');
  if (witness === sharer || witness === mine || witness === exchange.localConnectionDid || witness === exchange.remoteConnectionDid) {
    return no('witnessIsParty'); // profile choice: a party cannot witness its own exchange
  }

  // The terminal's delivered credential, where it carries one, is the presented credential (4.9.4 binding). Profile choice: absence is not refused.
  const delivered = isObj(terminal.payload) ? terminal.payload.vwc : undefined;
  if (delivered !== undefined && (!isObj(delivered) || digestMultibaseOf(delivered) !== digestMultibaseOf(vwc))) return no('terminalCredential');

  // Signatures (these may resolve keys; an unresolvable identifier throws `unavailable`, never a verdict).
  const nowMs = options.nowMs;
  const vp = await options.verifier.verify(presentation, { nowMs, purposes: ['authentication'], signerMember: 'holder', challenge: options.challenge, domain: WITNESS_SHARE_DOMAIN });
  if (!vp.valid) {
    return no(vp.failure === 'challengeMismatch' ? 'challenge' : vp.failure === 'domainMismatch' ? 'domain' : 'presentationProof', vp.failure);
  }
  if (vp.signer !== sharer || presentation.holder !== sharer) return no('holder');

  const cred = await options.verifier.verify(vwc, { nowMs, purposes: ['assertionMethod'], signerMember: 'credential' });
  if (!cred.valid) return no('credentialProof', cred.failure);

  const term = await options.verifier.verify(terminal, { nowMs });
  if (!term.valid) return no('terminalProof', term.failure);
  if (term.signer !== initiating.recipient) return no('terminalSigner');

  return { ok: true, vwcJson: canonicalJson(vwc), digest: digestMultibaseOf(vwc), witnessDid: witness, subjectDid: sharer };
}
