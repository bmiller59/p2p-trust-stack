// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Test support for the witness-share vectors (conformance P7): fixed parties, and a builder for a
 * conforming share bundle (presentation, credential, initiating and terminal documents) with named
 * deviations. Test code only.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import type { VrcBoundaryAdapter } from './vrc-adapter.ts';
import { taskDigestMultibase } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/digest.js';
import { createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { WITNESS_SHARE_DOMAIN } from '@p2p-trust-stack/core/services/trust-tasks/boundary/witness-share-spec.js';

/** The instant the documents are issued and signed at; `useClock` moves it (the loopback listener uses the real clock). */
export const clock = { iso: '2026-11-12T10:00:00Z', ms: Date.parse('2026-11-12T10:00:00Z') };
export const useClock = (iso: string): void => {
  clock.iso = iso;
  clock.ms = Date.parse(iso);
};
export const WS = 'https://trusttasks.org/spec/vrc/relationships/witness-share/0.1';
export const WS_URN = 'urn:p2pts:tasks:spec:vrc:witness-share:0.1';
export const PROPOSE = 'https://trusttasks.org/spec/vrc/relationships/propose/0.1';
export const SESSION = 'https://trusttasks.org/spec/witness/session/0.1';
export const SUBMIT_RESPONSE = 'https://trusttasks.org/spec/witness/session/submit/0.1#response';
export const ERROR_TYPE = 'https://trusttasks.org/spec/trust-task-error/0.1';
export const mk = (byte: number) => {
  const seed = new Uint8Array(32).fill(byte);
  const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
  return { did, signer: createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) }) };
};
export type Party = ReturnType<typeof mk>;
// A: the sharing peer's connection DID. X: another connected peer. R/S: relationship DIDs (one per exchange).
// W: the witness. Y: a second key (a non-recipient signer).
export const A = mk(0x0a), X = mk(0x0b), R = mk(0x0c), S = mk(0x0d), W = mk(0x0e), Y = mk(0x0f);
export const uid = (n: number) => `urn:uuid:dddddddd-dddd-4ddd-8ddd-${String(n).padStart(12, '0')}`;
export const sign = (who: Party, doc: Record<string, unknown>, options: Record<string, unknown> = {}) => signDocument(doc, who.signer, { created: clock.ms, ...options });
export const text = (doc: unknown) => JSON.stringify(doc);

/** Accept a proposal from A naming relationship DID `rel`; returns the IUT's relationship DID. */
export async function accepted(adapter: VrcBoundaryAdapter, thread = uid(1), rel: Party = R, peer: Party = A): Promise<string> {
  await adapter.setClock(clock.iso);
  await adapter.trigger('policy', { propose: 'accept' });
  const reply = await adapter.send({ from: { kind: 'actor', vid: peer.did }, bytes: text(sign(peer, { id: thread, threadId: thread, type: PROPOSE, issuer: peer.did, recipient: adapter.signer.did, issuedAt: clock.iso, payload: { relationshipDid: rel.did } })) });
  return JSON.parse(reply.replies[0]!).payload.relationshipDid as string;
}

export interface BundleOptions {
  sharer?: Party; // relationship DID party (default R)
  witness?: Party;
  thread?: string;
  subject?: string;
  parties?: unknown;
  challenge?: string;
  domain?: string;
  holder?: string;
  /** Mutate the initiating document AFTER the credential cited it. */
  alterInitiating?: (d: Record<string, unknown>) => void;
  citation?: (c: { taskContext: string; taskDigestMultibase: string }) => { taskContext: string; taskDigestMultibase: string };
  terminal?: (t: Record<string, unknown>) => Record<string, unknown>;
  terminalSigner?: Party;
  terminalProof?: boolean;
  nested?: boolean;
  extraPresented?: boolean;
  /** Change the credential AFTER it was signed (its own proof must then fail). */
  tamperVwc?: (v: Record<string, unknown>) => void;
}

/** A conforming bundle for the exchange whose IUT-side relationship DID is `mine`, with named deviations. */
export function bundle(mine: string, o: BundleOptions = {}) {
  const sharer = o.sharer ?? R;
  const witness = o.witness ?? W;
  const initiating = sign(sharer, {
    id: uid(500),
    threadId: uid(500),
    type: SESSION,
    issuer: sharer.did,
    recipient: witness.did,
    issuedAt: clock.iso,
    payload: { parties: [sharer.did, mine] },
  });
  let cite = { taskContext: initiating.id as string, taskDigestMultibase: taskDigestMultibase(initiating) };
  if (o.citation) cite = o.citation(cite);
  const subject = { id: o.subject ?? sharer.did, ...(o.parties === undefined ? {} : { parties: o.parties }), ...(o.nested ? cite : {}) };
  const vwc: Record<string, unknown> = sign(
    witness,
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'VerifiableWitnessCredential'],
      issuer: witness.did,
      validFrom: clock.iso,
      ...(o.nested ? {} : cite),
      credentialSubject: subject,
    },
    { purpose: 'assertionMethod' },
  );
  o.tamperVwc?.(vwc);
  const unsignedTerminal = {
    id: uid(501),
    threadId: initiating.id,
    type: SUBMIT_RESPONSE,
    issuer: witness.did,
    recipient: sharer.did,
    issuedAt: clock.iso,
    payload: { vwc },
  };
  let terminal: Record<string, unknown> = o.terminal ? o.terminal(unsignedTerminal) : unsignedTerminal;
  const signer = o.terminalSigner ?? witness;
  terminal = sign(signer, terminal, { purpose: 'assertionMethod', allowIssuerMismatch: true });
  if (o.terminalProof === false) delete terminal.proof;
  const presentation = sign(
    sharer,
    {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: o.holder ?? sharer.did,
      verifiableCredential: [vwc, ...(o.extraPresented ? [vwc] : [])],
    },
    { purpose: 'authentication', challenge: o.challenge ?? o.thread ?? uid(1), domain: o.domain ?? WITNESS_SHARE_DOMAIN, allowIssuerMismatch: true },
  );
  const altered = structuredClone(initiating) as Record<string, unknown>;
  if (o.alterInitiating) o.alterInitiating(altered);
  return { vwc, presentation, initiating: altered, terminal };
}

export const shareDoc = (adapter: VrcBoundaryAdapter, id: string, thread: string, b: ReturnType<typeof bundle>, from: Party = A, extra: Record<string, unknown> = {}, type = WS) =>
  sign(from, {
    id,
    threadId: thread,
    type,
    issuer: A.did,
    recipient: adapter.signer.did,
    issuedAt: clock.iso,
    payload: { presentation: b.presentation, outcomeEvidence: { initiating: b.initiating, terminal: b.terminal }, ...extra },
  }, { allowIssuerMismatch: true });
