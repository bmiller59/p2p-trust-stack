// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Carry-forward of a did:scid:vh DID document into the next log entry (conformance gate G2, K1/K2).
 *
 * Every writer of a new log entry used to REBUILD the document from `buildDidPeer4Document`, which
 * knows only the fixed slots (`#key-1`, `#key-2`, optional `#key-scid`, `#key-mldsa`, `#key-kem`).
 * Anything else in the previous document (a dedicated `#key-boundary` method, extra services,
 * relationships) vanished at the next rotation or name claim. These helpers instead CLONE the
 * previous document and change only what the entry is meant to change.
 *
 * Slot layouts (both are preserved exactly, never converted into one another):
 *  - Slot-A (utility server): `#key-1`/`#key-2` are the permanent TSP key and its agreement key;
 *    the did:scid:vh chain follows `#key-scid`. A rotation replaces ONLY `#key-scid`.
 *  - Slot-B (agents): `#key-1` is the identity key and `#key-2` its agreement key. A rotation
 *    replaces `#key-1` and `#key-2`.
 */
import { ed25519ToX25519 } from '../crypto/primitives.js';
import type { Ed25519KeyPair } from '../crypto/primitives.js';
import { encodeEd25519Multikey, encodeMlDsa65Multikey, encodeX25519Multikey } from './create.js';
import type { DidDocument, DidParameters, ServiceEndpoint, VerificationMethod } from './types.js';

/** The fragment of the dedicated boundary-signing verification method (gate G2). */
export const BOUNDARY_VM_FRAGMENT = 'key-boundary';
/** Its identifier inside a document (relative, like every other method in these documents). */
export const BOUNDARY_VM_ID = `#${BOUNDARY_VM_FRAGMENT}`;

/** True when the document uses the Slot-A layout (a distinct `#key-scid` identity slot). */
export function hasSlotA(doc: DidDocument): boolean {
  return doc.verificationMethod.some((vm) => vm.id === '#key-scid');
}

export interface CarryForwardOptions {
  /** The DID, written to the new document's `id`. Default: the previous document's `id`. */
  id?: string;
  alsoKnownAs?: string[];
  parameters?: DidParameters;
  /** Replaces (or adds) the `#tsp` service. Omitted: the previous services are kept untouched. */
  transport?: ServiceEndpoint;
  /** When the identity has a PQ key pair the previous document lacks, publish it (appended). */
  mlDsa65PublicKey?: Uint8Array;
}

function replaceKey(vms: VerificationMethod[], id: string, publicKeyMultibase: string): void {
  const i = vms.findIndex((vm) => vm.id === id);
  if (i !== -1) vms[i] = { ...vms[i]!, publicKeyMultibase };
}

/**
 * The document of the entry that ROTATES the identity key to `newIdentityKeyPair`, carried forward
 * from `prev`: a deep clone with only the identity slot(s) replaced (see the layouts above). All
 * other verification methods, relationships, services and extra members are kept as they were.
 * Passing the current identity key (a self-commit) leaves every key as it was.
 */
export function carryForwardDocument(prev: DidDocument, newIdentityKeyPair: Ed25519KeyPair, options: CarryForwardOptions = {}): DidDocument {
  const doc = structuredClone(prev);
  if (hasSlotA(doc)) {
    replaceKey(doc.verificationMethod, '#key-scid', encodeEd25519Multikey(newIdentityKeyPair.publicKey));
  } else {
    replaceKey(doc.verificationMethod, '#key-1', encodeEd25519Multikey(newIdentityKeyPair.publicKey));
    replaceKey(doc.verificationMethod, '#key-2', encodeX25519Multikey(ed25519ToX25519(newIdentityKeyPair.secretKey).publicKey));
  }
  if (options.mlDsa65PublicKey !== undefined && !doc.verificationMethod.some((vm) => vm.id === '#key-mldsa')) {
    doc.verificationMethod.push({
      id: '#key-mldsa',
      type: 'Multikey',
      controller: '',
      publicKeyMultibase: encodeMlDsa65Multikey(options.mlDsa65PublicKey),
    });
    doc.assertionMethod = [...(doc.assertionMethod ?? []), '#key-mldsa'];
  }
  if (options.transport !== undefined) {
    const tsp = { id: '#tsp', type: 'TSPTransport', serviceEndpoint: options.transport };
    const rest = (doc.service ?? []).filter((s) => s.id !== '#tsp');
    doc.service = [tsp, ...rest];
  }
  const id = options.id ?? prev.id;
  if (id !== undefined) doc.id = id;
  if (options.alsoKnownAs !== undefined) doc.alsoKnownAs = options.alsoKnownAs;
  if (options.parameters !== undefined) doc.parameters = options.parameters;
  return doc;
}

/**
 * Append the dedicated boundary verification method to `doc` (mutates): a Multikey `#key-boundary`
 * appended AFTER every existing method (extractors read `[0]`/`[1]` by index) and listed under
 * `authentication` only. It is not an assertion, key-agreement or identity key. Throws if the
 * document already has a method of that id.
 */
export function addBoundaryVerificationMethod(doc: DidDocument, boundaryPublicKey: Uint8Array): void {
  if (doc.verificationMethod.some((vm) => vm.id === BOUNDARY_VM_ID)) {
    throw new Error(`addBoundaryVerificationMethod: ${BOUNDARY_VM_ID} is already present`);
  }
  doc.verificationMethod.push({
    id: BOUNDARY_VM_ID,
    type: 'Multikey',
    controller: '',
    publicKeyMultibase: encodeEd25519Multikey(boundaryPublicKey),
  });
  doc.authentication = [...doc.authentication, BOUNDARY_VM_ID];
}

/**
 * Problems that make `next` NOT a carry-forward of `prev` for a metadata-only update: a verification
 * method of `prev` that is missing or whose key or type changed, or a relationship entry lost. An
 * empty list means every earlier method and relationship survives (added ones are fine). `allow` names
 * method ids exempt from the check (the dedicated boundary key only, for rotation and retirement).
 */
export function carryForwardViolations(prev: DidDocument, next: DidDocument, allow: readonly string[] = []): string[] {
  const problems: string[] = [];
  for (const vm of prev.verificationMethod) {
    if (allow.includes(vm.id)) continue;
    const now = next.verificationMethod.find((v) => v.id === vm.id);
    if (now === undefined) problems.push(`verification method ${vm.id} was removed`);
    else if (now.publicKeyMultibase !== vm.publicKeyMultibase || now.type !== vm.type) problems.push(`verification method ${vm.id} was changed`);
  }
  for (const rel of ['authentication', 'assertionMethod', 'keyAgreement'] as const) {
    for (const ref of prev[rel] ?? []) {
      if (allow.includes(ref)) continue;
      if (!(next[rel] ?? []).includes(ref)) problems.push(`${ref} was dropped from ${rel}`);
    }
  }
  return problems;
}

/** Replace the key of the existing `#key-boundary` method (mutates). Throws when absent or when the key is unchanged. */
export function replaceBoundaryVerificationMethod(doc: DidDocument, boundaryPublicKey: Uint8Array): void {
  const vm = doc.verificationMethod.find((v) => v.id === BOUNDARY_VM_ID);
  if (vm === undefined) throw new Error(`replaceBoundaryVerificationMethod: ${BOUNDARY_VM_ID} is not present`);
  const encoded = encodeEd25519Multikey(boundaryPublicKey);
  if (vm.publicKeyMultibase === encoded) throw new Error(`replaceBoundaryVerificationMethod: ${BOUNDARY_VM_ID} already holds that key`);
  vm.publicKeyMultibase = encoded;
}

/** Remove the `#key-boundary` method and its `authentication` entry (mutates). Throws when absent. */
export function removeBoundaryVerificationMethod(doc: DidDocument): void {
  if (!doc.verificationMethod.some((v) => v.id === BOUNDARY_VM_ID)) throw new Error(`removeBoundaryVerificationMethod: ${BOUNDARY_VM_ID} is not present`);
  doc.verificationMethod = doc.verificationMethod.filter((v) => v.id !== BOUNDARY_VM_ID);
  doc.authentication = doc.authentication.filter((a) => a !== BOUNDARY_VM_ID);
}
