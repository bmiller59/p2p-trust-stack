// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Carry-forward of a did:scid:vh DID document into the next log entry.
 *
 * Every writer of a new log entry used to REBUILD the document from `buildDidPeer4Document`, which
 * knows only the fixed slots (`#key-1`, `#key-2`, optional `#key-scid`, `#key-mldsa`, `#key-kem`).
 * Anything else in the previous document (an added verification method, extra services,
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
