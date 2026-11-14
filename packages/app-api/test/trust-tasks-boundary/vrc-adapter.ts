// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The in-process conformance adapter of phases P6 and P7, kept under its old name for the existing
 * tests. Since P8 it is the same class the JSON-RPC server runs (`conformance/adapter.ts`), configured
 * as before: a `did:key` agent identity and the issue task as the generic carrier.
 */
import { TruststackersAdapter, PASSPHRASE } from '../../conformance/adapter.ts';
import type { TruststackersAdapterOptions } from '../../conformance/adapter.ts';

export { PASSPHRASE };
export type VrcAdapterOptions = TruststackersAdapterOptions;

export class VrcBoundaryAdapter extends TruststackersAdapter {
  constructor(options: VrcAdapterOptions = {}) {
    super({ identity: 'key', carrier: 'issue', name: 'truststackers-agent-vrc-boundary', ...options });
  }
}
