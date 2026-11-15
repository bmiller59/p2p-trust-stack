// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

// Adapter contract for the DTGWG trust conformance suite (dtgwg-trust-conformance, docs/04-suite-design.md
// section 4, src/adapter/contract.ts), reproduced here as types so the in-process adapter can be checked
// against it without a cross-repository dependency. The suite is licensed Apache-2.0. When the suite
// contract changes, update this file by hand and bump the adapter.
export type TransportKind = "document" | "none" | "refused";

export interface CarrierDecl {
  typeUri: string;
  class: "consequential" | "read" | "fire-and-forget";
  /** A valid request payload, so generic vectors can use the carrier. */
  validPayload: Record<string, unknown>;
}

/** The ceremony-document family (suite docs/04 section 11.4): payload templates may use `$A` and `$X`, the two administrators. */
export interface CeremonyDecl {
  beginType: string;
  approveType: string;
  resetType: string;
  statusType?: string;
  /** Request payload template of the status task; declared together with `statusType`. */
  statusPayload?: Record<string, unknown>;
  /** Whether a begin records the proposer's approval (suite docs/04 section 11.4). Required. */
  proposerApproves: boolean;
  beginPayload: Record<string, unknown>;
  approvePayload: Record<string, unknown>;
  resetPayload: Record<string, unknown>;
}

export interface Capabilities {
  name: string;
  /** The implementation these capabilities belong to when `name` also names a mode (for example `x-attested`); runs that share it are merged into one matrix row. Default: `name`. */
  implementation?: string;
  version: string;
  /** Highest tier the implementation claims. */
  tierMax: 1 | 2;
  bindings: string[];
  supportedTypes: string[];
  carriers: CarrierDecl[];
  cryptosuites: string[];
  /** control, idempotencyKey, restart, trigger.consent, trigger.twoPhase, ceremony, ceremony.status, trigger.ceremonyDeadline, trigger.ceremonyEffect, observe.retained, fault.claimStore, discovery.acceptanceWindow, discovery.expiryHorizon, binding.requireBearer, clock (or clockFree; exactly one), proofVerify, receiptVerify, attested */
  optional: string[];
  /** Present with the optional capability `ceremony`. */
  ceremony?: CeremonyDecl;
  /** The acceptance window the implementation enforces and advertises, in whole seconds (suite docs/04 section 6); absent means the profile pins. */
  window?: { maxAgeSeconds: number; clockSkewSeconds: number; expiryHorizonSeconds: number };
  pins: { framework: string; error: string; binding: string };
}

export interface ProvisionedRole {
  vid: string;
  didDocument?: unknown;
  transportAddress: string;
  keyCustody: "iut" | "harness";
}

/** The authenticated transport identity of the sender: a harness actor, nobody, or a spoofed identity. */
export type SendFrom = { kind: "actor"; vid: string } | { kind: "none" } | { kind: "spoof"; vid: string };

/**
 * HTTPS binding request line (bindings/https/0.3 section 2). Present only when the vector exercises the binding and the adapter
 * declares `https`; absent means the default `POST /trust-tasks` with `Content-Type: application/json`. The sender identity is
 * `from` (the adapter presents the bearer token it holds for that identity; `none` sends no Authorization header).
 */
export interface HttpRequestLine {
  method?: string;
  path?: string;
  contentType?: string;
}

export interface SendParams {
  from: SendFrom;
  /** Document text exactly as it goes on the wire. */
  bytes: string;
  channel?: string;
  http?: HttpRequestLine;
}

export interface SendResult {
  /** Reply documents emitted, as text, in order. */
  replies: string[];
  /** `status` and `contentType` are reported by adapters that declare the `https` binding and were given `http`. */
  transport: { status?: number; kind: TransportKind; contentType?: string };
  quiescentAfterMs: number;
}

export type ObserveQuery =
  | { query: "handled" }
  | { query: "documentState"; id: string }
  | { query: "stored"; kind: string; digest?: string }
  | { query: "retained"; id: string; side: "request" | "reply" };

export interface ObserveResult {
  /** `handled`/`stored`: a count. `documentState`: unknown | accepted | responded | errored. */
  value: number | string;
}

export interface ProofVerifyResult {
  valid: boolean;
}

/**
 * Helper layer (optional capability `receiptVerify`, vector group RCPT): the verifier rules of `trust-ceremony-receipt` 0.1 have no wire
 * output, so the receipt vectors hand a verifier the receipt and what it holds and ask for its verdict. Pure: it changes no state.
 */
export interface VerifyReceiptParams {
  /** The receipt document text, exactly as received. */
  receipt: string;
  /** The ceremony definition the verifier resolved for `payload.definition`. Absent or null: it could not be resolved. */
  definition?: Record<string, unknown> | null;
  /** The enactment's role bindings, role name to the VIDs bound to it. Absent or null: not available to the verifier. */
  roleBindings?: Record<string, string[]> | null;
  /** The step documents the verifier holds, each exactly as received. Absent or empty: it holds none. */
  steps?: string[];
}

/** `complete`, `incomplete` (verified but the steps do not satisfy the rule, or are a prefix), `unverifiable` (could not check), `invalid` (rejected). */
export type ReceiptOutcome = 'complete' | 'incomplete' | 'unverifiable' | 'invalid';
export interface VerifyReceiptResult {
  outcome: ReceiptOutcome;
  reason?: string;
}

export interface Adapter {
  capabilities(): Promise<Capabilities>;
  provision(roles: string[]): Promise<Record<string, ProvisionedRole>>;
  trust(vid: string, didDocument?: unknown): Promise<void>;
  setClock(iso: string): Promise<void>;
  advance(ms: number): Promise<void>;
  send(params: SendParams): Promise<SendResult>;
  trigger(action: string, args: Record<string, unknown>): Promise<{ documents: string[] }>;
  observe(query: ObserveQuery): Promise<ObserveResult>;
  restart(): Promise<void>;
  reset(): Promise<void>;
  snapshot(): Promise<string>;
  diff(snapshotId: string): Promise<{ changed: boolean; detail?: string }>;
  /** Helper layer (optional capability `proofVerify`): verify a proof on bytes as received. */
  verifyProof(params: { bytes: string }): Promise<ProofVerifyResult>;
  /** Helper layer (optional capability `receiptVerify`): verify a `trust-ceremony-receipt` against what the verifier holds. */
  verifyReceipt?(params: VerifyReceiptParams): Promise<VerifyReceiptResult>;
}

export const RPC_METHODS = [
  "capabilities", "provision", "trust", "setClock", "advance", "send", "trigger",
  "observe", "restart", "reset", "snapshot", "diff", "verifyProof", "verifyReceipt",
] as const;

export interface RpcRequest {
  jsonrpc: "2.0";
  id: number | string | null;
  method: string;
  params?: unknown;
}

export type RpcResponse =
  | { jsonrpc: "2.0"; id: number | string | null; result: unknown }
  | { jsonrpc: "2.0"; id: number | string | null; error: { code: number; message: string } };
