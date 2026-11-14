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

export interface Capabilities {
  name: string;
  version: string;
  /** Highest tier the implementation claims. */
  tierMax: 1 | 2;
  bindings: string[];
  supportedTypes: string[];
  carriers: CarrierDecl[];
  cryptosuites: string[];
  /** control, idempotencyKey, restart, trigger.consent, clock, proofVerify */
  optional: string[];
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

export interface SendParams {
  from: SendFrom;
  /** Document text exactly as it goes on the wire. */
  bytes: string;
  channel?: string;
}

export interface SendResult {
  /** Reply documents emitted, as text, in order. */
  replies: string[];
  transport: { status?: number; kind: TransportKind };
  quiescentAfterMs: number;
}

export type ObserveQuery =
  | { query: "handled" }
  | { query: "documentState"; id: string }
  | { query: "stored"; kind: string; digest?: string };

export interface ObserveResult {
  /** `handled`/`stored`: a count. `documentState`: unknown | accepted | responded | errored. */
  value: number | string;
}

export interface ProofVerifyResult {
  valid: boolean;
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
}

export const RPC_METHODS = [
  "capabilities", "provision", "trust", "setClock", "advance", "send", "trigger",
  "observe", "restart", "reset", "snapshot", "diff", "verifyProof",
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
