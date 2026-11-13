// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * In-process adapter skeleton for the conformance suite (plan P0). It implements the suite's adapter
 * contract on top of the boundary runtime module only: the adopted library's `consumeInbound`, an
 * in-memory duplicate record, one injected clock and the `myVid` selector. It grows each phase and is
 * wrapped for JSON-RPC in P8.
 *
 * Honest by construction: it claims Tier 1 only, signs nothing, verifies no proof (a proof present is
 * refused by the interim `rejectIfPresent` policy), serves exactly the handlers it is given, and
 * answers every other type `unsupportedType`. Test code only; nothing here ships in the package.
 */
import { createHash } from "node:crypto";
import {
  InMemoryReplayGuard,
  StaticTransport,
  UnauthenticatedTransport,
  consequentialChecks,
  consumeInbound,
  selectMyVid,
} from "../../../../../src/services/trust-tasks/boundary/runtime.ts";
import type { ReplayGuard, SpecPolicy, TrustTaskDocument } from "../../../../../src/services/trust-tasks/boundary/runtime.ts";
import { TaskError, buildErrorDocument, isInboundError } from "../../../../../src/services/trust-tasks/boundary/errors.ts";
import { transition } from "../../../../../src/services/trust-tasks/boundary/lifecycle.ts";
import type { LifecycleState } from "../../../../../src/services/trust-tasks/boundary/lifecycle.ts";
import { ERROR_SPEC_VERSION, FRAMEWORK_VERSION } from "../../../../../src/services/trust-tasks/boundary/pins.ts";
import type {
  Adapter,
  Capabilities,
  CarrierDecl,
  ObserveQuery,
  ObserveResult,
  ProofVerifyResult,
  ProvisionedRole,
  SendParams,
  SendResult,
} from "./contract.ts";

/**
 * A deliberately small JSON Schema reader for the test carrier: `type`, `required`, `properties` with a
 * primitive `type`. Enough to give the adapter a real item-2 payload check; the generated policies use
 * the library's own schemas and a full validator in later phases.
 */
const tinyValidator = {
  validate(schema: unknown, payload: unknown): { ok: boolean; errors?: string[] } {
    const sc = schema as { required?: string[]; properties?: Record<string, { type?: string }> };
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return { ok: false, errors: ["payload must be an object"] };
    const p = payload as Record<string, unknown>;
    const errors: string[] = [];
    for (const k of sc.required ?? []) if (!(k in p)) errors.push(`missing ${k}`);
    for (const [k, def] of Object.entries(sc.properties ?? {})) {
      if (k in p && def.type !== undefined && typeof p[k] !== def.type) errors.push(`${k} must be ${def.type}`);
    }
    return { ok: errors.length === 0, errors };
  },
};

export interface BoundaryHandler {
  spec: SpecPolicy;
  /** Business handler; return the response document (or nothing for a fire-and-forget task). */
  handle: (doc: TrustTaskDocument<unknown>) => TrustTaskDocument<unknown> | void | Promise<TrustTaskDocument<unknown> | void>;
  carrier?: CarrierDecl;
}

export interface BoundaryAdapterOptions {
  /** Identifiers this listener serves as a recipient; the first is the default. */
  servedVids: readonly string[];
  handlers?: readonly BoundaryHandler[];
  name?: string;
}

const uuid = (seed: string): string => {
  const h = createHash("sha256").update(seed).digest("hex");
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

const isoSeconds = (ms: number): string => `${new Date(Math.floor(ms / 1000) * 1000).toISOString().slice(0, 19)}Z`;

export class BoundaryAdapter implements Adapter {
  private readonly served: readonly string[];
  private readonly handlers: Map<string, BoundaryHandler>;
  private readonly name: string;
  private nowMs: number | undefined;
  private guard: ReplayGuard = new InMemoryReplayGuard();
  private handled = 0;
  private counter = 0;
  private readonly states = new Map<string, LifecycleState>();
  private readonly snapshots = new Map<string, string>();

  constructor(options: BoundaryAdapterOptions) {
    if (options.servedVids.length === 0) throw new Error("at least one served identifier is required");
    this.served = options.servedVids;
    this.handlers = new Map((options.handlers ?? []).map((h) => [h.spec.typeUri, h]));
    this.name = options.name ?? "truststackers-boundary";
  }

  private now(): number {
    return this.nowMs ?? Date.now();
  }
  private newId(): string {
    return uuid(`${this.served[0]}:${this.counter++}`);
  }

  async capabilities(): Promise<Capabilities> {
    return {
      name: this.name,
      version: "0.0.0-p0",
      tierMax: 1,
      bindings: ["in-process"],
      supportedTypes: [...this.handlers.keys()],
      carriers: [...this.handlers.values()].flatMap((h) => (h.carrier ? [h.carrier] : [])),
      cryptosuites: [],
      optional: ["clock"],
      pins: { framework: FRAMEWORK_VERSION, error: ERROR_SPEC_VERSION, binding: "none" },
    };
  }

  async provision(roles: string[]): Promise<Record<string, ProvisionedRole>> {
    const out: Record<string, ProvisionedRole> = {};
    for (const r of roles) out[r] = { vid: this.served[0]!, transportAddress: "in-process", keyCustody: "iut" };
    return out;
  }

  async trust(): Promise<void> {
    /* no peer resolution until the verifier lands (P4) */
  }
  async setClock(iso: string): Promise<void> {
    const ms = Date.parse(iso);
    if (Number.isNaN(ms)) throw new Error(`unreadable clock value: ${iso}`);
    this.nowMs = ms;
  }
  async advance(ms: number): Promise<void> {
    this.nowMs = this.now() + ms;
  }
  async trigger(): Promise<{ documents: string[] }> {
    throw new Error("not implemented: no IUT-initiated ceremonies before P6");
  }
  async restart(): Promise<void> {
    throw new Error("not implemented: the duplicate record is in memory until P3");
  }
  async reset(): Promise<void> {
    this.guard = new InMemoryReplayGuard();
    this.handled = 0;
    this.counter = 0;
    this.states.clear();
    this.snapshots.clear();
    this.nowMs = undefined;
  }
  async snapshot(): Promise<string> {
    const id = `snap-${this.snapshots.size}`;
    this.snapshots.set(id, this.stateText());
    return id;
  }
  async diff(snapshotId: string): Promise<{ changed: boolean; detail?: string }> {
    const before = this.snapshots.get(snapshotId);
    if (before === undefined) throw new Error(`unknown snapshot: ${snapshotId}`);
    const now = this.stateText();
    return before === now ? { changed: false } : { changed: true, detail: `${before} -> ${now}` };
  }
  private stateText(): string {
    return JSON.stringify({ handled: this.handled, states: [...this.states] });
  }

  async observe(q: ObserveQuery): Promise<ObserveResult> {
    switch (q.query) {
      case "handled":
      case "stored":
        return { value: this.handled };
      case "documentState":
        return { value: this.states.get(q.id) ?? "unknown" };
    }
  }

  async verifyProof(_params: { bytes: string }): Promise<ProofVerifyResult> {
    throw new Error("not implemented: the DID-resolving verifier lands in P4");
  }

  async send(params: SendParams): Promise<SendResult> {
    const out = (replies: unknown[], kind: SendResult["transport"]["kind"] = "document"): SendResult => ({
      replies: replies.map((r) => JSON.stringify(r)),
      transport: { kind: replies.length === 0 ? "none" : kind },
      quiescentAfterMs: 0,
    });
    const clock = (): string => isoSeconds(this.now());

    let doc: TrustTaskDocument<unknown>;
    try {
      const parsed: unknown = JSON.parse(params.bytes);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("not an object");
      doc = parsed as TrustTaskDocument<unknown>;
    } catch {
      return out([]);
    }

    const type = typeof doc.type === "string" ? doc.type : "";
    // An inbound error is never answered (no error loops) and changes the state of nothing.
    if (isInboundError(doc)) return out([]);

    const handler = this.handlers.get(type.split("#")[0]!);
    if (handler === undefined) {
      if (typeof doc.id !== "string" || type === "") return out([]);
      return out([buildErrorDocument(doc, new TaskError({ code: "unsupportedType" }), { newId: () => this.newId(), now: clock })]);
    }

    const transport = params.from.kind === "none" ? new UnauthenticatedTransport() : new StaticTransport({ issuer: params.from.vid });
    let outcome: Awaited<ReturnType<typeof consumeInbound>>;
    try {
      outcome = await consumeInbound({
        transport,
        spec: handler.spec,
        proofPolicy: { kind: "rejectIfPresent" },
        payloadPolicy: { kind: "validate", validate: tinyValidator },
        checks: consequentialChecks(this.guard),
        doc,
        myVid: selectMyVid(doc, this.served, this.served[0]!),
        now: this.now(),
        newErrorId: () => this.newId(),
        clock,
        handler: async (accepted) => {
          this.handled++;
          let state: LifecycleState = transition("validated", "accepted");
          this.states.set(accepted.id, state);
          state = transition(state, "executing");
          this.states.set(accepted.id, state);
          try {
            const response = (await handler.handle(accepted as TrustTaskDocument<unknown>)) as TrustTaskDocument<unknown> | void;
            this.states.set(accepted.id, transition(state, "responded"));
            return response;
          } catch (err) {
            this.states.set(accepted.id, transition(state, "errored"));
            throw err;
          }
        },
      });
    } catch (err) {
      // Catch-all: whatever a handler throws reaches the wire as a typed error, opaque unless it is a TaskError.
      return out([buildErrorDocument(doc, err, { newId: () => this.newId(), now: clock })]);
    }

    switch (outcome.kind) {
      case "handled":
        return out([outcome.response]);
      case "accepted":
      case "suppressed":
        return out([]);
      case "duplicate":
        return out(outcome.priorResponse === undefined ? [] : [outcome.priorResponse]);
      case "rejected":
        return out([outcome.error]);
    }
  }
}
