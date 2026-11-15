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
import { Pipeline } from "../../../../../src/services/trust-tasks/boundary/pipeline.ts";
import type { PipelineHandler } from "../../../../../src/services/trust-tasks/boundary/handlers.ts";
import type { Strictness } from "../../../../../src/services/trust-tasks/boundary/pipeline.ts";
import { InMemoryReplayGuard } from "../../../../../src/services/trust-tasks/boundary/runtime.ts";
import type { ReplayGuard, SpecPolicy, TrustTaskDocument } from "../../../../../src/services/trust-tasks/boundary/runtime.ts";
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
  strictness?: Strictness;
  /**
   * Builds the duplicate record. `reset` starts from empty; `restart` must see what the previous
   * instance wrote (a durable store over the same database). Default: in memory, which loses everything.
   */
  guardFactory?: (kind: "reset" | "restart") => ReplayGuard;
}

const uuid = (seed: string): string => {
  const h = createHash("sha256").update(seed).digest("hex");
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
};


export class BoundaryAdapter implements Adapter {
  private readonly served: readonly string[];
  private readonly handlers: Map<string, BoundaryHandler>;
  private readonly name: string;
  private readonly strictness: Strictness;
  private pipeline: Pipeline;
  private nowMs: number | undefined;
  private guard: ReplayGuard;
  private readonly guardFactory: (kind: "reset" | "restart") => ReplayGuard;
  private handled = 0;
  private counter = 0;
  private readonly states = new Map<string, LifecycleState>();
  private readonly snapshots = new Map<string, string>();

  constructor(options: BoundaryAdapterOptions) {
    if (options.servedVids.length === 0) throw new Error("at least one served identifier is required");
    this.served = options.servedVids;
    this.handlers = new Map((options.handlers ?? []).map((h) => [h.spec.typeUri, h]));
    this.name = options.name ?? "truststackers-boundary";
    this.strictness = options.strictness ?? "strict";
    this.guardFactory = options.guardFactory ?? (() => new InMemoryReplayGuard());
    this.guard = this.guardFactory("reset");
    this.pipeline = this.buildPipeline();
  }

  private buildPipeline(): Pipeline {
    const handlers: PipelineHandler[] = [...this.handlers.values()].map((h) => ({
      types: [h.spec.typeUri],
      spec: h.spec,
      consequential: h.carrier?.class !== "read",
      handle: async (accepted) => {
        this.handled++;
        let state: LifecycleState = transition("validated", "accepted");
        this.states.set(accepted.id, state);
        state = transition(state, "executing");
        this.states.set(accepted.id, state);
        try {
          const response = await h.handle(accepted);
          this.states.set(accepted.id, transition(state, "responded"));
          return response;
        } catch (err) {
          this.states.set(accepted.id, transition(state, "errored"));
          throw err;
        }
      },
    }));
    return new Pipeline({ handlers, servedVids: this.served, guard: this.guard, now: () => this.now(), newId: () => this.newId(), strictness: this.strictness });
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
    // A new process: the pipeline and the guard object are rebuilt; whatever the guard persisted stays,
    // the handled counter (observable state of the effects) is not touched.
    this.guard = this.guardFactory("restart");
    this.pipeline = this.buildPipeline();
  }
  async reset(): Promise<void> {
    this.guard = this.guardFactory("reset");
    this.pipeline = this.buildPipeline();
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
    const result = await this.pipeline.process({ raw: params.bytes, sender: params.from.kind === "none" ? undefined : params.from.vid });
    const replies = result.document === undefined ? [] : [JSON.stringify(result.document)];
    return { replies, transport: { status: result.status, kind: replies.length === 0 ? "none" : "document" }, quiescentAfterMs: 0 };
  }
}
