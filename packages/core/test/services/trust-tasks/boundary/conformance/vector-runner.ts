// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * A small vector runner for the framework groups the boundary serves so far (ERR, LIF, RSP; the
 * `carrier.request`, `error.inbound` and `control.cancel` templates, `$`-tokens, `params`, and the
 * `response` / `error` / `silence` dispositions with `code`, `retryable`, `pointer`, `noSideEffect`
 * and `state`). It follows the suite's own runner (dtgwg-trust-conformance, src/runner) for those
 * features and reports anything else as unsupported rather than passing it. Test code only; P8
 * replaces it with the suite's runner driving the JSON-RPC adapter.
 *
 * The suite's generic reply validators that apply at Tier 1 are applied to every reply: threading,
 * addressing, error shape, bounded `details`.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalJson } from "../../../../../src/services/trust-tasks/boundary/runtime.ts";
import type { Adapter, SendParams } from "./contract.ts";

export const VECTORS_DIR = join(import.meta.dirname, "..", "vectors");

const ERROR_PREFIX = "https://trusttasks.org/spec/trust-task-error/";
const ERROR_TYPE = `${ERROR_PREFIX}0.6`;
const CONTROL_TYPE = "https://trusttasks.org/spec/trust-task-control/0.1";

export interface VectorStep {
  at?: string;
  send?: {
    template?: string;
    params?: Record<string, unknown>;
    /** `null` means unsigned; the in-process adapter never verifies a proof, so it is ignored. */
    sign?: unknown;
    from?: string | { spoof: string };
    mutate?: { op: string; bytes?: number }[];
    [k: string]: unknown;
  };
  expect?: {
    disposition: string;
    code?: string | string[];
    retryable?: boolean;
    pointer?: Record<string, unknown>;
    noSideEffect?: boolean;
    state?: { handled?: number; documentState?: Record<string, string> };
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

export interface Vector {
  id: string;
  title: string;
  tier: 1 | 2;
  clarify: string | null;
  /** Per-vector clock start; overrides the file's. */
  clockStart?: string;
  requires?: string[];
  skipIfOptional?: string[];
  steps: VectorStep[];
}

export interface VectorFile {
  format: string;
  group: string;
  clock: { start: string };
  vectors: Vector[];
}

export function loadVectorFile(name: string): VectorFile {
  return JSON.parse(readFileSync(join(VECTORS_DIR, name), "utf8")) as VectorFile;
}

export function allVectors(names: readonly string[] = ["err.json", "lif.json", "rsp.json"]): { file: VectorFile; vector: Vector }[] {
  return names.flatMap((n) => {
    const file = loadVectorFile(n);
    return file.vectors.map((vector) => ({ file, vector }));
  });
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function parse(text: string): Record<string, unknown> | undefined {
  try {
    const v: unknown = JSON.parse(text);
    return isObject(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

export function deterministicId(vectorId: string, name: string): string {
  const h = createHash("sha256").update(`${vectorId}/${name}`).digest("hex");
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function offsetMs(text: string): number {
  const m = /^([+-])(\d+)(ms|s|m|h)$/.exec(text);
  if (m === null) throw new Error(`bad offset ${text}`);
  const unit = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 }[m[3] as "ms" | "s" | "m" | "h"];
  return (m[1] === "-" ? -1 : 1) * Number(m[2]) * unit;
}

const isoMs = (ms: number): string => {
  const s = new Date(ms).toISOString();
  return s.endsWith(".000Z") ? `${s.slice(0, -5)}Z` : s;
};

export interface Env {
  iutVid: string;
  senderVid: string;
  /** The suite's actor X: a second identity, used for `$X` and for spoofing. */
  otherVid?: string;
  carrier: string;
  carrierPayload: Record<string, unknown>;
  clockStart: string;
}

function substitute(value: unknown, vectorId: string, env: Env, nowMs: number): unknown {
  if (typeof value === "string") {
    if (!value.startsWith("$")) return value;
    if (value === "$iut") return env.iutVid;
    if (value === "$A") return env.senderVid;
    if (value === "$X") return env.otherVid ?? "did:web:x.example";
    if (value === "$carrier") return env.carrier;
    if (value === "$carrierResponse") return `${env.carrier}#response`;
    const id = /^\$id\(([^)]+)\)$/.exec(value);
    if (id !== null) return deterministicId(vectorId, id[1]!);
    const now = /^\$now([+-]\d+(?:ms|s|m|h))$/.exec(value);
    if (now !== null) return isoMs(nowMs + offsetMs(now[1]!));
    throw new Error(`unsupported token ${value}`);
  }
  if (Array.isArray(value)) return value.map((v) => substitute(v, vectorId, env, nowMs));
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substitute(v, vectorId, env, nowMs)]));
  return value;
}

function template(name: string, env: Env): Record<string, unknown> {
  switch (name) {
    case "carrier.request":
      return { id: "$id(req)", type: "$carrier", issuer: "$A", recipient: "$iut", issuedAt: "$now+0s", payload: { ...env.carrierPayload } };
    case "error.inbound":
      return {
        id: "$id(err)", threadId: "$id(req)", type: ERROR_TYPE, issuer: "$A", recipient: "$iut", issuedAt: "$now+0s",
        payload: { code: "taskFailed", message: "failed", retryable: false, inResponseTo: { typeUri: "$carrier", id: "$id(req)" } },
      };
    case "control.cancel":
      return {
        id: "$id(ctl)", type: CONTROL_TYPE, issuer: "$A", recipient: "$iut", issuedAt: "$now+0s",
        payload: { operation: "cancel", target: { id: "$id(req)" } },
      };
    default:
      throw new Error(`unsupported template ${name}`);
  }
}

function pointer(root: unknown, ptr: string): unknown {
  let cur: unknown = root;
  for (const seg of ptr.split("/").slice(1).map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"))) {
    cur = isObject(cur) ? cur[seg] : undefined;
  }
  return cur;
}

/** The suite's generic Tier 1 reply checks (threading, addressing, error shape, bounded details, no leak). */
export function validateReply(text: string, request: Record<string, unknown> | undefined, env: Env, sender: string = env.senderVid): string[] {
  const errs: string[] = [];
  const r = parse(text);
  if (r === undefined) return ["reply is not a JSON object"];
  if (typeof r.id !== "string" || r.id === "") errs.push("reply has no string id");
  if (typeof r.type !== "string") errs.push("reply has no string type");
  if (!isObject(r.payload)) errs.push("reply payload is not an object");
  const type = typeof r.type === "string" ? r.type : "";
  const isError = type.startsWith(ERROR_PREFIX);
  if (request !== undefined && typeof request.id === "string") {
    if (r.id === request.id) errs.push("reply id equals the request id");
    const thread = typeof request.threadId === "string" ? request.threadId : request.id;
    if (r.threadId !== thread) errs.push(`reply threadId ${String(r.threadId)} != ${thread}`);
  }
  if (r.issuer !== env.iutVid) errs.push(`reply issuer ${String(r.issuer)} is not the IUT`);
  const code = isObject(r.payload) ? r.payload.code : undefined;
  if (request !== undefined) {
    if (isError && code === "identityMismatch") {
      if (r.recipient !== sender) errs.push("identityMismatch reply is not addressed to the transport sender");
    } else if (typeof request.issuer === "string" && r.recipient !== request.issuer) errs.push("reply is not addressed to the request issuer");
    if (!isError && typeof request.type === "string" && type !== `${request.type.split("#")[0]}#response`) errs.push(`reply type ${type} is not the request's #response`);
  }
  if (isError && isObject(r.payload)) {
    const p = r.payload;
    if (typeof p.code !== "string") errs.push("error code is not a string");
    if (typeof p.retryable !== "boolean") errs.push("error retryable is not a boolean (framework 8.2 MUST)");
    if (p.message !== undefined && typeof p.message !== "string") errs.push("error message is not a string");
    if (p.details !== undefined) {
      if (!isObject(p.details)) errs.push("details is not an object");
      else {
        if (Object.keys(p.details).length > 16) errs.push("details has more than 16 members (8.2.2)");
        if (Buffer.byteLength(canonicalJson(p.details), "utf8") > 4096) errs.push("details exceeds 4096 bytes (8.2.2)");
      }
    }
    if (code === "identityMismatch" && typeof p.message === "string") {
      for (const leaked of [sender, request === undefined ? undefined : request.issuer]) {
        if (typeof leaked === "string" && p.message.includes(leaked)) errs.push("identityMismatch message leaks an identity (8.2.1)");
      }
    }
    if (request !== undefined && isObject(p.inResponseTo)) {
      if (p.inResponseTo.typeUri !== request.type) errs.push("inResponseTo.typeUri does not name the request type");
      if (code === "identityMismatch" && p.inResponseTo.id !== undefined) errs.push("identityMismatch echoes inResponseTo.id (8.2)");
    }
  }
  return errs;
}

export interface Outcome {
  pass: boolean;
  failures: string[];
}

export async function runVector(adapter: Adapter, file: VectorFile, vector: Vector, env: Env): Promise<Outcome> {
  const failures: string[] = [];
  await adapter.reset();
  const start = Date.parse(vector.clockStart ?? file.clock.start);
  let at = 0;
  for (const [i, step] of vector.steps.entries()) {
    const label = `step ${i + 1}`;
    try {
      if (step.at !== undefined) at = offsetMs(step.at);
      const nowMs = start + at;
      await adapter.setClock(new Date(nowMs).toISOString());
      const send = step.send;
      if (send?.template === undefined) throw new Error("unsupported step: only template sends are implemented");
      const doc = substitute(template(send.template, env), vector.id, env, nowMs) as Record<string, unknown>;
      for (const [k, v] of Object.entries(send.params ?? {})) {
        if (isObject(v) && v["$omit"] === true) delete doc[k];
        else doc[k] = substitute(v, vector.id, env, nowMs);
      }
      let bytes = JSON.stringify(doc);
      for (const m of send.mutate ?? []) {
        if (m.op !== "truncate") throw new Error(`unsupported mutation ${m.op}`);
        bytes = bytes.slice(0, Math.max(0, bytes.length - (m.bytes ?? 1)));
      }
      const from: SendParams["from"] =
        send.from === undefined ? { kind: "actor", vid: env.senderVid }
        : typeof send.from === "object" ? { kind: "spoof", vid: send.from.spoof === "X" ? (env.otherVid ?? "did:web:x.example") : send.from.spoof }
        : send.from === "none" ? { kind: "none" }
        : (() => { throw new Error(`unsupported sender ${send.from}`); })();
      const ex = step.expect;
      if (ex === undefined) throw new Error("unsupported step: no expect");

      const handledBefore = Number((await adapter.observe({ query: "handled" })).value);
      const result = await adapter.send({ from, bytes });
      const handledAfter = Number((await adapter.observe({ query: "handled" })).value);
      for (const reply of result.replies) for (const e of validateReply(reply, doc, env, from.kind === "none" ? undefined : from.vid)) failures.push(`${label}: ${e}`);

      const first = result.replies[0] === undefined ? undefined : parse(result.replies[0]);
      const typeOf = typeof first?.type === "string" ? first.type : "";
      switch (ex.disposition) {
        case "response": {
          if (result.replies.length !== 1) failures.push(`${label}: expected one response, got ${result.replies.length} replies`);
          else if (typeOf !== `${env.carrier}#response`) failures.push(`${label}: expected the carrier response, got ${typeOf}`);
          break;
        }
        case "error": {
          if (result.replies.length !== 1) failures.push(`${label}: expected one error, got ${result.replies.length} replies`);
          else if (!typeOf.startsWith(ERROR_PREFIX)) failures.push(`${label}: expected a trust-task-error, got ${typeOf}`);
          else {
            const codes = Array.isArray(ex.code) ? ex.code : [ex.code!];
            const payload = first!.payload as Record<string, unknown>;
            if (!codes.includes(String(payload.code))) failures.push(`${label}: expected code ${codes.join("|")}, got ${String(payload.code)}`);
            if (ex.retryable !== undefined && payload.retryable !== ex.retryable) failures.push(`${label}: expected retryable ${String(ex.retryable)}`);
          }
          break;
        }
        case "any-refusal": {
          // Refused or ignored, never executed: no response document, and (checked below) no side effect.
          if (result.replies.length > 1) failures.push(`${label}: expected a refusal, got ${result.replies.length} replies`);
          else if (result.replies.length === 1 && !typeOf.startsWith(ERROR_PREFIX)) failures.push(`${label}: expected a refusal, got ${typeOf}`);
          break;
        }
        case "silence":
          if (result.replies.length !== 0) failures.push(`${label}: expected silence, got ${result.replies.length} replies`);
          break;
        default:
          failures.push(`${label}: unsupported disposition ${ex.disposition}`);
      }
      if (ex.noSideEffect === true && handledAfter !== handledBefore) failures.push(`${label}: observable state changed (noSideEffect)`);
      if (ex.state?.handled !== undefined && handledAfter !== ex.state.handled) failures.push(`${label}: handled ${handledAfter}, expected ${ex.state.handled}`);
      for (const [k, want] of Object.entries(ex.state?.documentState ?? {})) {
        const id = substitute(k, vector.id, env, nowMs) as string;
        const got = String((await adapter.observe({ query: "documentState", id })).value);
        if (got !== want) failures.push(`${label}: documentState(${id}) = ${got}, expected ${want}`);
      }
      for (const [ptr, want] of Object.entries(ex.pointer ?? {})) {
        const wantValue = substitute(want, vector.id, env, nowMs);
        const got = first === undefined ? undefined : pointer(first, ptr);
        if (canonicalJson((got ?? null) as never) !== canonicalJson((wantValue ?? null) as never)) failures.push(`${label}: pointer ${ptr}: got ${JSON.stringify(got)}`);
      }
    } catch (err) {
      failures.push(`${label}: adapter or harness error: ${(err as Error).message}`);
    }
  }
  return { pass: failures.length === 0, failures };
}
