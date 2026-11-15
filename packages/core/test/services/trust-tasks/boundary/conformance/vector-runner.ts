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
import { signDocument } from "../../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import type { BoundarySigner } from "../../../../../src/services/trust-tasks/boundary/proof/signer.ts";
import type { DidProofVerifier } from "../../../../../src/services/trust-tasks/boundary/proof/verify.ts";

export const VECTORS_DIR = join(import.meta.dirname, "..", "vectors");

const ERROR_PREFIX = "https://trusttasks.org/spec/trust-task-error/";
const ERROR_TYPE = `${ERROR_PREFIX}0.6`;
const CONTROL_TYPE = "https://trusttasks.org/spec/trust-task-control/0.1";

export interface VectorStep {
  at?: string;
  /** Absolute instant for this step (DUP window-edge vectors). */
  atAbsolute?: string;
  send?: {
    template?: string;
    /** Verbatim bytes (the shared-fixture vectors) and the substitutions applied to them. */
    raw?: string;
    substitute?: Record<string, string>;
    /** `previous`: resend the previous step's document. */
    same?: string;
    params?: Record<string, unknown>;
    /** `null` means unsigned; the in-process adapter never verifies a proof, so it is ignored. */
    sign?: unknown;
    from?: string | { spoof: string };
    mutate?: { op: string; bytes?: number; path?: string; value?: unknown; afterSign?: boolean }[];
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
  /**
   * Signing identities of the suite's actors (A, X). When present, a `carrier.request` is signed as A
   * unless the step says `sign: null` (the suite's default), and replies are checked as signed at Tier 2.
   */
  keys?: { A: BoundarySigner; X: BoundarySigner };
  /** Verifier for the Tier 2 reply checks (signed by the IUT, purpose, whole seconds). */
  replyVerifier?: DidProofVerifier;
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

const WHOLE_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/** Tier 2 reply checks: signed by the IUT under authentication, verifiable under the request's recipient, whole-second times. */
export async function validateSignedReply(text: string, request: Record<string, unknown>, env: Env, nowMs: number): Promise<string[]> {
  const errs: string[] = [];
  const r = parse(text);
  if (r === undefined) return ["reply is not a JSON object"];
  if (!isObject(r.proof)) return ["reply is not signed (proof on every response and error)"];
  if (r.issuer !== request.recipient) errs.push("reply is issued by an identifier other than the request's recipient (RSP-005)");
  if (r.proof.proofPurpose !== "authentication") errs.push(`reply proofPurpose is ${String(r.proof.proofPurpose)}, expected authentication`);
  for (const [name, v] of [["issuedAt", r.issuedAt], ["proof.created", r.proof.created], ["expiresAt", r.expiresAt]] as const) {
    if (v !== undefined && !(typeof v === "string" && WHOLE_SECOND.test(v))) errs.push(`${name} is not a whole-second UTC timestamp: ${String(v)}`);
  }
  const verdict = await env.replyVerifier!.verify(r, { nowMs });
  if (!verdict.valid) errs.push(`reply proof does not verify: ${verdict.failure ?? ""} ${verdict.detail ?? ""}`);
  else if (verdict.signer !== request.recipient) errs.push("reply proof does not verify under the request's recipient (RSP-005)");
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
  let previous: { doc: Record<string, unknown> | undefined; replies: string[] } | undefined;
  for (const [i, step] of vector.steps.entries()) {
    const label = `step ${i + 1}`;
    try {
      if (step.at !== undefined) at = offsetMs(step.at);
      const nowMs = step.atAbsolute !== undefined ? Date.parse(step.atAbsolute) : start + at;
      await adapter.setClock(new Date(nowMs).toISOString());
      const send = step.send;
      if (send === undefined) throw new Error("unsupported step: no send");
      let doc: Record<string, unknown>;
      let bytes: string;
      if (send.raw !== undefined) {
        bytes = send.raw;
        for (const [from, to] of Object.entries(send.substitute ?? {})) bytes = bytes.split(from).join(substitute(to, vector.id, env, nowMs) as string);
        doc = parse(bytes) ?? {};
      } else if (send.same === "previous") {
        if (previous?.doc === undefined) throw new Error("same: previous has no document");
        if (isObject(send.sign) && send.sign.created !== undefined) throw new Error("unsupported step: a re-signed resend needs the signer (attestation phase)");
        doc = structuredClone(previous.doc);
        for (const m of send.mutate ?? []) {
          if (m.op === "set") {
            const segs = m.path!.split("/").slice(1);
            let cur: Record<string, unknown> = doc;
            for (const seg of segs.slice(0, -1)) cur = cur[seg] as Record<string, unknown>;
            cur[segs[segs.length - 1]!] = substitute(m.value, vector.id, env, nowMs);
          } else if (m.op !== "reorder") throw new Error(`unsupported mutation ${m.op}`);
        }
        const reorder = (send.mutate ?? []).some((m) => m.op === "reorder");
        bytes = reorder ? JSON.stringify(Object.fromEntries(Object.entries(doc).reverse()), null, 2) : JSON.stringify(doc);
      } else {
        if (send.template === undefined) throw new Error("unsupported step: only template, raw and same sends are implemented");
        doc = substitute(template(send.template, env), vector.id, env, nowMs) as Record<string, unknown>;
        for (const [k, v] of Object.entries(send.params ?? {})) {
          if (isObject(v) && v["$omit"] === true) delete doc[k];
          else doc[k] = substitute(v, vector.id, env, nowMs);
        }
        const setAt = (target: Record<string, unknown>, path: string, value: unknown): void => {
          const segs = path.split("/").slice(1);
          let cur: Record<string, unknown> = target;
          for (const seg of segs.slice(0, -1)) cur = cur[seg] as Record<string, unknown>;
          cur[segs[segs.length - 1]!] = substitute(value, vector.id, env, nowMs);
        };
        for (const m of (send.mutate ?? []).filter((x) => x.op === "set" && x.afterSign !== true)) setAt(doc, m.path!, m.value);
        if (env.keys !== undefined && send.sign !== null) {
          const how = isObject(send.sign) ? send.sign : {};
          const who = how.as === "X" ? env.keys.X : env.keys.A;
          const created = typeof how.created === "string" ? nowMs + offsetMs(how.created) : nowMs;
          doc = signDocument(doc, who, { created, ...(typeof how.purpose === "string" ? { purpose: how.purpose } : {}), allowIssuerMismatch: how.allowIssuerMismatch === true });
        }
        for (const m of (send.mutate ?? []).filter((x) => x.op === "set" && x.afterSign === true)) setAt(doc, m.path!, m.value);
        bytes = JSON.stringify(doc);
        for (const m of send.mutate ?? []) {
          if (m.op === "set") continue;
          if (m.op !== "truncate") throw new Error(`unsupported mutation ${m.op}`);
          bytes = bytes.slice(0, Math.max(0, bytes.length - (m.bytes ?? 1)));
        }
      }
      const from: SendParams["from"] =
        send.from === undefined ? (send.raw !== undefined ? { kind: "none" } : { kind: "actor", vid: env.senderVid })
        : typeof send.from === "object" ? { kind: "spoof", vid: send.from.spoof === "X" ? (env.otherVid ?? "did:web:x.example") : send.from.spoof }
        : send.from === "none" ? { kind: "none" }
        : (() => { throw new Error(`unsupported sender ${send.from}`); })();
      const ex = step.expect;
      if (ex === undefined) throw new Error("unsupported step: no expect");

      const handledBefore = Number((await adapter.observe({ query: "handled" })).value);
      const result = await adapter.send({ from, bytes });
      const handledAfter = Number((await adapter.observe({ query: "handled" })).value);
      const prevReplies = previous?.replies;
      previous = { doc, replies: result.replies };
      for (const reply of result.replies) for (const e of validateReply(reply, doc, env, from.kind === "none" ? undefined : from.vid)) failures.push(`${label}: ${e}`);
      if (vector.tier === 2 && env.replyVerifier !== undefined) {
        for (const reply of result.replies) for (const e of await validateSignedReply(reply, doc, env, nowMs)) failures.push(`${label}: ${e}`);
      }

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
        case "duplicate": {
          // Absorbed, never an error, never executed again; a reply, if any, is the prior reply (7.2 item 11).
          if (result.replies.length > 1) failures.push(`${label}: duplicate produced several replies`);
          if (result.replies.length === 1) {
            if (typeOf.startsWith(ERROR_PREFIX)) failures.push(`${label}: a duplicate was reported as an error (${String((first!.payload as Record<string, unknown>).code)})`);
            else if (prevReplies === undefined || !prevReplies.some((p) => canonicalJson(parse(p) as never) === canonicalJson(first as never))) failures.push(`${label}: duplicate reply is not the prior reply`);
          }
          if (handledAfter !== handledBefore) failures.push(`${label}: a duplicate was executed again`);
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
