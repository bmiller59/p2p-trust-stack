// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Verifier of `trust-ceremony-receipt` 0.1: the verifier rules of the specification
 * (specs/trust-ceremony-receipt/0.1/spec.md:126-138, rules 1 to 11, and the closing paragraph :140), over data the verifier is handed:
 * the receipt text, the ceremony definition it resolved, the enactment's role bindings and the step documents it holds.
 *
 * VERIFY ONLY. Nothing here produces a receipt; the boundary has no recorder role (a recorder is a separate piece of work).
 *
 * The verdict is one of four, and the specification's distinctions are kept:
 *  - `complete`: the receipt verified, the completion rule holds over the enumerated steps, and a held terminal step document carries the
 *    signed marker (spec.md:134).
 *  - `incomplete`: it verified but the enumerated steps do not satisfy the rule, or are a prefix (no terminal step; or the held terminal
 *    document does not carry the marker).
 *  - `unverifiable`: something the verdict needs could not be checked: the definition is unresolved or does not match its digest
 *    (spec.md:129, :162), the role bindings are unavailable (:135), no terminal step document is held (:134, :140), the salt is missing
 *    or a digest names a hash function this verifier does not implement, or a key set could not be resolved right now.
 *  - `invalid`: the receipt is rejected.
 * `reason` is for people.
 *
 * Positions where the specification is silent (each is a deliberate reading; the suite's RCPT CLARIFY vectors observe them):
 *  P1 `payload.complete` disagrees with the rule: the verifier's own evaluation wins (spec.md:132), so a recorder that says
 *     "incomplete" over satisfying steps is reported `complete`; a recorder that says "complete" over unsatisfying steps is `incomplete`.
 *  P2 Hash functions: sha2-256 and sha2-512 are implemented; any other multihash is `unverifiable` (spec.md:108 fixes no minimum).
 *  P3 No salt, held documents: the digests cannot be recomputed, so `unverifiable` (schema: salt is required where steps carry prev).
 *  P4 A held step document with no proof is `invalid` (spec.md:103: each step carries its own proof; rule 11 verifies it).
 *  P5 A receipt addressed to another party, or carrying a threadId, still verifies (bearer, spec.md:152). Step threadIds are not read.
 *  P6 `parentEnactment` equal to the receipt's own enactment is `invalid` (it breaks the producer rule on the envelope member).
 *  P7 A step name the definition does not declare, a `typeUri` other than the declared type, or a round beyond `maxRounds`
 *     (default 1) is `invalid` (the schema descriptions state each check; no verifier rule does).
 *  P8 A re-presented receipt is verified again with the same verdict: the verifier keeps no state.
 *  P9 A key set that cannot be obtained right now ("could not check", not "forged") is `unverifiable`, never `invalid`.
 */
import { createHash } from 'node:crypto';
import { base58btc } from 'multiformats/bases/base58';
import { TaskError } from './errors.js';
import { decodeDigestMultibase, digestMultibaseOf } from './proof/digest.js';
import { jcsBytes } from './proof/data-integrity.js';
import type { DidProofVerifier } from './proof/verify.js';

export const CEREMONY_RECEIPT_TYPE = 'https://trusttasks.org/spec/trust-ceremony-receipt/0.1';

export type ReceiptOutcome = 'complete' | 'incomplete' | 'unverifiable' | 'invalid';

export interface ReceiptVerdict {
  readonly outcome: ReceiptOutcome;
  readonly reason: string;
}

export interface ReceiptVerifyInput {
  /** The receipt document text, as received. */
  readonly receipt: string;
  /** The definition the verifier resolved for `payload.definition`. Absent or null: it could not be resolved. */
  readonly definition?: Record<string, unknown> | null | undefined;
  /** The enactment's role bindings, role name to VIDs. Absent or null: not available to the verifier. */
  readonly roleBindings?: Record<string, readonly string[]> | null | undefined;
  /** The step documents the verifier holds, each as received. */
  readonly steps?: readonly string[] | undefined;
}

export interface ReceiptVerifyDeps {
  readonly verifier: DidProofVerifier;
  /** The instant proofs are judged at, epoch ms. */
  readonly nowMs: number;
}

// ---------------------------------------------------------------------------
// Step digest (spec.md:93-111)
// ---------------------------------------------------------------------------

/** The multihash functions implemented: sha2-256 (0x12) and sha2-512 (0x13). */
const HASHES = {
  'sha2-256': { code: 0x12, node: 'sha256', length: 32 },
  'sha2-512': { code: 0x13, node: 'sha512', length: 64 },
} as const;
export type ReceiptHash = keyof typeof HASHES;

function hashNameOfCode(code: number): ReceiptHash | undefined {
  return (Object.keys(HASHES) as ReceiptHash[]).find((k) => HASHES[k].code === code);
}

/** Decode a multibase text (base58btc `z`, base64url `u`, hex `f`); null when it is not one. */
function fromMultibase(text: string): Uint8Array | null {
  if (typeof text !== 'string' || text.length < 2) return null;
  try {
    switch (text[0]) {
      case 'z':
        return base58btc.decode(text);
      case 'u':
        return /^[A-Za-z0-9_-]+$/.test(text.slice(1)) ? new Uint8Array(Buffer.from(text.slice(1), 'base64url')) : null;
      case 'f':
        return /^(?:[0-9a-f]{2})+$/.test(text.slice(1)) ? new Uint8Array(Buffer.from(text.slice(1), 'hex')) : null;
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * `multibase( multihash( H( JCS(document) || salt ) ) )`: over the WHOLE document including its `proof`, with the decoded salt as a
 * SUFFIX. Not the task digest of SPEC.md 4.9.3 (`taskDigestMultibase`), which leaves the proof out. Null when the salt is not multibase.
 */
export function ceremonyStepDigest(document: unknown, salt: string, hash: ReceiptHash = 'sha2-256'): string | null {
  const s = fromMultibase(salt);
  if (s === null) return null;
  const h = HASHES[hash];
  const sum = createHash(h.node).update(jcsBytes(document)).update(s).digest();
  return base58btc.encode(Uint8Array.from([h.code, h.length, ...sum]));
}

/** Compare two multibase multihashes on decoded bytes (spelling-independent). */
function sameDigest(a: string, b: string): boolean {
  const x = decodeDigestMultibase(a);
  const y = decodeDigestMultibase(b);
  return x !== null && y !== null && x.code === y.code && Buffer.from(x.digest).equals(Buffer.from(y.digest));
}

// ---------------------------------------------------------------------------
// Payload shape (payload.schema.json: closed, required members, types, bounds)
// ---------------------------------------------------------------------------

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const DIGEST = /^(z[1-9A-HJ-NP-Za-km-z]+|u[A-Za-z0-9_-]+)$/;
const EXT_KEY = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/;
const URI = /^[A-Za-z][A-Za-z0-9+.-]*:\S+$/;
const STEP_MEMBERS = ['step', 'round', 'typeUri', 'issuer', 'id', 'digestMultibase', 'terminal'];
const PAYLOAD_MEMBERS = ['enactment', 'parentEnactment', 'definition', 'definitionDigest', 'complete', 'salt', 'steps', 'ext'];

/** Problems found validating a receipt payload against the schema; empty when it conforms. */
export function receiptPayloadErrors(payload: unknown): string[] {
  const errs: string[] = [];
  if (!isObject(payload)) return ['payload must be an object'];
  for (const k of Object.keys(payload)) if (!PAYLOAD_MEMBERS.includes(k)) errs.push(`unknown member ${k}`);
  for (const k of ['enactment', 'definition', 'definitionDigest', 'complete', 'steps']) if (!(k in payload)) errs.push(`missing ${k}`);
  const text = (k: string, min = 1): void => {
    if (k in payload && (typeof payload[k] !== 'string' || (payload[k] as string).length < min)) errs.push(`${k} must be a string of at least ${min} characters`);
  };
  text('enactment');
  text('parentEnactment');
  text('definition');
  if (typeof payload.definition === 'string' && !URI.test(payload.definition)) errs.push('definition must be a URI');
  text('salt', 22);
  if ('definitionDigest' in payload && (typeof payload.definitionDigest !== 'string' || payload.definitionDigest.length < 16 || !DIGEST.test(payload.definitionDigest))) {
    errs.push('definitionDigest must be a multibase multihash');
  }
  if ('complete' in payload && typeof payload.complete !== 'boolean') errs.push('complete must be a boolean');
  if ('ext' in payload && (!isObject(payload.ext) || Object.keys(payload.ext).length === 0 || Object.keys(payload.ext).some((k) => !EXT_KEY.test(k)))) {
    errs.push('ext keys must be reverse-DNS namespaces');
  }
  if ('steps' in payload) {
    if (!Array.isArray(payload.steps) || payload.steps.length < 1) errs.push('steps must have at least one entry');
    else {
      payload.steps.forEach((s: unknown, i: number) => {
        if (!isObject(s)) return void errs.push(`steps[${i}] must be an object`);
        for (const k of Object.keys(s)) if (!STEP_MEMBERS.includes(k)) errs.push(`steps[${i}]: unknown member ${k}`);
        for (const k of ['step', 'typeUri', 'issuer', 'id', 'digestMultibase']) if (!(k in s)) errs.push(`steps[${i}]: missing ${k}`);
        for (const k of ['step', 'issuer', 'id']) if (k in s && (typeof s[k] !== 'string' || s[k] === '')) errs.push(`steps[${i}].${k} must be a non-empty string`);
        if ('typeUri' in s && (typeof s.typeUri !== 'string' || !URI.test(s.typeUri))) errs.push(`steps[${i}].typeUri must be a URI`);
        if ('digestMultibase' in s && (typeof s.digestMultibase !== 'string' || s.digestMultibase.length < 16 || !DIGEST.test(s.digestMultibase))) {
          errs.push(`steps[${i}].digestMultibase must be a multibase multihash`);
        }
        if ('round' in s && (!Number.isInteger(s.round) || (s.round as number) < 1)) errs.push(`steps[${i}].round must be an integer of at least 1`);
        if ('terminal' in s && typeof s.terminal !== 'boolean') errs.push(`steps[${i}].terminal must be a boolean`);
      });
    }
  }
  return errs;
}

interface Entry {
  readonly step: string;
  readonly round: number;
  readonly typeUri: string;
  readonly issuer: string;
  readonly id: string;
  readonly digestMultibase: string;
  readonly terminal: boolean;
}

type StepDefs = Record<string, Record<string, unknown>>;

function parseObject(text: string): Record<string, unknown> | undefined {
  try {
    const v: unknown = JSON.parse(text);
    return isObject(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

/** The completion predicate (the registry's closed combinators: a step name, allOf, anyOf, threshold) over the present step instances. */
function satisfied(p: unknown, present: ReadonlyMap<string, ReadonlySet<string>>): boolean {
  if (typeof p === 'string') return (present.get(p)?.size ?? 0) > 0;
  if (!isObject(p)) return false;
  if (Array.isArray(p.allOf)) return p.allOf.every((x) => satisfied(x, present));
  if (Array.isArray(p.anyOf)) return p.anyOf.some((x) => satisfied(x, present));
  if (isObject(p.threshold)) {
    const t = p.threshold;
    const n = Number(t.n);
    if (!Number.isFinite(n)) return false;
    if (typeof t.ofStep === 'string') return (present.get(t.ofStep)?.size ?? 0) >= n;
    if (Array.isArray(t.of)) return t.of.filter((x) => satisfied(x, present)).length >= n;
  }
  return false;
}

/** Steps that are ancestors of `step` in the definition's `prev` graph. */
function ancestors(steps: StepDefs, step: string): Set<string> {
  const out = new Set<string>();
  const walk = (s: string): void => {
    for (const p of Array.isArray(steps[s]?.prev) ? (steps[s]!.prev as string[]) : []) {
      if (!out.has(p)) {
        out.add(p);
        walk(p);
      }
    }
  };
  walk(step);
  return out;
}

const done = (outcome: ReceiptOutcome, reason: string): ReceiptVerdict => ({ outcome, reason });
const invalid = (reason: string): ReceiptVerdict => done('invalid', reason);

type ProofResult = { ok: true } | { ok: false; unavailable: boolean; detail: string };

async function checkProof(deps: ReceiptVerifyDeps, doc: Record<string, unknown>): Promise<ProofResult> {
  try {
    const v = await deps.verifier.verify(doc, { nowMs: deps.nowMs });
    return v.valid ? { ok: true } : { ok: false, unavailable: false, detail: `${v.failure ?? ''} ${v.detail ?? ''}`.trim() };
  } catch (err) {
    if (err instanceof TaskError) return { ok: false, unavailable: true, detail: 'a key set could not be obtained' };
    throw err;
  }
}

/** Verify a trust-ceremony-receipt against what the verifier holds. Pure with respect to state: it stores nothing. */
export async function verifyCeremonyReceipt(input: ReceiptVerifyInput, deps: ReceiptVerifyDeps): Promise<ReceiptVerdict> {
  // Rule 1: the SPEC.md 7.2 pipeline. The type, the envelope, the payload schema, the receipt's own proof.
  const doc = parseObject(input.receipt);
  if (doc === undefined) return invalid('the receipt is not a JSON object');
  if (doc.type !== CEREMONY_RECEIPT_TYPE) return invalid(`type ${String(doc.type)} is not ${CEREMONY_RECEIPT_TYPE}`);
  if (typeof doc.id !== 'string' || doc.id === '' || !isObject(doc.payload)) return invalid('envelope: id and payload are required');
  const errs = receiptPayloadErrors(doc.payload);
  if (errs.length > 0) return invalid(`payload schema: ${errs[0]}`);
  const payload = doc.payload;
  if (payload.parentEnactment !== undefined && payload.parentEnactment === payload.enactment) return invalid("parentEnactment is the receipt's own enactment");
  const unverifiable: string[] = [];
  if (doc.proof === undefined) return invalid('proofRequired: the receipt carries no proof');
  const own = await checkProof(deps, doc);
  if (!own.ok) {
    if (!own.unavailable) return invalid(`proofInvalid: ${own.detail}`);
    unverifiable.push("the receipt's own proof could not be checked: a key set could not be obtained");
  }
  const entries: Entry[] = (payload.steps as Record<string, unknown>[]).map((s) => ({
    step: String(s.step), round: typeof s.round === 'number' ? s.round : 1, typeUri: String(s.typeUri), issuer: String(s.issuer),
    id: String(s.id), digestMultibase: String(s.digestMultibase), terminal: s.terminal === true,
  }));

  // Rule 2: resolve the definition and check its digest. Unresolved or mismatching is "could not verify", not "invalid".
  const def = input.definition;
  if (def === undefined || def === null) return done('unverifiable', 'the definition could not be resolved');
  const claimed = decodeDigestMultibase(String(payload.definitionDigest));
  if (claimed === null || claimed.code !== 0x12 || !sameDigest(digestMultibaseOf(def), String(payload.definitionDigest))) {
    return done('unverifiable', 'the resolved definition does not match definitionDigest');
  }
  const steps: StepDefs = isObject(def.steps) ? (def.steps as StepDefs) : {};

  // Rule 4 (before anything is counted): de-duplicate by document id, and by step and round (perRole: also by issuer).
  const ids = new Set<string>();
  const slots = new Set<string>();
  for (const e of entries) {
    if (ids.has(e.id)) return invalid(`document id ${e.id} is enumerated twice`);
    ids.add(e.id);
    const perRole = steps[e.step]?.multiplicity === 'perRole';
    const slot = `${e.step}|${e.round}${perRole ? `|${e.issuer}` : ''}`;
    if (slots.has(slot)) return invalid(`step ${e.step} is enumerated twice at round ${e.round}`);
    slots.add(slot);
  }
  // P7: the checks the schema descriptions imply.
  for (const e of entries) {
    const d = steps[e.step];
    if (d === undefined) return invalid(`step ${e.step} is not in the definition`);
    if (typeof d.type === 'string' && d.type !== e.typeUri) return invalid(`step ${e.step} enacted ${e.typeUri}, the definition declares ${d.type}`);
    if (e.round > (typeof d.maxRounds === 'number' ? d.maxRounds : 1)) return invalid(`step ${e.step} round ${e.round} exceeds maxRounds`);
  }

  // Rule 3: the recorder is one the definition names (roles; their VIDs come from the bindings, rule 8).
  const evidence = isObject(def.evidence) ? def.evidence : {};
  const recorderRoles = Array.isArray(evidence.recorders) ? (evidence.recorders as string[]) : [];
  const bindings = input.roleBindings;
  const bound = (role: unknown): readonly string[] => (bindings === undefined || bindings === null || typeof role !== 'string' ? [] : bindings[role] ?? []);
  if (bindings === undefined || bindings === null) {
    unverifiable.push("the enactment's role bindings are not available (the recorder)");
  } else if (!recorderRoles.some((r) => bound(r).includes(String(doc.issuer)))) {
    return invalid('the issuer is not a recorder the definition names');
  }

  // Rule 8: each enumerated step's issuer is bound to the role the definition names as that step's issuer.
  if (bindings === undefined || bindings === null) {
    unverifiable.push("the enactment's role bindings are not available (step issuers)");
  } else {
    for (const e of entries) {
      if (!bound(steps[e.step]!.issuer).includes(e.issuer)) return invalid(`step ${e.step} was issued by ${e.issuer}, which is not bound to its issuer role`);
    }
  }

  // Rules 6 and 7: the terminal step. Only steps the definition declares terminal count; the echo is the recorder's word.
  const declaredTerminal = entries.filter((e) => steps[e.step]?.terminal === true);
  if (entries.some((e) => e.terminal && steps[e.step]?.terminal !== true)) return invalid('a step the definition does not declare terminal is marked terminal');

  // Rules 9 to 11 over the documents held.
  const held = (input.steps ?? []).map((t) => parseObject(t)).filter((d): d is Record<string, unknown> => d !== undefined);
  const byId = new Map(entries.map((e) => [e.id, e]));
  const salt = typeof payload.salt === 'string' ? payload.salt : undefined;
  const heldTerminal = new Map<string, boolean>();
  for (const sd of held) {
    const e = byId.get(String(sd.id));
    if (e === undefined) continue;
    const c = isObject(sd.ceremony) ? sd.ceremony : {};
    // Rule 9: recompute the digest; enactment, definition digest, step, round and issuer agree with the receipt.
    const named = decodeDigestMultibase(e.digestMultibase);
    const hash = named === null ? undefined : hashNameOfCode(named.code);
    if (salt === undefined) unverifiable.push('no salt: the step digests cannot be recomputed');
    else if (hash === undefined) unverifiable.push(`a digest names a multihash function this verifier does not implement (${e.id})`);
    else {
      const want = ceremonyStepDigest(sd, salt, hash);
      if (want === null) unverifiable.push('the salt is not a multibase value: the step digests cannot be recomputed');
      else if (!sameDigest(want, e.digestMultibase)) return invalid(`the digest of step ${e.id} does not match the document held`);
    }
    if (c.enactment !== payload.enactment) return invalid(`step ${e.id} belongs to enactment ${String(c.enactment)}, not ${String(payload.enactment)}`);
    if (typeof c.definitionDigest !== 'string' || !sameDigest(c.definitionDigest, String(payload.definitionDigest))) return invalid(`step ${e.id} pins another definition`);
    if (c.step !== e.step || (typeof c.round === 'number' ? c.round : 1) !== e.round || sd.issuer !== e.issuer) {
      return invalid(`step ${e.id} disagrees with the receipt on step, round or issuer`);
    }
    // Rule 8 for a held document: its recipient is bound to the recipient role.
    if (bindings !== undefined && bindings !== null && !bound(steps[e.step]!.recipient).includes(String(sd.recipient))) {
      return invalid(`step ${e.id} was addressed to a party not bound to its recipient role`);
    }
    // Rule 7: the terminal marker in the document's signed content; a contradicted echo is rejected.
    if (steps[e.step]?.terminal === true) {
      const marked = c.terminal === true;
      if (e.terminal && !marked) return invalid(`step ${e.id} is echoed terminal but the document does not carry the marker`);
      heldTerminal.set(e.id, marked);
    }
    // Rule 10: walk the chain.
    if (Array.isArray(c.prev)) {
      for (const p of c.prev) {
        if (!isObject(p)) return invalid(`step ${e.id} has a malformed prev entry`);
        const pred = byId.get(String(p.id));
        if (pred === undefined) return invalid(`step ${e.id} follows ${String(p.id)}, which the receipt does not enumerate (an omitted step)`);
        if (!sameDigest(String(p.digestMultibase), pred.digestMultibase)) return invalid(`step ${e.id} commits to another digest of ${pred.id} than the receipt does`);
        if (!(ancestors(steps, e.step).has(pred.step) || (pred.step === e.step && pred.round < e.round))) {
          return invalid(`step ${pred.step} is not an ancestor of ${e.step} in the definition`);
        }
      }
    }
    // Rule 11: the held document's own proof (P4: a held document with none is invalid).
    if (sd.proof === undefined) return invalid(`step ${e.id} carries no proof`);
    const sp = await checkProof(deps, sd);
    if (!sp.ok) {
      if (!sp.unavailable) return invalid(`the proof of step ${e.id} does not verify`);
      unverifiable.push(`the proof of step ${e.id} could not be checked: a key set could not be obtained`);
    }
  }

  // Rule 5: evaluate the completion rule over the enumerated steps; payload.complete is never relied on (P1).
  const present = new Map<string, Set<string>>();
  for (const e of entries) present.set(e.step, (present.get(e.step) ?? new Set<string>()).add(e.issuer));
  if (!satisfied(def.completion, present)) return done('incomplete', 'the enumerated steps do not satisfy the completion rule');
  // Rule 6: at least one enumerated step the definition declares terminal; none is a prefix.
  if (declaredTerminal.length === 0) return done('incomplete', 'no enumerated step is a terminal step: the receipt is a prefix');
  // Rule 7: confirm the marker in a held document; with none held the verifier cannot say complete.
  const docs = declaredTerminal.filter((e) => heldTerminal.has(e.id));
  if (docs.length === 0) unverifiable.push('no step document the definition declares terminal is held: the terminal marker was not checked');
  else if (!docs.some((e) => heldTerminal.get(e.id) === true)) return done('incomplete', 'the held terminal step document does not carry ceremony.terminal');
  if (unverifiable.length > 0) return done('unverifiable', unverifiable[0]!);
  return done('complete', 'verified');
}
