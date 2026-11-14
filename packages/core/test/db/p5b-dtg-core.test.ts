// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P5b (core side): the pure parts of `task-consent/{request,decision}` and
 * `credential-exchange/{issue,present}`, migration 0023 and the presentation repository.
 * The end-to-end behaviours run in app-api. Temp directories only.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { SqliteDataSource } from '../../src/db/sqlite-data-source.js';
import { runMigrations } from '../../src/db/migrate.js';
import { getMigrationsDir } from '../../src/db/migrations-dir.js';
import * as presentations from '../../src/db/repositories/credential-presentations-repo.js';
import {
  checkIssuedCredential,
  checkPresentation,
  issueRefusal,
  parseIssuePayload,
  presentRefusal,
  ISSUE_UNSUPPORTED_FORMAT,
  PRESENT_AUDIENCE_MISMATCH,
  PRESENT_STALE_NONCE,
} from '../../src/services/trust-tasks/boundary/credential-exchange.js';
import { createLocalKeyResolver } from '../../src/services/trust-tasks/boundary/proof/install.js';
import { didKeyFromEd25519 } from '../../src/services/trust-tasks/boundary/proof/resolver.js';
import { createEd25519BoundarySigner, signDocument } from '../../src/services/trust-tasks/boundary/proof/signer.js';
import { DidProofVerifier } from '../../src/services/trust-tasks/boundary/proof/verify.js';
import { ATTESTATION_SLUGS, allowedPurposes } from '../../src/services/trust-tasks/boundary/proof/purposes.js';
import {
  TASK_CONSENT_DECISION_SERVED_VERSIONS,
  TASK_CONSENT_DECISION_TYPE,
  TASK_CONSENT_REQUEST_TYPE,
  consentChallenge,
  consentPayloadDigest,
  parseConsentRequestPayload,
  parseDecisionPayload,
} from '../../src/services/trust-tasks/boundary/task-consent.js';
import {
  CREDENTIAL_ISSUE_SPEC,
  CREDENTIAL_PRESENT_SPEC,
  TASK_CONSENT_DECISION_SPEC,
  TASK_CONSENT_REQUEST_SPEC,
  tryParseTypeUri,
} from '../../src/services/trust-tasks/boundary/runtime.js';
import { CEREMONY_PROPOSE_WIRE_TYPE } from '../../src/services/trust-tasks/boundary/ceremony-spec.js';

const NOW = Date.parse('2026-11-12T10:00:00Z');
const DIGEST = 'zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR';
const party = (n: number) => {
  const seed = new Uint8Array(32).fill(n);
  const did = didKeyFromEd25519(ed25519.getPublicKey(seed));
  return { did, signer: createEd25519BoundarySigner({ did, secretKey: seed, fragment: did.slice('did:key:'.length) }) };
};
const issuer = party(11);
const holder = party(12);
const other = party(13);
const verifier = new DidProofVerifier({ resolver: createLocalKeyResolver({}) });
const ctx = { verifier, nowMs: NOW };

const credential = (over: Record<string, unknown> = {}, signWith = issuer) =>
  signDocument(
    { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential', 'MembershipCredential'], issuer: issuer.did, credentialSubject: { id: holder.did, memberOf: 'x' }, ...over },
    signWith.signer,
    { created: NOW, purpose: 'assertionMethod', allowIssuerMismatch: true },
  );

describe('task-consent: version choice and policy', () => {
  it('serves decision 0.2 only (0.1 is superseded in the registry), request 0.1; the specs require proof and recipient', () => {
    assert.deepEqual(TASK_CONSENT_DECISION_SERVED_VERSIONS, ['0.2']);
    assert.equal(TASK_CONSENT_DECISION_TYPE, TASK_CONSENT_DECISION_SPEC.typeUri);
    assert.equal(TASK_CONSENT_REQUEST_TYPE, TASK_CONSENT_REQUEST_SPEC.typeUri);
    for (const s of [TASK_CONSENT_DECISION_SPEC, TASK_CONSENT_REQUEST_SPEC, CREDENTIAL_ISSUE_SPEC, CREDENTIAL_PRESENT_SPEC]) {
      assert.equal(s.isProofRequired, true);
      assert.equal(s.isRecipientRequired, true);
      assert.notEqual(tryParseTypeUri(s.typeUri), null);
    }
    assert.equal(TASK_CONSENT_DECISION_SPEC.isIssuedAtRequired, true);
  });

  it('purpose pin: the decision is proven under assertionMethod only at Tier 2; the request and the credential tasks under authentication', () => {
    assert.ok(ATTESTATION_SLUGS.includes('task-consent/decision'));
    assert.deepEqual(allowedPurposes(TASK_CONSENT_DECISION_TYPE, 2), ['assertionMethod']);
    assert.deepEqual(allowedPurposes(TASK_CONSENT_REQUEST_TYPE, 2), ['authentication']);
    assert.deepEqual(allowedPurposes('https://trusttasks.org/spec/credential-exchange/issue/0.1', 2), ['authentication']);
    assert.deepEqual(allowedPurposes('https://trusttasks.org/spec/credential-exchange/present/0.1', 2), ['authentication']);
  });
});

describe('task-consent: derived challenge and digest', () => {
  const subject = { name: 'Acme', kind: 'vtc', threshold: 2, adminDids: ['did:a', 'did:b'], parentCommunityDid: null };
  it('are stable, multibase, distinct per ceremony and per content, and independent of admin order', () => {
    const c1 = consentChallenge({ ceremonyId: 'c-1', proposalHash: 'h1' });
    assert.equal(c1, consentChallenge({ ceremonyId: 'c-1', proposalHash: 'h1' }));
    assert.match(c1, /^z[1-9A-HJ-NP-Za-km-z]+$/);
    assert.ok(c1.length >= 16);
    assert.notEqual(c1, consentChallenge({ ceremonyId: 'c-2', proposalHash: 'h1' }));
    assert.notEqual(c1, consentChallenge({ ceremonyId: 'c-1', proposalHash: 'h2' }));
    const d = consentPayloadDigest({ taskType: CEREMONY_PROPOSE_WIRE_TYPE, subject, challenge: c1 });
    assert.equal(d, consentPayloadDigest({ taskType: CEREMONY_PROPOSE_WIRE_TYPE, subject: { ...subject, adminDids: ['did:b', 'did:a'] }, challenge: c1 }));
    assert.notEqual(d, consentPayloadDigest({ taskType: CEREMONY_PROPOSE_WIRE_TYPE, subject: { ...subject, threshold: 1 }, challenge: c1 }));
    assert.notEqual(d, consentPayloadDigest({ taskType: 'urn:other', subject, challenge: c1 }));
    assert.notEqual(d, consentPayloadDigest({ taskType: CEREMONY_PROPOSE_WIRE_TYPE, subject, challenge: consentChallenge({ ceremonyId: 'c-2', proposalHash: 'h1' }) }));
  });
});

describe('task-consent: payload rules the small schema reader does not enforce', () => {
  const good = { challenge: 'c'.repeat(16), payloadDigest: DIGEST, decision: 'approve' };
  it('accepts a minimal decision and reports evidence without trusting it', () => {
    assert.deepEqual(parseDecisionPayload(good), { ...good, hasEvidence: false });
    assert.equal(parseDecisionPayload({ ...good, evidence: { kind: 'webauthn', assertion: {} } }).hasEvidence, true);
  });
  it('refuses a short challenge, a bad digest, a bad decision, an oversize reason and an empty actionId', () => {
    for (const bad of [{ challenge: 'short' }, { payloadDigest: 'abc' }, { payloadDigest: 'z0OIl0OIl0OIl0OIl0' }, { decision: 'maybe' }, { reason: 'x'.repeat(501) }, { actionId: '' }, { evidence: 'x' }]) {
      assert.throws(() => parseDecisionPayload({ ...good, ...bad }), (e: { code?: string }) => e.code === 'malformedRequest');
    }
  });
  const request = {
    challenge: 'c'.repeat(16), taskType: 'https://trusttasks.org/spec/x/y/0.1', payloadDigest: DIGEST, sideEffects: 'mutating',
    exposure: { discloses: 'none', actsAsSubject: false }, effects: [], requester: 'did:r', approverSet: 'admins', minApprovals: 1, excludeRequester: true,
    expiresAt: '2026-11-12T11:00:00Z',
  };
  it('parses a consent request and refuses malformed members', () => {
    assert.equal(parseConsentRequestPayload(request).expiresAtMs, Date.parse('2026-11-12T11:00:00Z'));
    for (const bad of [{ minApprovals: 0 }, { excludeRequester: 'yes' }, { expiresAt: 'soon' }, { sideEffects: 'x' }, { exposure: {} }, { effects: {} }, { taskType: 'no-scheme' }]) {
      assert.throws(() => parseConsentRequestPayload({ ...request, ...bad }), (e: { code?: string }) => e.code === 'malformedRequest');
    }
  });
});

describe('credential-exchange/issue: payload shape', () => {
  it('oneOf is enforced: both or neither is malformed; sealed and string credentials are an unsupported format; an object is accepted', () => {
    const vc = credential();
    assert.equal(parseIssuePayload({ credential_response: { credential: vc }, sealed: 'x' }).ok, false);
    assert.deepEqual(parseIssuePayload({}), { ok: false, reason: 'malformed' });
    assert.deepEqual(parseIssuePayload({ sealed: 'armored' }), { ok: false, reason: 'unsupportedFormat' });
    assert.deepEqual(parseIssuePayload({ credential_response: { credential: 'eyJ.x.y' } }), { ok: false, reason: 'unsupportedFormat' });
    assert.deepEqual(parseIssuePayload({ credential_response: {} }), { ok: false, reason: 'malformed' });
    assert.equal(parseIssuePayload({ credential_response: { credential: vc } }).ok, true);
  });
  it('refusals map to the registry extended code, a standard code, or the closed vcInvalid reason', () => {
    assert.equal(issueRefusal('unsupportedFormat', 'x').code, ISSUE_UNSUPPORTED_FORMAT);
    assert.equal(issueRefusal('ownPath', 'x').code, ISSUE_UNSUPPORTED_FORMAT);
    assert.equal(issueRefusal('malformed', 'x').code, 'malformedRequest');
    assert.equal(issueRefusal('issuerNotSender', 'x').code, 'permissionDenied');
    assert.equal(issueRefusal('proofInvalid', 'x').code, 'taskFailed');
  });
});

describe('credential-exchange/issue: credential checks', () => {
  const expected = { sender: issuer.did, holder: holder.did };
  it('accepts a signed credential from its issuer about the holder, with a stable digest and id (idempotent by digest)', async () => {
    const a = await checkIssuedCredential(credential(), expected, ctx);
    assert.equal(a.ok, true);
    if (!a.ok) return;
    assert.equal(a.vcType, 'vmc');
    assert.equal(a.issuerDid, issuer.did);
    const b = await checkIssuedCredential(JSON.parse(JSON.stringify(credential())), expected, ctx);
    assert.ok(b.ok && b.digestHex === a.digestHex && b.credentialUuid === a.credentialUuid && b.text === a.text);
    const c = await checkIssuedCredential(credential({ credentialSubject: { id: holder.did, memberOf: 'y' } }), expected, ctx);
    assert.ok(c.ok && c.credentialUuid !== a.credentialUuid);
  });
  it('refuses: another sender (relay), another subject, a tampered credential, a wrong-purpose proof, an expired one, own-path and unknown kinds', async () => {
    const reason = async (vc: Record<string, unknown>, exp = expected) => { const r = await checkIssuedCredential(vc, exp, ctx); return r.ok ? 'ok' : r.reason; };
    assert.equal(await reason(credential(), { sender: other.did, holder: holder.did }), 'issuerNotSender');
    assert.equal(await reason(credential(), { sender: issuer.did, holder: other.did }), 'subjectNotHolder');
    const tampered = credential();
    (tampered.credentialSubject as { memberOf: string }).memberOf = 'evil';
    assert.equal(await reason(tampered), 'proofInvalid');
    const auth = signDocument({ type: ['VerifiableCredential', 'MembershipCredential'], issuer: issuer.did, credentialSubject: { id: holder.did } }, issuer.signer, { created: NOW, purpose: 'authentication', allowIssuerMismatch: true });
    assert.equal(await reason(auth), 'proofInvalid');
    assert.equal(await reason(credential({ validUntil: '2026-11-12T09:00:00Z' })), 'expired');
    assert.equal(await reason(credential({ type: ['VerifiableCredential', 'RelationshipCredential'] })), 'ownPath');
    assert.equal(await reason(credential({ type: ['VerifiableCredential', 'StatementCredential'] })), 'ownPath');
    assert.equal(await reason(credential({ type: ['VerifiableCredential', 'Mystery'] })), 'unsupportedKind');
    assert.equal(await reason({ ...credential(), proof: undefined }), 'malformed');
    assert.equal(await reason(credential({ validUntil: 'whenever' })), 'malformed');
  });
});

describe('credential-exchange/present: presentation checks', () => {
  const expected = { holder: holder.did, audience: 'did:key:verifier', nonce: 'thread-1' };
  const vp = (over: Record<string, unknown> = {}, proof: Record<string, unknown> = {}, signWith = holder) =>
    signDocument(
      { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiablePresentation'], holder: holder.did, verifiableCredential: [credential()], ...over },
      signWith.signer,
      { created: NOW, purpose: 'authentication', challenge: 'thread-1', domain: 'did:key:verifier', allowIssuerMismatch: true, ...proof },
    );
  it('accepts a holder-bound presentation of a valid credential and records the issuers without asserting trust', async () => {
    const r = await checkPresentation(vp(), expected, ctx);
    assert.ok(r.ok);
    if (r.ok) assert.deepEqual([r.issuers, r.credentialCount], [[issuer.did], 1]);
  });
  it('maps a different nonce to staleNonce and a different audience to audienceMismatch', async () => {
    const stale = await checkPresentation(vp({}, { challenge: 'thread-0' }), expected, ctx);
    assert.deepEqual(stale.ok ? 'ok' : stale.reason, 'staleNonce');
    const aud = await checkPresentation(vp({}, { domain: 'did:key:elsewhere' }), expected, ctx);
    assert.deepEqual(aud.ok ? 'ok' : aud.reason, 'audienceMismatch');
    assert.equal(presentRefusal('staleNonce', 'x').code, PRESENT_STALE_NONCE);
    assert.equal(presentRefusal('audienceMismatch', 'x').code, PRESENT_AUDIENCE_MISMATCH);
  });
  it('refuses another holder, a credential about someone else, a forged credential, an empty or SD-JWT presentation', async () => {
    const reason = async (token: unknown) => { const r = await checkPresentation(token, expected, ctx); return r.ok ? 'ok' : r.reason; };
    assert.equal(await reason(vp({ holder: other.did })), 'holderNotSender');
    assert.equal(await reason(vp({ verifiableCredential: [credential({ credentialSubject: { id: other.did } })] })), 'credentialInvalid');
    const forged = credential();
    (forged.credentialSubject as { memberOf: string }).memberOf = 'evil';
    assert.equal(await reason(vp({ verifiableCredential: [forged] })), 'credentialInvalid');
    assert.equal(await reason(vp({ verifiableCredential: [] })), 'malformed');
    assert.equal(await reason('eyJhbGciOi.x.y'), 'unsupportedFormat');
    assert.equal(await reason(vp({}, {}, other)), 'proofInvalid');
  });
});

describe('migration 0023 and the presentation repository', () => {
  it('is one additive dialect-neutral table; the nonce (thread) is unique and the digest is the key', async () => {
    const sql = readFileSync(join(getMigrationsDir(), '0023_credential_presentations.sql'), 'utf8').replace(/--.*$/gm, '');
    assert.equal((sql.match(/CREATE TABLE/g) ?? []).length, 1);
    assert.ok(!/ALTER|DROP|DELETE|RENAME|INSERT OR|ON CONFLICT|unixepoch|datetime|DEFAULT/i.test(sql));
    const ds = new SqliteDataSource(':memory:');
    runMigrations(ds.getRawDb(), getMigrationsDir());
    const row = (id: string, threadId: string) => ({ id, threadId, holderDid: 'did:h', verifierDid: 'did:v', vpJson: '{}', issuers: ['did:i'], credentialCount: 1, now: NOW });
    await presentations.insert(ds, row('zP1', 't-1'));
    await assert.rejects(presentations.insert(ds, row('zP2', 't-1')), 'a second presentation on one nonce');
    await assert.rejects(presentations.insert(ds, row('zP1', 't-2')), 'the same digest twice');
    assert.deepEqual((await presentations.findByThread(ds, 't-1'))?.issuers, ['did:i']);
    assert.equal((await presentations.findByDigest(ds, 'zP1'))?.createdAt, NOW);
    await presentations.remove(ds, 'zP1');
    assert.equal(await presentations.count(ds), 0);
    await ds.close();
  });
});
