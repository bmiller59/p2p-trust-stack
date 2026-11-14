// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P8: the JSON-RPC adapter server. The server is started as a child process exactly the
 * way the suite starts it (`stdio:<command>`), on temporary databases, and driven over the wire:
 * framing and error codes, the real pipeline behind `send`, the injectable clock, the duplicate record
 * across `restart`, `reset`, `snapshot`/`diff`, `observe`, `verifyProof`, and a did:scid:vh identity
 * whose signed replies verify against the document `provision` publishes.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { after, describe, it } from 'node:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { keysOfDocument, didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { DidProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/verify.js';
import { createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import { WIDGET_TYPE } from '../../conformance/adapter.ts';

const APP_API = new URL('../..', import.meta.url).pathname;
const START = '2026-11-12T10:00:00.000Z';
const A_SEED = new Uint8Array(32).fill(7);
const A_DID = didKeyFromEd25519(ed25519.getPublicKey(A_SEED));
const A = createEd25519BoundarySigner({ did: A_DID, secretKey: A_SEED, fragment: A_DID.slice('did:key:'.length) });

class Server {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly lines: string[] = [];
  private waiter: ((l: string) => void) | undefined;
  private nextId = 1;
  stderr = '';

  constructor(args: string[]) {
    this.child = spawn(process.execPath, ['--conditions=development', '--experimental-strip-types', '--loader', './test-loader.mjs', 'conformance/server.ts', ...args], {
      cwd: APP_API,
      env: { ...process.env, NODE_NO_WARNINGS: '1' },
    });
    this.child.stderr.on('data', (d: Buffer) => (this.stderr += d.toString()));
    createInterface({ input: this.child.stdout }).on('line', (l) => {
      if (this.waiter) {
        const w = this.waiter;
        this.waiter = undefined;
        w(l);
      } else this.lines.push(l);
    });
  }

  rawLine(text: string): Promise<string> {
    const got = this.lines.shift();
    const p = got !== undefined ? Promise.resolve(got) : new Promise<string>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`no reply to ${text.slice(0, 80)}; stderr: ${this.stderr.slice(-400)}`)), 60_000);
      this.waiter = (l) => { clearTimeout(t); resolve(l); };
    });
    this.child.stdin.write(`${text}\n`);
    return p;
  }

  async rpc(method: string, params?: unknown): Promise<{ result?: any; error?: { code: number; message: string } }> {
    return JSON.parse(await this.rawLine(JSON.stringify({ jsonrpc: '2.0', id: this.nextId++, method, ...(params === undefined ? {} : { params }) })));
  }
  async call(method: string, params?: unknown): Promise<any> {
    const r = await this.rpc(method, params);
    assert.equal(r.error, undefined, `${method}: ${r.error?.message}`);
    return r.result;
  }

  async close(): Promise<number | null> {
    this.child.stdin.end();
    const [code] = (await once(this.child, 'exit')) as [number | null];
    return code;
  }
}

const servers: Server[] = [];
const start = (args: string[]): Server => {
  const s = new Server(args);
  servers.push(s);
  return s;
};
after(async () => {
  await Promise.all(servers.map((s) => s.close().catch(() => undefined)));
});

const uid = (n: number): string => `urn:uuid:aaaaaaaa-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
function widget(iut: string, n: number, extra: Record<string, unknown> = {}, nowIso = START): string {
  const doc = { id: uid(n), type: WIDGET_TYPE, issuer: A_DID, recipient: iut, issuedAt: nowIso.replace('.000Z', 'Z'), payload: { subject: 'did:web:alice.example' }, ...extra };
  return JSON.stringify(signDocument(doc, A, { created: Date.parse(nowIso) }));
}
const actor = { kind: 'actor', vid: A_DID };

describe('framing and error codes', () => {
  it('answers parse errors, invalid requests, unknown methods and failing methods with the contract codes', async () => {
    const s = start(['--identity', 'key']);
    assert.deepEqual(JSON.parse(await s.rawLine('{not json')), { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
    assert.equal(JSON.parse(await s.rawLine('[1]')).error.code, -32600);
    assert.equal(JSON.parse(await s.rawLine('{"jsonrpc":"1.0","id":5,"method":"capabilities"}')).error.code, -32600);
    const unknown = JSON.parse(await s.rawLine('{"jsonrpc":"2.0","id":6,"method":"nope"}'));
    assert.equal(unknown.error.code, -32601);
    assert.equal(unknown.id, 6);
    assert.equal((await s.rpc('setClock', { iso: 'yesterday' })).error?.code, -32000);
    assert.equal((await s.rpc('send', { from: { kind: 'weird' }, bytes: '{}' })).error?.code, -32000);
    assert.equal((await s.rpc('diff', { snapshotId: 'snap-9' })).error?.code, -32000);
    assert.equal((await s.rpc('observe', { query: 'bogus' })).error?.code, -32000);
    assert.equal(await s.close(), 0, 'the server exits cleanly when stdin closes');
  });
});

describe('capabilities and provision', () => {
  it('declares what it serves and gives a did:scid:vh connection identifier with its document', async () => {
    const s = start(['--attested']);
    const caps = await s.call('capabilities');
    assert.equal(caps.tierMax, 2);
    assert.deepEqual(caps.cryptosuites, ['eddsa-jcs-2022']);
    for (const t of ['vrc/relationships/propose/0.1', 'vrc/relationships/issue/0.1', 'vrc/relationships/witness-share/0.1']) {
      assert.ok(caps.supportedTypes.includes(`https://trusttasks.org/spec/${t}`), t);
    }
    for (const o of ['trigger.consent', 'clock', 'restart', 'fault.claimStore', 'trigger.twoPhase', 'proofVerify', 'attested']) assert.ok(caps.optional.includes(o), o);
    for (const o of ['control', 'idempotencyKey']) assert.ok(!caps.optional.includes(o), `${o} is not claimed`);
    assert.equal(caps.carriers[0].typeUri, WIDGET_TYPE);
    const p = await s.call('provision', { roles: ['iut'] });
    assert.match(p.iut.vid, /^did:scid:vh:/);
    assert.equal(p.iut.keyCustody, 'iut');
    assert.ok(p.iut.didDocument.verificationMethod.some((m: { id: string }) => m.id === '#key-1'));
  });

  it('the Tier 1 server claims Tier 1 only and the carrier can be withdrawn', async () => {
    const t1 = start([]);
    const caps = await t1.call('capabilities');
    assert.equal(caps.tierMax, 1);
    assert.ok(!caps.optional.includes('attested'));
    const none = start(['--carrier', 'none', '--no-witness-share', '--no-issue', '--no-ceremony']);
    const c2 = await none.call('capabilities');
    assert.deepEqual(c2.carriers, []);
    assert.deepEqual(c2.supportedTypes, ['https://trusttasks.org/spec/trust-task-discovery/0.4', 'https://trusttasks.org/spec/vrc/relationships/propose/0.1']);
  });

  it('declares discovery 0.4 and lists every served task, discovery included, in registry and URN form, as the discovery answer does', async () => {
    const s = start(['--attested', '--identity', 'key']);
    const caps = await s.call('capabilities');
    const p = await s.call('provision', { roles: ['iut'] });
    await s.call('setClock', { iso: START });
    const doc = { id: uid(900), type: 'https://trusttasks.org/spec/trust-task-discovery/0.4', issuer: A_DID, recipient: p.iut.vid, issuedAt: '2026-11-12T10:00:00Z', payload: {} };
    const sent = await s.call('send', { from: { kind: 'actor', vid: A_DID }, bytes: JSON.stringify(signDocument(doc, A, { created: Date.parse(START) })) });
    const listed = JSON.parse(sent.replies[0]).payload.supportedTypes as string[];
    assert.deepEqual([...caps.supportedTypes].sort(), [...listed].sort());
    assert.ok(caps.supportedTypes.includes('https://trusttasks.org/spec/trust-task-discovery/0.4'));
    assert.ok(caps.supportedTypes.some((t: string) => t.startsWith('urn:p2pts:tasks:spec:ceremony:')), 'the private ceremony types are listed in URN form');
    for (const o of ['discovery.acceptanceWindow', 'discovery.expiryHorizon']) assert.ok(caps.optional.includes(o), o);
  });
});

describe('send through the real pipeline', () => {
  it('answers a signed carrier request with a reply signed as the did:scid:vh agent, verifiable from the published document', async () => {
    const s = start(['--attested']);
    const iut = (await s.call('provision', { roles: ['iut'] })).iut;
    await s.call('setClock', { iso: START });
    const r = await s.call('send', { from: actor, bytes: widget(iut.vid, 1) });
    assert.equal(r.transport.kind, 'document');
    assert.equal(r.transport.status, 200);
    const reply = JSON.parse(r.replies[0]);
    assert.equal(reply.type, `${WIDGET_TYPE}#response`);
    assert.equal(reply.issuer, iut.vid);
    assert.equal(reply.recipient, A_DID);
    assert.equal(reply.proof.proofPurpose, 'authentication');
    assert.equal(reply.proof.verificationMethod, `${iut.vid}#key-1`);
    // The harness cannot resolve a did:scid:vh itself; the document provision published is enough.
    const verifier = new DidProofVerifier({ resolver: { resolve: async (did) => (did === iut.vid ? keysOfDocument(did, iut.didDocument as DidDocument, 'local') : null) } });
    const verdict = await verifier.verify(reply, { nowMs: Date.parse(START) });
    assert.equal(verdict.valid, true, verdict.detail);
    assert.deepEqual(await s.call('observe', { query: 'handled' }), { value: 1 });
    assert.deepEqual(await s.call('observe', { query: 'documentState', id: uid(1) }), { value: 'responded' });
  });

  it('fault.claimStore fails closed (unavailable, retryable, nothing run), burns no id, and reset clears the fault', async () => {
    const s = start(['--attested']);
    const iut = (await s.call('provision', { roles: ['iut'] })).iut;
    await s.call('setClock', { iso: START });
    await s.call('trigger', { action: 'fault', args: { claimStore: 'unreadable' } });
    const bytes = widget(iut.vid, 1);
    const refused = JSON.parse((await s.call('send', { from: actor, bytes })).replies[0]);
    assert.equal(refused.payload.code, 'unavailable');
    assert.equal(refused.payload.retryable, true);
    assert.deepEqual(await s.call('observe', { query: 'handled' }), { value: 0 });
    await s.call('trigger', { action: 'fault', args: { claimStore: 'ok' } });
    const again = JSON.parse((await s.call('send', { from: actor, bytes })).replies[0]);
    assert.equal(again.type, `${WIDGET_TYPE}#response`);
    assert.deepEqual(await s.call('observe', { query: 'handled' }), { value: 1 });
    await s.call('trigger', { action: 'fault', args: { claimStore: 'unreadable' } });
    await s.call('reset');
    await s.call('setClock', { iso: START });
    const afterReset = JSON.parse((await s.call('send', { from: actor, bytes })).replies[0]);
    assert.equal(afterReset.type, `${WIDGET_TYPE}#response`);
    assert.match((await s.rpc('trigger', { action: 'fault', args: { claimStore: 'maybe' } })).error?.message ?? '', /unreadable or ok/);
  });
  it('Tier 2 refuses an unsigned request (proofRequired) and refuses a wrong recipient; neither runs the task', async () => {
    const s = start(['--attested', '--identity', 'key']);
    const iut = (await s.call('provision', { roles: ['iut'] })).iut;
    await s.call('setClock', { iso: START });
    const unsigned = JSON.stringify({ id: uid(2), type: WIDGET_TYPE, issuer: A_DID, recipient: iut.vid, issuedAt: '2026-11-12T10:00:00Z', payload: { subject: 'x' } });
    const r1 = JSON.parse((await s.call('send', { from: actor, bytes: unsigned })).replies[0]);
    assert.equal(r1.payload.code, 'proofRequired');
    const r2 = JSON.parse((await s.call('send', { from: actor, bytes: widget('did:web:somebody.else', 3) })).replies[0]);
    assert.equal(r2.payload.code, 'wrongRecipient');
    assert.deepEqual(await s.call('observe', { query: 'handled' }), { value: 0 });
  });

  it('the injected clock drives freshness: advance past the window and the same document is expired', async () => {
    const s = start(['--attested', '--identity', 'key']);
    const iut = (await s.call('provision', { roles: ['iut'] })).iut;
    await s.call('setClock', { iso: START });
    const bytes = widget(iut.vid, 4);
    await s.call('advance', { ms: 6 * 60_000 });
    const r = JSON.parse((await s.call('send', { from: actor, bytes })).replies[0]);
    assert.equal(r.payload.code, 'expired');
    assert.deepEqual(await s.call('observe', { query: 'handled' }), { value: 0 });
    // an unreadable clock is an error of the method, not a silent default
    assert.equal((await s.rpc('setClock', { iso: 'nonsense' })).error?.code, -32000);
  });
});

describe('durable state: restart, reset, snapshot', () => {
  it('restart reopens the databases: the duplicate record and the stored effect survive; reset clears both', async () => {
    const s = start(['--attested', '--identity', 'key']);
    const iut = (await s.call('provision', { roles: ['iut'] })).iut;
    await s.call('setClock', { iso: START });
    const bytes = widget(iut.vid, 5);
    const first = await s.call('send', { from: actor, bytes });
    assert.equal(JSON.parse(first.replies[0]).type, `${WIDGET_TYPE}#response`);
    await s.call('restart');
    assert.deepEqual(await s.call('observe', { query: 'handled' }), { value: 1 }, 'the execution is durable');
    const again = await s.call('send', { from: actor, bytes });
    assert.deepEqual(await s.call('observe', { query: 'handled' }), { value: 1 }, 'the resend after a restart did not run the task again');
    assert.equal(again.transport.status, 200, 'a duplicate is answered 200 with the prior response');
    assert.equal(again.replies[0], first.replies[0], 'the prior response, byte for byte, read back from disk');
    const changed = widget(iut.vid, 5, { payload: { subject: 'did:web:other.example' } });
    const conflict = JSON.parse((await s.call('send', { from: actor, bytes: changed })).replies[0]);
    assert.equal(conflict.payload.code, 'idConflict', 'the accepted-id record was reloaded from disk');
    await s.call('reset');
    await s.call('setClock', { iso: START });
    assert.deepEqual(await s.call('observe', { query: 'handled' }), { value: 0 });
    assert.deepEqual(await s.call('observe', { query: 'documentState', id: uid(5) }), { value: 'unknown' });
    const fresh = JSON.parse((await s.call('send', { from: actor, bytes })).replies[0]);
    assert.equal(fresh.type, `${WIDGET_TYPE}#response`, 'after reset the same id is new again');
  });

  it('snapshot and diff see durable changes', async () => {
    const s = start(['--identity', 'key']);
    const iut = (await s.call('provision', { roles: ['iut'] })).iut;
    await s.call('setClock', { iso: START });
    const snap = await s.call('snapshot');
    assert.deepEqual(await s.call('diff', { snapshotId: snap }), { changed: false });
    await s.call('send', { from: actor, bytes: widget(iut.vid, 6) });
    const d = await s.call('diff', { snapshotId: snap });
    assert.equal(d.changed, true);
  });

  it('trust accepts a counterpart document and the adapter keeps working across a restart', async () => {
    const s = start(['--identity', 'key']);
    await s.call('trust', { vid: 'did:web:peer.example', didDocument: { id: 'did:web:peer.example', verificationMethod: [] } });
    await s.call('restart');
    assert.equal(await s.call('trust', { vid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' }), null);
  });
});

describe('trigger, observe and verifyProof', () => {
  it('policy and consent decide a held proposal and return the signed reply; observe sees the exchange', async () => {
    const s = start(['--attested', '--identity', 'key']);
    const iut = (await s.call('provision', { roles: ['iut'] })).iut;
    await s.call('setClock', { iso: START });
    await s.call('trigger', { action: 'policy', args: { propose: 'hold' } });
    const propose = JSON.stringify(signDocument({
      id: uid(7), threadId: uid(7), type: 'https://trusttasks.org/spec/vrc/relationships/propose/0.1', issuer: A_DID, recipient: iut.vid,
      issuedAt: '2026-11-12T10:00:00Z', payload: { relationshipDid: 'did:peer:4zQmRemoteRelationshipDidForTheAdapterTest' },
    }, A, { created: Date.parse(START) }));
    const held = JSON.parse((await s.call('send', { from: actor, bytes: propose })).replies[0]);
    assert.match(held.type, /trust-task-next-step/);
    assert.ok(held.proof, 'the hold is signed at Tier 2');
    assert.deepEqual(await s.call('observe', { query: 'documentState', id: uid(7) }), { value: 'accepted' });
    const decided = await s.call('trigger', { action: 'consent', args: { exchangeId: uid(7), decision: 'decline' } });
    assert.equal(decided.documents.length, 1);
    assert.match(JSON.parse(decided.documents[0]).payload.code, /declined/);
    assert.deepEqual(await s.call('observe', { query: 'documentState', id: uid(7) }), { value: 'errored' });
    assert.equal((await s.rpc('trigger', { action: 'nope', args: {} })).error?.code, -32000);
    assert.equal((await s.rpc('trigger', { action: 'policy', args: { propose: 'maybe' } })).error?.code, -32000);
  });

  it('verifyProof says valid for a signed document and invalid once a byte of the body changes', async () => {
    const s = start(['--identity', 'key']);
    const iut = (await s.call('provision', { roles: ['iut'] })).iut;
    await s.call('setClock', { iso: START });
    const bytes = widget(iut.vid, 8);
    assert.deepEqual(await s.call('verifyProof', { bytes }), { valid: true });
    assert.deepEqual(await s.call('verifyProof', { bytes: bytes.replace('alice', 'mallory') }), { valid: false });
    assert.deepEqual(await s.call('verifyProof', { bytes: 'not json' }), { valid: false });
  });
});
