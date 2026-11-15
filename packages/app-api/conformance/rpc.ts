// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * JSON-RPC 2.0 over newline-delimited stdio or HTTP POST for the conformance adapter (the wire
 * contract is docs/04-suite-design.md section 4 of the suite). One request at a time, answered in order.
 * Errors: -32700 unparseable input (id null), -32600 invalid request, -32601 unknown method,
 * -32000 the method failed (the message is the failure text). Logs go to stderr, never stdout.
 */
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import { RPC_METHODS } from './contract.ts';
import type { Adapter, ObserveQuery, RpcRequest, RpcResponse, SendParams, VerifyReceiptParams } from './contract.ts';

const obj = (v: unknown): Record<string, unknown> => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown, name: string): string => {
  if (typeof v !== 'string') throw new Error(`${name} must be a string`);
  return v;
};

/** Run one request against the adapter. */
export async function dispatch(adapter: Adapter, req: RpcRequest): Promise<RpcResponse> {
  const id = req.id ?? null;
  if (req.jsonrpc !== '2.0' || typeof req.method !== 'string' || (req.id !== undefined && req.id !== null && typeof req.id !== 'string' && typeof req.id !== 'number')) {
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } };
  }
  if (!(RPC_METHODS as readonly string[]).includes(req.method)) {
    return { jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${req.method}` } };
  }
  const p = obj(req.params);
  try {
    let result: unknown;
    switch (req.method) {
      case 'capabilities': result = await adapter.capabilities(); break;
      case 'provision': {
        if (!Array.isArray(p.roles) || p.roles.some((r) => typeof r !== 'string')) throw new Error('roles must be a list of strings');
        result = await adapter.provision(p.roles as string[]);
        break;
      }
      case 'trust': result = await adapter.trust(str(p.vid, 'vid'), p.didDocument) ?? null; break;
      case 'setClock': result = await adapter.setClock(str(p.iso, 'iso')) ?? null; break;
      case 'advance': {
        if (typeof p.ms !== 'number') throw new Error('ms must be a number');
        result = await adapter.advance(p.ms) ?? null;
        break;
      }
      case 'send': {
        const from = obj(p.from);
        if (from.kind !== 'actor' && from.kind !== 'none' && from.kind !== 'spoof') throw new Error('from.kind must be actor, none or spoof');
        if (from.kind !== 'none') str(from.vid, 'from.vid');
        let http: SendParams['http'];
        if (p.http !== undefined) {
          const h = obj(p.http);
          for (const k of ['method', 'path', 'contentType']) if (h[k] !== undefined && typeof h[k] !== 'string') throw new Error(`http.${k} must be a string`);
          http = { ...(h.method === undefined ? {} : { method: h.method as string }), ...(h.path === undefined ? {} : { path: h.path as string }), ...(h.contentType === undefined ? {} : { contentType: h.contentType as string }) };
        }
        result = await adapter.send({ from: from as unknown as SendParams['from'], bytes: str(p.bytes, 'bytes'), ...(typeof p.channel === 'string' ? { channel: p.channel } : {}), ...(http === undefined ? {} : { http }) });
        break;
      }
      case 'trigger': result = await adapter.trigger(str(p.action, 'action'), obj(p.args)); break;
      case 'observe': {
        const q = p.query;
        if (q !== 'handled' && q !== 'documentState' && q !== 'stored' && q !== 'retained') throw new Error('query must be handled, documentState, stored or retained');
        result = await adapter.observe(p as unknown as ObserveQuery);
        break;
      }
      case 'restart': result = await adapter.restart() ?? null; break;
      case 'reset': result = await adapter.reset() ?? null; break;
      case 'snapshot': result = await adapter.snapshot(); break;
      case 'diff': result = await adapter.diff(str(p.snapshotId, 'snapshotId')); break;
      case 'verifyReceipt': {
        if (adapter.verifyReceipt === undefined) throw new Error('verifyReceipt is not supported');
        const params: VerifyReceiptParams = { receipt: str(p.receipt, 'receipt') };
        if (p.definition !== undefined && p.definition !== null) {
          if (typeof p.definition !== 'object' || Array.isArray(p.definition)) throw new Error('definition must be an object or null');
          params.definition = p.definition as Record<string, unknown>;
        } else if (p.definition === null) params.definition = null;
        if (p.roleBindings !== undefined && p.roleBindings !== null) {
          const b = obj(p.roleBindings);
          if (Object.values(b).some((v) => !Array.isArray(v) || v.some((x) => typeof x !== 'string'))) throw new Error('roleBindings must map role names to lists of strings');
          params.roleBindings = b as Record<string, string[]>;
        } else if (p.roleBindings === null) params.roleBindings = null;
        if (p.steps !== undefined) {
          if (!Array.isArray(p.steps) || p.steps.some((x) => typeof x !== 'string')) throw new Error('steps must be a list of strings');
          params.steps = p.steps as string[];
        }
        result = await adapter.verifyReceipt(params);
        break;
      }
      case 'verifyProof': result = await adapter.verifyProof({ bytes: str(p.bytes, 'bytes') }); break;
    }
    return { jsonrpc: '2.0', id, result: result === undefined ? null : result };
  } catch (err) {
    return { jsonrpc: '2.0', id, error: { code: -32000, message: (err as Error)?.message ?? String(err) } };
  }
}

/** One line of text in, one response text out. */
export async function handleText(adapter: Adapter, text: string): Promise<string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } });
  }
  return JSON.stringify(await dispatch(adapter, parsed as RpcRequest));
}

/** Serve stdio until the input closes; resolves then. Requests are answered strictly in order. */
export function serveStdio(adapter: Adapter, input: Readable = process.stdin, output: Writable = process.stdout): Promise<void> {
  return new Promise((resolve) => {
    const rl = createInterface({ input, crlfDelay: Infinity });
    let chain: Promise<void> = Promise.resolve();
    rl.on('line', (line) => {
      if (line.trim() === '') return;
      chain = chain.then(async () => {
        output.write(`${await handleText(adapter, line)}\n`);
      });
    });
    rl.on('close', () => void chain.then(resolve));
  });
}

const MAX_BODY = 8 * 1024 * 1024;

/** Serve HTTP POST (any path) on `port` (0 picks one). */
export function serveHttp(adapter: Adapter, port: number, host = '127.0.0.1'): Promise<{ server: Server; port: number; close(): Promise<void> }> {
  let chain: Promise<unknown> = Promise.resolve();
  const server = createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST' }).end();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let tooBig = false;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) tooBig = true;
      else chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) {
        res.writeHead(413).end();
        return;
      }
      const run = chain.then(() => handleText(adapter, Buffer.concat(chunks).toString('utf8')));
      chain = run.catch(() => undefined);
      void run.then((out) => res.writeHead(200, { 'content-type': 'application/json' }).end(out));
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const bound = (server.address() as { port: number }).port;
      resolve({ server, port: bound, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}
