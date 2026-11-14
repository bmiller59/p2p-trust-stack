// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The HTTPS binding (bindings/https/0.3) for the conformance adapter: the agent's real Trust Task listener
 * (`startBoundaryListener`) on a loopback port, and a client that performs the request the suite describes (`http`: method, path,
 * Content-Type) and reports the HTTP status, the content type and the body that came back.
 *
 * The listener hands every document to the adapter's own pipeline, so the adapter's injectable clock, stores and signer are the
 * ones behind it; only the transport differs from an in-process `send`. The token-to-VID mapping of binding section 3 is a static
 * map held here (one token per identity the harness sends as); a request with no Authorization header, or an unknown token, has no
 * transport-authenticated sender.
 */
import { request } from 'node:http';
import type { IncomingMessage } from 'node:http';
import type { PipelineInput, PipelineResult } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pipeline.js';
import { LISTENER_PATH, startBoundaryListener } from '../src/runtime/trust-tasks-boundary/listener.ts';
import type { BoundaryListener } from '../src/runtime/trust-tasks-boundary/listener.ts';
import type { HttpRequestLine, SendFrom, SendResult } from './contract.ts';

export class HttpBinding {
  private listener: BoundaryListener | undefined;
  private readonly tokenOf = new Map<string, string>();
  private readonly vidOf = new Map<string, string>();

  /** Start the listener; `process` is the adapter's pipeline (read at request time, so a restart is followed). */
  async start(process: (input: PipelineInput) => Promise<PipelineResult>): Promise<void> {
    this.listener = await startBoundaryListener({
      host: '127.0.0.1',
      port: 0,
      process,
      authenticate: (req) => this.authenticate(req),
    });
  }

  async stop(): Promise<void> {
    await this.listener?.close();
    this.listener = undefined;
  }

  private authenticate(req: IncomingMessage): string | undefined {
    const match = /^Bearer (\S+)$/.exec(String(req.headers.authorization ?? ''));
    return match === null ? undefined : this.vidOf.get(match[1]!);
  }

  /** The bearer token this adapter holds for `vid` (minted on first use). */
  private tokenFor(vid: string): string {
    let token = this.tokenOf.get(vid);
    if (token === undefined) {
      token = `conformance-token-${this.tokenOf.size + 1}`;
      this.tokenOf.set(vid, token);
      this.vidOf.set(token, vid);
    }
    return token;
  }

  /** One HTTP exchange. `spoof` and `actor` identities both present the token held for that identifier; `none` sends no Authorization header. */
  async send(from: SendFrom, bytes: string, line: HttpRequestLine): Promise<SendResult> {
    const listener = this.listener;
    if (listener === undefined) throw new Error('the HTTPS listener is not running');
    const headers: Record<string, string> = {
      'content-type': line.contentType ?? 'application/json',
      accept: 'application/json',
      'content-length': String(Buffer.byteLength(bytes)),
    };
    if (from.kind !== 'none') headers.authorization = `Bearer ${this.tokenFor(from.vid)}`;
    const answer = await new Promise<{ status: number; type: string | undefined; body: string }>((resolve, reject) => {
      const req = request({ host: listener.host, port: listener.port, method: line.method ?? 'POST', path: line.path ?? LISTENER_PATH, headers, agent: false }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, type: res.headers['content-type'], body: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', reject);
      });
      req.on('error', reject);
      req.end(bytes);
    });
    // A body that is a Trust Task document is a reply; the minimal `{code,message,retryable}` body (nothing addressable) is a refusal.
    let isDocument = false;
    if (answer.body !== '') {
      try {
        isDocument = typeof (JSON.parse(answer.body) as { type?: unknown }).type === 'string';
      } catch {
        isDocument = false;
      }
    }
    return {
      replies: isDocument ? [answer.body] : [],
      transport: {
        status: answer.status,
        kind: isDocument ? 'document' : answer.body === '' ? 'none' : 'refused',
        ...(answer.body === '' || answer.type === undefined ? {} : { contentType: answer.type }),
      },
      quiescentAfterMs: 0,
    };
  }
}
