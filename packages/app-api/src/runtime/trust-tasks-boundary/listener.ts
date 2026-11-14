// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The agent's Trust Task listener (conformance phase P6c): one `POST /trust-tasks` route on its OWN
 * HTTP server and port, opt-in and off by default, never mounted on the UI server (which authenticates
 * with a cookie session and serves a human). The route ignores cookies and credentials entirely: the
 * sender is established solely by the verified proof inside the document (proof-only, conformance
 * G1/G3), so the pipeline is always handed no transport sender. The body is read raw (bounded) so
 * verification and digests run over the bytes received, and the reply is the exact bytes produced.
 *
 * Status follows the pipeline's result (the HTTPS binding's code-to-status function): 200 with the
 * reply, 202 for a duplicate still in flight, 204 for an absorbed document, 4xx/5xx for an error
 * document, and a minimal unsigned `{code,message,retryable}` body when nothing addressable exists.
 */
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { PipelineInput, PipelineResult } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pipeline.js';

export const LISTENER_PATH = '/trust-tasks';
const DEFAULT_MAX_BODY = 1024 * 1024;

export interface BoundaryListenerConfig {
  host: string;
  port: number;
  /** `2` is the attested profile (proof on every request, every reply signed); the default for the listener. */
  tier: 1 | 2;
  proposePolicy: 'hold' | 'decline';
}

export interface ListenerEnv {
  [name: string]: string | undefined;
}

/**
 * Opt-in resolution. Nothing listens unless it is switched on explicitly (`TRUST_TASKS_LISTENER=1` or
 * `override.enabled === true`) AND a port is given: there is no default port, so it can never collide
 * with, or be mistaken for, the UI. A port equal to a forbidden one (the UI port) is refused.
 */
export function resolveListenerConfig(
  env: ListenerEnv,
  override: Partial<BoundaryListenerConfig> & { enabled?: boolean } = {},
  forbiddenPorts: readonly number[] = [],
): BoundaryListenerConfig | null {
  const enabled = override.enabled ?? env.TRUST_TASKS_LISTENER === '1';
  if (!enabled) return null;
  const rawPort = override.port ?? (env.TRUST_TASKS_LISTENER_PORT === undefined ? undefined : Number(env.TRUST_TASKS_LISTENER_PORT));
  if (rawPort === undefined || !Number.isInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
    throw new Error('Trust Task listener is enabled but no valid port is configured (TRUST_TASKS_LISTENER_PORT)');
  }
  if (forbiddenPorts.includes(rawPort)) throw new Error(`Trust Task listener must not use port ${rawPort}: it is reserved for the UI`);
  const tier = override.tier ?? (env.TRUST_TASKS_TIER === '1' ? 1 : 2);
  const policy = override.proposePolicy ?? (env.TRUST_TASKS_PROPOSE_POLICY === 'decline' ? 'decline' : 'hold');
  return { host: override.host ?? env.TRUST_TASKS_LISTENER_HOST ?? '127.0.0.1', port: rawPort, tier, proposePolicy: policy };
}

export interface BoundaryListener {
  readonly port: number;
  readonly host: string;
  close(): Promise<void>;
}

export interface StartListenerOptions {
  host: string;
  port: number;
  process(input: PipelineInput): Promise<PipelineResult>;
  maxBodyBytes?: number;
  onError?: (err: unknown) => void;
  /**
   * Maps a request to the transport-authenticated sender (the VID a bearer token stands for, bindings/https section 3), or
   * `undefined` for no sender (no Authorization header, or a token it does not recognise). Absent by default: the agent's
   * own listener authenticates by the proof alone and passes the pipeline no sender. A deployment that issues bearer tokens
   * (and the conformance adapter) supplies it.
   */
  authenticate?: (req: IncomingMessage) => string | undefined;
}

function respond(res: ServerResponse, status: number, body?: unknown, type = 'application/json'): void {
  if (body === undefined) {
    res.writeHead(status).end();
    return;
  }
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'content-type': type, 'content-length': Buffer.byteLength(text) }).end(text);
}

const minimal = (code: string, message: string, retryable = false) => ({ code, message, retryable });

async function readBody(req: IncomingMessage, max: number): Promise<Buffer | 'tooLarge'> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > max) return 'tooLarge';
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export async function startBoundaryListener(options: StartListenerOptions): Promise<BoundaryListener> {
  const max = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const server: Server = createServer((req, res) => {
    void handle(req, res).catch((err) => {
      options.onError?.(err);
      if (!res.headersSent) respond(res, 500, minimal('internalError', 'The request could not be processed.', true));
      else res.end();
    });
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = (req.url ?? '').split('?')[0];
    // Other paths and methods are plain HTTP refusals with no body and no Content-Type: bindings/https section 2 says these
    // answers are not framework error documents.
    if (url !== LISTENER_PATH) return respond(res, 404);
    if (req.method !== 'POST') {
      res.setHeader('allow', 'POST');
      return respond(res, 405);
    }
    const ctype = String(req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
    if (ctype !== 'application/json') return respond(res, 415, minimal('unsupportedMediaType', 'Content-Type must be application/json.'));
    const body = await readBody(req, max);
    if (body === 'tooLarge') return respond(res, 413, minimal('malformedRequest', 'The document is too large.'));
    // Unless the deployment supplies `authenticate`, no cookie, bearer token or other credential is consulted: the pipeline
    // authenticates by proof alone.
    const result = await options.process({ raw: body, sender: options.authenticate?.(req) });
    if (result.minimal !== undefined) return respond(res, result.status, result.minimal);
    if (result.document !== undefined) return respond(res, result.status, result.document);
    return respond(res, result.status);
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port, options.host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const addr = server.address() as AddressInfo;
  return {
    port: addr.port,
    host: options.host,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}
