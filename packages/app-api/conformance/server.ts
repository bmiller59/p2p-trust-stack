// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The truststackers conformance adapter as a JSON-RPC server for the DTGWG trust conformance suite.
 *
 *   node --conditions=development --experimental-strip-types --loader ./test-loader.mjs conformance/server.ts [options]
 *
 *   stdio (default)   newline-delimited JSON-RPC on stdin/stdout; exits when stdin closes
 *   --http <port>     JSON-RPC over HTTP POST on 127.0.0.1 (0 picks a port; the bound port is printed on stderr)
 *   --attested        claim Tier 2 (proof on every request, signed replies)
 *   --identity <k>    scid-vh (default) | key
 *   --carrier <c>     widget (default) | issue | none
 *   --name <n>        the implementation name in capabilities (reports and the matrix key on it)
 *   --no-issue / --no-witness-share / --no-ceremony   do not serve that task (ceremony documents: begin, co-sign, status, reset)
 *   --no-https        declare the in-process binding only (the HTTPS listener is not used; the https vectors are SKIP)
 *
 * Databases live in a temporary directory removed on exit (set TMPDIR to choose where). The real HOME,
 * config and state are never read or written.
 */
import { TruststackersAdapter } from './adapter.ts';
import type { TruststackersAdapterOptions } from './adapter.ts';
import { serveHttp, serveStdio } from './rpc.ts';

// Anything the libraries log must not reach stdout, which carries the protocol.
for (const m of ['log', 'info', 'debug', 'warn'] as const) console[m] = console.error.bind(console);

function parse(argv: string[]): { options: TruststackersAdapterOptions; http: number | undefined } {
  const options: TruststackersAdapterOptions = { witness: true };
  let http: number | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const next = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === '--attested') options.attested = true;
    else if (a === '--http') http = Number(next());
    else if (a === '--identity') {
      const v = next();
      if (v !== 'scid-vh' && v !== 'key') throw new Error('--identity must be scid-vh or key');
      options.identity = v;
    } else if (a === '--carrier') {
      const v = next();
      if (v !== 'widget' && v !== 'issue' && v !== 'none') throw new Error('--carrier must be widget, issue or none');
      options.carrier = v;
    } else if (a === '--no-issue') options.issue = false;
    else if (a === '--no-witness-share') options.witness = false;
    else if (a === '--no-ceremony') options.ceremony = false;
    else if (a === '--no-https') options.https = false;
    else if (a === '--name') options.name = next();
    else if (a === '--seed') options.seed = Number(next());
    else throw new Error(`unknown option ${a}`);
  }
  return { options, http };
}

async function main(): Promise<void> {
  const { options, http } = parse(process.argv.slice(2));
  const adapter = await TruststackersAdapter.create(options);
  try {
    if (http !== undefined) {
      const s = await serveHttp(adapter, http);
      console.error(`truststackers conformance adapter listening on http://127.0.0.1:${s.port}/`);
      await new Promise<void>((resolve) => {
        process.once('SIGINT', resolve);
        process.once('SIGTERM', resolve);
      });
      await s.close();
    } else {
      await serveStdio(adapter);
    }
  } finally {
    await adapter.dispose();
  }
}

main().then(
  () => process.exit(0),
  (err: unknown) => {
    console.error((err as Error)?.stack ?? String(err));
    process.exit(2);
  },
);
