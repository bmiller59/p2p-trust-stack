// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers


/**
 * Process-level configuration of the opt-in Trust Task listener, shared by the processes that host
 * it (the agent runtime and the utility server), plus the structured log line both emit.
 *
 * DEFAULT OFF: nothing is resolved, bound or logged unless `TRUST_TASKS_LISTENER=1` (or an explicit
 * override) switches it on, and then only with an explicit port: there is no default port. Once on,
 * every setting is validated strictly and a bad one THROWS instead of being read as a default (a
 * typo in `TRUST_TASKS_TIER` must not quietly select Tier 2, or Tier 1, by accident).
 */
export interface BoundaryListenerSettings {
  host: string;
  port: number;
  /** `2` is the attested profile (proof on every request, every reply signed): the default. */
  tier: 1 | 2;
  proposePolicy: 'hold' | 'decline';
}

export type ListenerEnvironment = Readonly<Record<string, string | undefined>>;

export function resolveBoundaryListenerSettings(
  env: ListenerEnvironment,
  override: Partial<BoundaryListenerSettings> & { enabled?: boolean } = {},
  forbiddenPorts: readonly number[] = [],
): BoundaryListenerSettings | null {
  const enabled = override.enabled ?? env.TRUST_TASKS_LISTENER === '1';
  if (!enabled) return null;
  const rawPort = override.port ?? (env.TRUST_TASKS_LISTENER_PORT === undefined ? undefined : Number(env.TRUST_TASKS_LISTENER_PORT));
  if (rawPort === undefined || !Number.isInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
    throw new Error('Trust Task listener is enabled but no valid port is configured (TRUST_TASKS_LISTENER_PORT)');
  }
  if (forbiddenPorts.includes(rawPort)) throw new Error(`Trust Task listener must not use port ${rawPort}: it is reserved for the UI`);
  const tierRaw = override.tier ?? env.TRUST_TASKS_TIER;
  let tier: 1 | 2;
  if (tierRaw === undefined || tierRaw === '') tier = 2;
  else if (tierRaw === 1 || tierRaw === '1') tier = 1;
  else if (tierRaw === 2 || tierRaw === '2') tier = 2;
  else throw new Error(`TRUST_TASKS_TIER must be 1 or 2, got ${JSON.stringify(String(tierRaw))}`);
  const policy = override.proposePolicy ?? env.TRUST_TASKS_PROPOSE_POLICY;
  if (policy !== undefined && policy !== '' && policy !== 'hold' && policy !== 'decline') {
    throw new Error(`TRUST_TASKS_PROPOSE_POLICY must be hold or decline, got ${JSON.stringify(String(policy))}`);
  }
  const host = override.host ?? env.TRUST_TASKS_LISTENER_HOST ?? '127.0.0.1';
  if (typeof host !== 'string' || host.trim() === '') throw new Error('TRUST_TASKS_LISTENER_HOST must not be empty');
  return { host: host.trim(), port: rawPort, tier, proposePolicy: policy === 'decline' ? 'decline' : 'hold' };
}

/** A host that is reachable from other machines (anything but loopback); the caller logs a warning. */
export function isExposedHost(host: string): boolean {
  return !(host === 'localhost' || host === '::1' || host === '[::1]' || /^127\./.test(host));
}

const SENSITIVE_NAME = /secret|passphrase|password|seed|private|token|cookie|authorization|mnemonic/i;

/**
 * One structured log line: `[trust-tasks] {"event":"...", ...}`. Field names that look sensitive
 * and any binary value (keys, buffers) are replaced by `"[redacted]"`, so a caller that passes the
 * wrong thing still cannot print it. Public identifiers and fingerprints are fine.
 */
export function formatBoundaryEvent(event: string, fields: Readonly<Record<string, unknown>> = {}): string {
  const safe: Record<string, unknown> = { event };
  for (const [name, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    const binary = value instanceof Uint8Array || (typeof value === 'object' && value !== null && !Array.isArray(value));
    safe[name] = SENSITIVE_NAME.test(name) || binary ? '[redacted]' : value;
  }
  return `[trust-tasks] ${JSON.stringify(safe)}`;
}
