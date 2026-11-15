// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers


/** Shared listener settings and the structured log line: default off, strict once on, no secrets in logs. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { formatBoundaryEvent, isExposedHost, resolveBoundaryListenerSettings } from "../../../../src/services/trust-tasks/boundary/process-config.ts";

describe("resolveBoundaryListenerSettings", () => {
  it("DEFAULT OFF: nothing resolves without the explicit switch, whatever else is set", () => {
    assert.equal(resolveBoundaryListenerSettings({}), null);
    assert.equal(resolveBoundaryListenerSettings({ TRUST_TASKS_LISTENER_PORT: "4000", TRUST_TASKS_TIER: "banana" }), null);
    assert.equal(resolveBoundaryListenerSettings({ TRUST_TASKS_LISTENER: "0", TRUST_TASKS_LISTENER_PORT: "4000" }), null);
    assert.equal(resolveBoundaryListenerSettings({ TRUST_TASKS_LISTENER: "true", TRUST_TASKS_LISTENER_PORT: "4000" }), null, "only 1 switches it on");
  });

  it("on: an explicit port is mandatory and a reserved port is refused; defaults are loopback, Tier 2, hold", () => {
    assert.throws(() => resolveBoundaryListenerSettings({ TRUST_TASKS_LISTENER: "1" }), /no valid port/);
    for (const port of ["0", "70000", "abc", "1.5", ""]) assert.throws(() => resolveBoundaryListenerSettings({ TRUST_TASKS_LISTENER: "1", TRUST_TASKS_LISTENER_PORT: port }), /no valid port/, port);
    assert.throws(() => resolveBoundaryListenerSettings({ TRUST_TASKS_LISTENER: "1", TRUST_TASKS_LISTENER_PORT: "3000" }, {}, [3000]), /reserved for the UI/);
    assert.deepEqual(resolveBoundaryListenerSettings({ TRUST_TASKS_LISTENER: "1", TRUST_TASKS_LISTENER_PORT: "4000" }), { host: "127.0.0.1", port: 4000, tier: 2, proposePolicy: "hold" });
  });

  it("on: a bad tier, policy or host throws instead of reading as a default", () => {
    const base = { TRUST_TASKS_LISTENER: "1", TRUST_TASKS_LISTENER_PORT: "4000" };
    assert.throws(() => resolveBoundaryListenerSettings({ ...base, TRUST_TASKS_TIER: "3" }), /TRUST_TASKS_TIER/);
    assert.throws(() => resolveBoundaryListenerSettings({ ...base, TRUST_TASKS_TIER: "one" }), /TRUST_TASKS_TIER/);
    assert.throws(() => resolveBoundaryListenerSettings({ ...base, TRUST_TASKS_PROPOSE_POLICY: "accept" }), /PROPOSE_POLICY/);
    assert.throws(() => resolveBoundaryListenerSettings({ ...base, TRUST_TASKS_LISTENER_HOST: "  " }), /HOST/);
    assert.equal(resolveBoundaryListenerSettings({ ...base, TRUST_TASKS_TIER: "1", TRUST_TASKS_PROPOSE_POLICY: "decline" })!.tier, 1);
  });

  it("flags exposed hosts", () => {
    assert.equal(isExposedHost("127.0.0.1"), false);
    assert.equal(isExposedHost("localhost"), false);
    assert.equal(isExposedHost("0.0.0.0"), true);
    assert.equal(isExposedHost("10.0.0.5"), true);
  });
});

describe("formatBoundaryEvent", () => {
  it("is one JSON line and never prints sensitive names or binary values", () => {
    const line = formatBoundaryEvent("signer.installed", { generation: 2, fingerprint: "ab12", passphrase: "hunter2", secretKey: new Uint8Array([1, 2, 3]), seedHex: "ff", note: { nested: "x" }, bearerToken: "t", gone: undefined });
    assert.match(line, /^\[trust-tasks\] \{/);
    const parsed = JSON.parse(line.slice("[trust-tasks] ".length)) as Record<string, unknown>;
    assert.deepEqual(parsed, { event: "signer.installed", generation: 2, fingerprint: "ab12", passphrase: "[redacted]", secretKey: "[redacted]", seedHex: "[redacted]", note: "[redacted]", bearerToken: "[redacted]" });
    assert.equal(line.includes("hunter2"), false);
  });
});
