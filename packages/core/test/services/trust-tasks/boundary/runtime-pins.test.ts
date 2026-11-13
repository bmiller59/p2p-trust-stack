// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import {
  ACCEPTANCE_WINDOW,
  TRUST_TASKS_LIBRARY,
  TRUST_TASKS_LIBRARY_VERSION,
} from "../../../../src/services/trust-tasks/boundary/pins.ts";
import { selectMyVid } from "../../../../src/services/trust-tasks/boundary/runtime.ts";
import {
  DEFAULT_EXPIRY_HORIZON_MS,
  DEFAULT_MAX_AGE_MS,
  DEFAULT_SKEW_MS,
} from "@openvtc/trust-tasks/runtime";

const coreDir = join(import.meta.dirname, "..", "..", "..", "..");
const repoRoot = join(coreDir, "..", "..");
const require = createRequire(import.meta.url);

describe("library pin and licence", () => {
  const own = JSON.parse(readFileSync(join(coreDir, "package.json"), "utf8")) as { dependencies: Record<string, string> };

  it("package.json pins the library exactly (no range) at the version in pins.ts", () => {
    assert.equal(own.dependencies[TRUST_TASKS_LIBRARY], TRUST_TASKS_LIBRARY_VERSION);
    assert.match(TRUST_TASKS_LIBRARY_VERSION, /^\d+\.\d+\.\d+$/);
  });

  it("the installed library is that version, Apache-2.0, with no runtime dependencies", () => {
    // The exports map hides ./package.json; resolve the entry (dist/index.js) and go up one level.
    const pkgPath = join(dirname(require.resolve(TRUST_TASKS_LIBRARY)), "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string; license: string; dependencies?: object };
    assert.equal(pkg.version, TRUST_TASKS_LIBRARY_VERSION);
    assert.equal(pkg.license, "Apache-2.0");
    assert.deepEqual(Object.keys(pkg.dependencies ?? {}), []);
  });

  it("the repository dependency-licence check passes with the library in the closure", () => {
    const r = spawnSync(process.execPath, [join(repoRoot, "scripts", "check-dependency-licenses.mjs"), coreDir], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /no copyleft runtime dependencies/);
  });

  it("NOTICE lists the library and the copied helper's source package", () => {
    const notice = readFileSync(join(repoRoot, "NOTICE"), "utf8");
    assert.ok(notice.includes("@openvtc/trust-tasks"));
    assert.ok(notice.includes("@openvtc/trust-tasks-proof"));
  });

  it("only boundary/runtime.ts imports the library from src", () => {
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name.endsWith(".ts") && !p.endsWith(join("boundary", "runtime.ts"))) {
          if (readFileSync(p, "utf8").includes("@openvtc/trust-tasks")) offenders.push(p);
        }
      }
    };
    walk(join(coreDir, "src"));
    // datetime.ts names the proof package in an attribution comment only; it must not import it.
    const real = offenders.filter((p) => /from\s+["']@openvtc\//.test(readFileSync(p, "utf8")));
    assert.deepEqual(real, []);
  });
});

describe("pins equal the adopted runtime's defaults", () => {
  it("acceptance window", () => {
    assert.equal(ACCEPTANCE_WINDOW.skewMs, DEFAULT_SKEW_MS);
    assert.equal(ACCEPTANCE_WINDOW.maxAgeMs, DEFAULT_MAX_AGE_MS);
    assert.equal(ACCEPTANCE_WINDOW.expiryHorizonMs, DEFAULT_EXPIRY_HORIZON_MS);
  });
});

describe("selectMyVid (the library takes a single recipient VID)", () => {
  const served = ["did:web:a.example", "did:web:b.example"];
  it("picks the document's recipient when served", () => {
    assert.equal(selectMyVid({ recipient: "did:web:b.example" }, served, served[0]!), "did:web:b.example");
  });
  it("falls back to the default for an unserved, absent or non-string recipient", () => {
    assert.equal(selectMyVid({ recipient: "did:web:c.example" }, served, served[0]!), served[0]);
    assert.equal(selectMyVid({}, served, served[0]!), served[0]);
    assert.equal(selectMyVid({ recipient: 5 as unknown as string }, served, served[0]!), served[0]);
  });
  it("accepts a Set", () => {
    assert.equal(selectMyVid({ recipient: "did:web:b.example" }, new Set(served), served[0]!), "did:web:b.example");
  });
});
