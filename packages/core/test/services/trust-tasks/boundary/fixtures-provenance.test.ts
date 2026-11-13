// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { FIXTURES, fixture } from "./helpers.ts";

interface Provenance {
  commit: string;
  commitNote: string;
  files: { path: string; sha256: string }[];
}

describe("copied task-force fixtures carry provenance", () => {
  const prov = fixture<Provenance>("PROVENANCE.json");

  it("records the upstream commit, or states UNKNOWN with a reason", () => {
    assert.ok(/^[0-9a-f]{40}$/.test(prov.commit) || prov.commit === "UNKNOWN");
    if (prov.commit === "UNKNOWN") assert.ok(prov.commitNote.length > 40);
  });

  it("every listed file matches its recorded SHA-256 and every copied file is listed", () => {
    for (const f of prov.files) {
      const sha = createHash("sha256").update(readFileSync(join(FIXTURES, f.path))).digest("hex");
      assert.equal(sha, f.sha256, f.path);
    }
    const listed = new Set(prov.files.map((f) => f.path));
    for (const dir of ["consume", "proof"]) {
      for (const name of readdirSync(join(FIXTURES, dir))) assert.ok(listed.has(`${dir}/${name}`), `unlisted fixture ${dir}/${name}`);
    }
  });
});
