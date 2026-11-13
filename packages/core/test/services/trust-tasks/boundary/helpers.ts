// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

import { readFileSync } from "node:fs";
import { join } from "node:path";

export const FIXTURES = join(import.meta.dirname, "fixtures");

export function fixture<T>(relative: string): T {
  return JSON.parse(readFileSync(join(FIXTURES, relative), "utf8")) as T;
}

export const CARRIER_TYPE = "https://trusttasks.org/spec/conformance/widget/0.1";
