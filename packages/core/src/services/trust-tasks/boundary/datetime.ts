// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

// parseDateTimeStamp below is adapted from the `@openvtc/trust-tasks-proof` package, version 0.2.0
// (dist/verifier.js), Copyright its authors, licensed under the Apache License, Version 2.0
// (http://www.apache.org/licenses/LICENSE-2.0). That package does not export it, so it is copied
// here with a type annotation and this attribution; see NOTICE.
//
// One deliberate difference: the original caps the UTC offset at 14:00, whereas the shared fixture
// `fixtures/consume/timestamps.json` (and the registry runtime's own reader, which accepts offsets
// up to 23:59) treats hours 0-23 and minutes 0-59 as valid, so offsets such as `-23:59` and `+23:59`
// are read here. The behaviour is checked against that fixture.

const DATE_TIME_STAMP_PARTS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/**
 * `value` as epoch milliseconds when it is a dateTimeStamp with every field in range (month 1-12,
 * a day the month has, leap years included, hour 0-23, minute and second 0-59 with no leap second,
 * an offset of hours 0-23 and minutes 0-59), else `undefined`. `Date.parse` alone accepts 24:00
 * and rolls 2027-02-30 into March, so ranges are checked explicitly.
 */
export function parseDateTimeStamp(value: string): number | undefined {
  const m = DATE_TIME_STAMP_PARTS.exec(value);
  if (m === null) return undefined;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth || hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }
  let offsetMinutes = 0;
  if (m[8] !== undefined) {
    const oh = Number(m[9]);
    const om = Number(m[10]);
    if (oh > 23 || om > 59) return undefined;
    offsetMinutes = (m[8] === "+" ? 1 : -1) * (oh * 60 + om);
  }
  const fractionMs = m[7] === undefined ? 0 : Number(`0${m[7]}`) * 1000;
  const utc = new Date(0);
  utc.setUTCFullYear(year, month - 1, day);
  utc.setUTCHours(hour, minute, second, 0);
  return utc.getTime() + fractionMs - offsetMinutes * 60_000;
}
