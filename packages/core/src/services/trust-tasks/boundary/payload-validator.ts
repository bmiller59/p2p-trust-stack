// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * A deliberately small JSON Schema reader for the boundary's payload check (framework 7.2 item 2).
 * It understands `type` (object, array, string, number, integer, boolean, null), `required`,
 * `properties` (recursively) and `additionalProperties: false`; anything else in a schema is
 * ignored, so it can only under-refuse, never refuse a valid payload. Generated policies carry full
 * schemas; a complete validator is a later phase. It never throws.
 */
import type { PayloadValidator } from './runtime.js';

type Schema = {
  type?: string;
  required?: readonly string[];
  properties?: Record<string, Schema>;
  additionalProperties?: boolean;
};

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function typeOk(type: string, v: unknown): boolean {
  switch (type) {
    case 'object': return isObject(v);
    case 'array': return Array.isArray(v);
    case 'string': return typeof v === 'string';
    case 'number': return typeof v === 'number' && Number.isFinite(v);
    case 'integer': return typeof v === 'number' && Number.isInteger(v);
    case 'boolean': return typeof v === 'boolean';
    case 'null': return v === null;
    default: return true;
  }
}

function check(schema: Schema, value: unknown, path: string, errors: string[]): void {
  if (typeof schema.type === 'string' && !typeOk(schema.type, value)) {
    errors.push(`${path || 'payload'} must be ${schema.type}`);
    return;
  }
  if (!isObject(value)) return;
  for (const k of schema.required ?? []) if (!(k in value)) errors.push(`missing ${path ? `${path}.` : ''}${k}`);
  for (const [k, def] of Object.entries(schema.properties ?? {})) {
    if (k in value && isObject(def)) check(def, value[k], path ? `${path}.${k}` : k, errors);
  }
  if (schema.additionalProperties === false) {
    const known = new Set(Object.keys(schema.properties ?? {}));
    for (const k of Object.keys(value)) if (!known.has(k)) errors.push(`unexpected ${path ? `${path}.` : ''}${k}`);
  }
}

export const simplePayloadValidator: PayloadValidator = {
  validate(schema: unknown, payload: unknown): { ok: boolean; errors: string[] } {
    const errors: string[] = [];
    try {
      if (isObject(schema)) check(schema as Schema, payload, '', errors);
    } catch {
      errors.push('payload could not be checked');
    }
    return { ok: errors.length === 0, errors };
  },
};
