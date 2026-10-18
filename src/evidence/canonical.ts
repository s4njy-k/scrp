/**
 * Deterministic JSON serialisation for hashing (blueprint v4 §23.3).
 *
 * Object keys are sorted by UTF-16 code unit order, no insignificant
 * whitespace, `undefined` members dropped, numbers in ECMAScript shortest
 * form. This matches RFC 8785 (JCS) for the value types the collector emits
 * (strings, finite numbers, booleans, null, arrays, plain objects).
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new Error('canonicalJson: non-finite number');
      return JSON.stringify(value);
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'object': {
      if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',')}]`;
      const entries = Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v !== undefined && typeof v !== 'function')
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
    }
    default:
      throw new Error(`canonicalJson: unsupported type ${typeof value}`);
  }
}
