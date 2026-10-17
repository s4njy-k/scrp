import { pino, type Logger } from 'pino';

/**
 * Structured, bounded logs. Cookies, authorization material and captured
 * tokens are redacted from general logs (§13); they exist only in restricted
 * artifacts.
 */
export const logger: Logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  base: { service: process.env.COLLECTOR_ROLE ?? 'cli' },
  redact: {
    paths: [
      '*.cookie', '*.Cookie', '*["set-cookie"]', '*.authorization', '*.Authorization',
      '*.password', '*.storageState', 'headers.cookie', 'headers.authorization',
      'DATABASE_URL', '*.DATABASE_URL', '*.connectionString',
    ],
    censor: '[redacted]',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

/** Truncate untrusted text before it reaches a log line. */
export function bounded(value: unknown, max = 500): string {
  const text = typeof value === 'string' ? value : value instanceof Error ? `${value.name}: ${value.message}` : JSON.stringify(value);
  if (text === undefined) return String(value);
  return text.length > max ? `${text.slice(0, max)}…[+${text.length - max} chars]` : text;
}
