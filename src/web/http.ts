/**
 * Minimal, explicit HTTP layer for the analyst API (blueprint v4 §22.2,
 * §23.2, §27.1). Deliberately small: every route declares its method, path,
 * authentication level, roles, CSRF requirement and body limit; nothing is
 * implicit. No framework, so the attack surface is this file.
 */
import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { logger } from '../observability/logger.js';

export class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly details?: unknown) {
    super(message);
  }
}

export const badRequest = (code: string, message: string, details?: unknown) => new HttpError(400, code, message, details);
export const forbidden = (message = 'not permitted', code = 'forbidden') => new HttpError(403, code, message);
export const notFound = (message = 'not found') => new HttpError(404, 'not_found', message);
export const conflict = (code: string, message: string, details?: unknown) => new HttpError(409, code, message, details);

export type Role = 'admin' | 'intake' | 'analyst' | 'approver' | 'evidence' | 'auditor' | 'report';
export const ROLES: readonly Role[] = ['admin', 'intake', 'analyst', 'approver', 'evidence', 'auditor', 'report'];

export interface AuthedUser {
  id: string;
  username: string;
  displayName: string;
  roles: Role[];
  sessionId: string;
  mfaVerified: boolean;
  mustChangePassword: boolean;
  totpEnabled: boolean;
  csrfToken: string;
}

export interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  method: string;
  url: URL;
  params: Record<string, string>;
  requestId: string;
  ip: string;
  user: AuthedUser | null;
  body: unknown;
  rawBody: Buffer | null;
  /** Response headers added by the handler (merged with security headers). */
  headers: Record<string, string>;
}

/**
 * 'none': public (login, static assets). 'password': a valid session that may
 * still need MFA or a password change (only the endpoints that complete those
 * steps). 'full': MFA satisfied (when required) and no pending password change.
 */
export type AuthLevel = 'none' | 'password' | 'full';

export interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  auth: AuthLevel;
  /** Any one of these roles grants access ('admin' never implies other roles). */
  roles?: Role[];
  /** Raw body (uploads) instead of JSON. */
  body?: 'json' | 'raw' | 'none';
  maxBodyBytes?: number;
  /** Mutating routes require CSRF unless explicitly public (login). Defaults to true for non-GET. */
  csrf?: boolean;
  /** Rate-limit bucket name; defaults to the per-user API bucket. */
  rateBucket?: string;
  handler: (ctx: Ctx) => Promise<unknown>;
}

export interface Reply {
  status: number;
  body?: unknown;
  /** Stream or buffer bodies bypass JSON encoding. */
  raw?: Buffer | NodeJS.ReadableStream;
  contentType?: string;
  headers?: Record<string, string>;
}

export function reply(status: number, body?: unknown, headers?: Record<string, string>): Reply {
  return { status, body, ...(headers ? { headers } : {}) };
}

export const isReply = (v: unknown): v is Reply => Boolean(v && typeof v === 'object' && 'status' in v && typeof (v as Reply).status === 'number' && ('body' in v || 'raw' in v));

interface CompiledRoute extends RouteSpec {
  regex: RegExp;
  keys: string[];
}

export function compile(spec: RouteSpec): CompiledRoute {
  const keys: string[] = [];
  const pattern = spec.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/:([a-zA-Z_]+)/g, (_, k: string) => {
    keys.push(k);
    return '([^/]+)';
  });
  return { ...spec, regex: new RegExp(`^${pattern}$`), keys };
}

export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' blob: data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join('; ');

export function securityHeaders(hsts: boolean): Record<string, string> {
  return {
    'Content-Security-Policy': CSP,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=()',
    ...(hsts ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}),
  };
}

export async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const declared = Number(req.headers['content-length'] ?? 0);
  if (declared > limit) throw new HttpError(413, 'payload_too_large', `request body exceeds ${limit} bytes`);
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new HttpError(413, 'payload_too_large', `request body exceeds ${limit} bytes`);
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export function clientIp(req: IncomingMessage): string {
  // The API binds to loopback/private networks behind an SSH tunnel; X-Forwarded-For is not trusted.
  return req.socket.remoteAddress ?? 'unknown';
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k && !(k in out)) {
      try {
        out[k] = decodeURIComponent(v);
      } catch {
        out[k] = v;
      }
    }
  }
  return out;
}

export function newRequestId(req: IncomingMessage): string {
  const given = req.headers['x-request-id'];
  return typeof given === 'string' && /^[A-Za-z0-9._-]{8,80}$/.test(given) ? given : randomUUID();
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string>): void {
  const text = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, {
    ...headers,
    ...(text ? { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': String(Buffer.byteLength(text)) } : { 'Content-Length': '0' }),
  });
  res.end(text);
}

export function sendError(res: ServerResponse, err: unknown, requestId: string, headers: Record<string, string>): void {
  if (err instanceof HttpError) {
    sendJson(res, err.status, { error: { code: err.code, message: err.message, request_id: requestId, ...(err.details !== undefined ? { details: err.details } : {}) } }, headers);
    return;
  }
  logger.error({ err: (err as Error)?.message, stack: (err as Error)?.stack?.split('\n').slice(0, 4).join(' | '), request_id: requestId }, 'unhandled API error');
  sendJson(res, 500, { error: { code: 'internal_error', message: 'internal error', request_id: requestId } }, headers);
}

/** Simple token bucket used for login and per-user API limits (in-process; one API replica). */
export class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  constructor(private readonly ratePerSecond: number, private readonly burst: number) {}
  take(key: string, now = Date.now()): boolean {
    const b = this.buckets.get(key) ?? { tokens: this.burst, at: now };
    b.tokens = Math.min(this.burst, b.tokens + ((now - b.at) / 1000) * this.ratePerSecond);
    b.at = now;
    if (b.tokens < 1) {
      this.buckets.set(key, b);
      return false;
    }
    b.tokens -= 1;
    this.buckets.set(key, b);
    if (this.buckets.size > 50_000) this.buckets.clear();
    return true;
  }
}

/** Cursor helpers: opaque base64url of a JSON tuple; never trusted beyond type checks. */
export function encodeCursor(v: unknown[]): string {
  return Buffer.from(JSON.stringify(v)).toString('base64url');
}

export function decodeCursor(s: string | null): unknown[] | null {
  if (!s) return null;
  try {
    const v: unknown = JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
    return Array.isArray(v) && v.length <= 4 ? v : null;
  } catch {
    return null;
  }
}

export function queryInt(url: URL, key: string, def: number, min: number, max: number): number {
  const raw = url.searchParams.get(key);
  if (raw === null || raw === '') return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw badRequest('invalid_query', `${key} must be an integer between ${min} and ${max}`);
  return n;
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function requireUuid(v: string | undefined, name = 'id'): string {
  if (!v || !UUID_RE.test(v)) throw badRequest('invalid_id', `${name} must be a UUID`);
  return v;
}

export function requireIntId(v: string | undefined, name = 'id'): number {
  const n = Number(v);
  if (!v || !Number.isSafeInteger(n) || n <= 0) throw badRequest('invalid_id', `${name} must be a positive integer`);
  return n;
}
