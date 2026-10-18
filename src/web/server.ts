/**
 * Analyst API and UI server (blueprint v4 §22, §23.2). Binds to loopback (or a
 * private network) only; public ingress is disabled by default and access is
 * through an SSH tunnel or an approved reverse proxy.
 */
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Policy } from '../config/policy.js';
import type { Pool } from '../db/pool.js';
import { logger } from '../observability/logger.js';
import { resolveSession, SESSION_COOKIE, safeEqual, type SessionPolicy } from './auth.js';
import {
  clientIp, compile, forbidden, HttpError, isReply, newRequestId, parseCookies, RateLimiter, readBody, securityHeaders, sendError, sendJson,
  type Ctx, type Reply, type RouteSpec,
} from './http.js';

export const DEFAULT_STATIC_DIR = fileURLToPath(new URL('../../web/', import.meta.url));

export interface AppDeps {
  pool: Pool;
  policy: Policy;
  root: string;
  staticDir?: string;
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

export class ApiApp {
  private readonly routes: ReturnType<typeof compile>[] = [];
  private readonly loginLimiter: RateLimiter;
  private readonly apiLimiter: RateLimiter;
  readonly sessionPolicy: SessionPolicy;
  private server: Server | null = null;
  private readonly staticCache = new Map<string, { body: Buffer; etag: string; type: string }>();

  constructor(readonly deps: AppDeps) {
    const w = deps.policy.web;
    this.loginLimiter = new RateLimiter(w.login_attempts_per_minute / 60, w.login_attempts_per_minute);
    this.apiLimiter = new RateLimiter(w.api_requests_per_second, w.api_requests_per_second * 3);
    this.sessionPolicy = { idleMinutes: w.session_idle_minutes, absoluteHours: w.session_absolute_hours, mfaRequired: w.mfa_required };
  }

  register(...specs: RouteSpec[]): void {
    for (const s of specs) this.routes.push(compile(s));
  }

  /** Route table for documentation tests (OpenAPI coverage). */
  routeTable(): { method: string; path: string; auth: string; roles: string[] }[] {
    return this.routes.map((r) => ({ method: r.method, path: r.path, auth: r.auth, roles: r.roles ?? [] }));
  }

  baseHeaders(requestId: string): Record<string, string> {
    return { ...securityHeaders(this.deps.policy.web.hsts), 'X-Request-Id': requestId };
  }

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const requestId = newRequestId(req);
    const headers = this.baseHeaders(requestId);
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://collector.local');
    } catch {
      sendJson(res, 400, { error: { code: 'bad_url', message: 'malformed URL', request_id: requestId } }, headers);
      return;
    }
    const method = (req.method ?? 'GET').toUpperCase();
    try {
      if (url.pathname.startsWith('/api/')) {
        await this.dispatch(req, res, method, url, requestId, headers);
      } else {
        await this.serveStatic(req, res, method, url, headers);
      }
    } catch (err) {
      if (!res.headersSent) sendError(res, err, requestId, { ...headers, 'Cache-Control': 'no-store' });
      else res.destroy();
    }
  }

  private async dispatch(req: IncomingMessage, res: ServerResponse, method: string, url: URL, requestId: string, headers: Record<string, string>): Promise<void> {
    const path = url.pathname.replace(/\/+$/, '') || '/';
    let route: ReturnType<typeof compile> | undefined;
    let match: RegExpExecArray | null = null;
    let pathMatched = false;
    for (const r of this.routes) {
      const m = r.regex.exec(path);
      if (!m) continue;
      pathMatched = true;
      if (r.method === method) {
        route = r;
        match = m;
        break;
      }
    }
    if (!route || !match) throw new HttpError(pathMatched ? 405 : 404, pathMatched ? 'method_not_allowed' : 'not_found', pathMatched ? 'method not allowed' : 'no such endpoint');
    const params: Record<string, string> = {};
    route.keys.forEach((k, i) => {
      params[k] = decodeURIComponent(match![i + 1]!);
    });

    const ip = clientIp(req);
    const cookies = parseCookies(req.headers.cookie);
    const user = route.auth === 'none' ? null : await resolveSession(this.deps.pool, cookies[SESSION_COOKIE], this.sessionPolicy);

    if (route.auth !== 'none') {
      if (!user) throw new HttpError(401, 'unauthenticated', 'sign in required');
      if (route.auth === 'full') {
        if (!user.mfaVerified) throw new HttpError(403, this.deps.policy.web.mfa_required && !user.totpEnabled ? 'mfa_enrolment_required' : 'mfa_required', 'multi-factor authentication required');
        if (user.mustChangePassword) throw new HttpError(403, 'password_change_required', 'password change required');
      }
      if (route.roles && route.roles.length && !route.roles.some((r) => user.roles.includes(r))) {
        throw forbidden(`requires one of the roles: ${route.roles.join(', ')}`);
      }
    }

    // Rate limits: login by client address, everything else by user (or address when anonymous).
    const bucket = route.rateBucket ?? 'api';
    const limiter = bucket === 'login' ? this.loginLimiter : this.apiLimiter;
    if (!limiter.take(`${bucket}:${bucket === 'login' ? ip : user?.id ?? ip}`)) {
      throw new HttpError(429, 'rate_limited', 'too many requests; slow down');
    }

    const mutating = method !== 'GET';
    if (mutating && route.csrf !== false) {
      const token = req.headers['x-csrf-token'];
      if (!user || typeof token !== 'string' || !safeEqual(token, user.csrfToken)) throw forbidden('missing or invalid CSRF token', 'csrf_failed');
    }
    if (mutating) {
      // Defence in depth against cross-site requests (SameSite=Strict cookies are the first line).
      const site = req.headers['sec-fetch-site'];
      if (typeof site === 'string' && site !== 'same-origin' && site !== 'none') throw forbidden('cross-site request refused', 'cross_site');
      const origin = req.headers.origin;
      if (typeof origin === 'string' && origin !== 'null') {
        const host = req.headers.host;
        let originHost: string | null = null;
        try {
          originHost = new URL(origin).host;
        } catch { /* invalid */ }
        if (!host || originHost !== host) throw forbidden('cross-origin request refused', 'cross_site');
      }
    }

    let body: unknown = null;
    let rawBody: Buffer | null = null;
    const kind = route.body ?? (mutating ? 'json' : 'none');
    if (kind !== 'none') {
      const limit = route.maxBodyBytes ?? 256 * 1024;
      rawBody = await readBody(req, limit);
      if (kind === 'json') {
        if (rawBody.length === 0) body = {};
        else {
          const ct = String(req.headers['content-type'] ?? '');
          if (!/^application\/json\b/i.test(ct)) throw new HttpError(415, 'unsupported_media_type', 'expected application/json');
          try {
            body = JSON.parse(rawBody.toString('utf8'));
          } catch {
            throw new HttpError(400, 'invalid_json', 'request body is not valid JSON');
          }
        }
      }
    }

    const ctx: Ctx = { req, res, method, url, params, requestId, ip, user, body, rawBody, headers: {} };
    const result = await route.handler(ctx);
    if (res.writableEnded || res.headersSent) return; // handler streamed (SSE, downloads)
    const out: Reply = isReply(result) ? result : { status: result === undefined ? 204 : 200, body: result };
    const h = { ...headers, 'Cache-Control': 'no-store', ...ctx.headers, ...(out.headers ?? {}) };
    if (out.raw) {
      res.writeHead(out.status, { ...h, 'Content-Type': out.contentType ?? 'application/octet-stream' });
      if (Buffer.isBuffer(out.raw)) res.end(out.raw);
      else (out.raw as NodeJS.ReadableStream).pipe(res);
      return;
    }
    sendJson(res, out.status, out.body, h);
  }

  private async serveStatic(req: IncomingMessage, res: ServerResponse, method: string, url: URL, headers: Record<string, string>): Promise<void> {
    if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed', 'method not allowed');
    const dir = this.deps.staticDir ?? DEFAULT_STATIC_DIR;
    let rel: string;
    try {
      rel = decodeURIComponent(url.pathname);
    } catch {
      throw new HttpError(400, 'bad_url', 'malformed path');
    }
    if (rel === '/' || rel === '') rel = '/index.html';
    const base = resolve(dir) + sep;
    const abs = resolve(join(base, normalize(rel)));
    if (!abs.startsWith(base) || rel.includes('\0')) throw new HttpError(404, 'not_found', 'not found');
    const type = MIME[extname(abs).toLowerCase()];
    if (!type) throw new HttpError(404, 'not_found', 'not found');
    let entry = this.staticCache.get(abs);
    if (!entry) {
      const st = await stat(abs).catch(() => null);
      if (!st?.isFile()) throw new HttpError(404, 'not_found', 'not found');
      const body = await readFile(abs);
      entry = { body, etag: `"${createHash('sha256').update(body).digest('base64url').slice(0, 27)}"`, type };
      if (process.env.NODE_ENV === 'production') this.staticCache.set(abs, entry);
    }
    const h = { ...headers, 'Content-Type': entry.type, ETag: entry.etag, 'Cache-Control': 'no-cache' };
    if (req.headers['if-none-match'] === entry.etag) {
      res.writeHead(304, h).end();
      return;
    }
    res.writeHead(200, { ...h, 'Content-Length': String(entry.body.length) });
    res.end(method === 'HEAD' ? undefined : entry.body);
  }

  async listen(port: number, host: string): Promise<{ port: number }> {
    this.server = createServer((req, res) => void this.handle(req, res));
    this.server.headersTimeout = 20_000;
    this.server.requestTimeout = 120_000;
    this.server.keepAliveTimeout = 5_000;
    await new Promise<void>((resolve) => this.server!.listen(port, host, () => resolve()));
    const addr = this.server.address();
    const actual = typeof addr === 'object' && addr ? addr.port : port;
    logger.info({ port: actual, host }, 'analyst API listening');
    return { port: actual };
  }

  async close(): Promise<void> {
    if (!this.server) return;
    this.server.closeAllConnections?.();
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
  }
}
