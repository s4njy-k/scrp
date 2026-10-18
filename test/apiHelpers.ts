import { randomUUID } from 'node:crypto';
import type { Policy } from '../src/config/policy.js';
import type { Pool } from '../src/db/pool.js';
import { buildApp } from '../src/web/app.js';
import { hashPassword, newTotpSecret, totpCode } from '../src/web/auth.js';
import type { ApiApp } from '../src/web/server.js';

export const TEST_PASSWORD = 'correct horse battery staple';

export async function startApi(pool: Pool, policy: Policy, root: string): Promise<{ app: ApiApp; base: string }> {
  const app = buildApp({ pool, policy, root });
  const { port } = await app.listen(0, '127.0.0.1');
  return { app, base: `http://127.0.0.1:${port}` };
}

/** Create a ready-to-use account (password changed, TOTP enrolled) directly in the database. */
export async function seedUser(pool: Pool, username: string, roles: string[], o: { totp?: boolean; mustChange?: boolean } = {}): Promise<{ id: string; username: string; totpSecret: string | null }> {
  const id = randomUUID();
  const secret = o.totp === false ? null : newTotpSecret();
  await pool.query(
    `INSERT INTO users (id, username, display_name, password_hash, roles, totp_secret, totp_enabled, must_change_password, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'test')`,
    [id, username, username.toUpperCase(), await hashPassword(TEST_PASSWORD), roles, secret, secret !== null, o.mustChange ?? false],
  );
  return { id, username, totpSecret: secret };
}

export class ApiClient {
  cookie: string | null = null;
  csrf: string | null = null;
  lastTotpCounter = 0;
  constructor(readonly base: string) {}

  async call(method: string, path: string, body?: unknown, opts: { headers?: Record<string, string>; raw?: Buffer | string; contentType?: string } = {}): Promise<{ status: number; body: any; headers: Headers; text: string }> {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (this.cookie) headers.cookie = this.cookie;
    if (this.csrf && method !== 'GET' && !('x-csrf-token' in headers)) headers['x-csrf-token'] = this.csrf;
    let payload: string | Uint8Array | undefined;
    if (opts.raw !== undefined) {
      payload = opts.raw;
      headers['content-type'] = opts.contentType ?? 'application/octet-stream';
    } else if (body !== undefined) {
      payload = JSON.stringify(body);
      headers['content-type'] = 'application/json';
    }
    const res = await fetch(`${this.base}${path}`, { method, headers, body: payload as BodyInit | undefined });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      const v = /cwc_session=([^;]*)/.exec(setCookie)?.[1];
      this.cookie = v ? `cwc_session=${v}` : null;
    }
    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    if (parsed && typeof parsed === 'object' && 'csrf_token' in parsed && typeof (parsed as { csrf_token: unknown }).csrf_token === 'string') {
      this.csrf = (parsed as { csrf_token: string }).csrf_token;
    }
    return { status: res.status, body: parsed, headers: res.headers, text };
  }

  get = (p: string, h?: Record<string, string>) => this.call('GET', p, undefined, h ? { headers: h } : {});
  post = (p: string, b?: unknown, h?: Record<string, string>) => this.call('POST', p, b ?? {}, h ? { headers: h } : {});
  patch = (p: string, b?: unknown) => this.call('PATCH', p, b ?? {});
  del = (p: string) => this.call('DELETE', p);

  /** Full sign-in including the TOTP step; waits for a fresh time step if needed to avoid replay rejection. */
  async login(username: string, totpSecret: string | null, password = TEST_PASSWORD): Promise<void> {
    const r = await this.post('/api/v1/auth/login', { username, password });
    if (r.status !== 200) throw new Error(`login failed: ${r.status} ${r.text}`);
    if (totpSecret && r.body.next === 'mfa') {
      let counter = Math.floor(Date.now() / 30_000);
      if (counter <= this.lastTotpCounter) {
        await new Promise((res) => setTimeout(res, (this.lastTotpCounter + 1) * 30_000 - Date.now() + 50));
        counter = Math.floor(Date.now() / 30_000);
      }
      const v = await this.post('/api/v1/auth/mfa/verify', { code: totpCode(totpSecret, counter) });
      if (v.status !== 200) throw new Error(`mfa failed: ${v.status} ${v.text}`);
      this.lastTotpCounter = counter;
    }
  }
}

export async function loggedIn(base: string, pool: Pool, username: string, roles: string[]): Promise<{ client: ApiClient; user: { id: string; username: string; totpSecret: string | null } }> {
  const user = await seedUser(pool, username, roles);
  const client = new ApiClient(base);
  await client.login(username, user.totpSecret);
  return { client, user };
}
