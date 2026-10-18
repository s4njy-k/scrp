/**
 * Authentication primitives (checklist §7, §9; blueprint v4 §27.1):
 * scrypt password hashes, database-backed sessions storing only a token hash,
 * idle and absolute expiry, revocation, CSRF tokens, and RFC 6238 TOTP with
 * replay protection. SSO/OIDC is not configured in this release.
 */
import { createHash, createHmac, randomBytes, randomUUID, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import type { Pool, Queryable } from '../db/pool.js';
import type { AuthedUser, Role } from './http.js';

const scrypt = promisify(scryptCb) as (pw: string | Buffer, salt: Buffer, keylen: number, opts: { N: number; r: number; p: number; maxmem: number }) => Promise<Buffer>;
const SCRYPT = { N: 1 << 15, r: 8, p: 1, keylen: 32 };

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password.normalize('NFKC'), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 128 * SCRYPT.N * SCRYPT.r * 2 });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltB64, keyB64] = parts as [string, string, string, string, string, string];
  const N = Number(n);
  const R = Number(r);
  const P = Number(p);
  if (!Number.isInteger(N) || N < 1024 || N > 1 << 20 || R < 1 || R > 32 || P < 1 || P > 16) return false;
  const expected = Buffer.from(keyB64, 'base64');
  const got = await scrypt(password.normalize('NFKC'), Buffer.from(saltB64, 'base64'), expected.length, { N, r: R, p: P, maxmem: 128 * N * R * 2 });
  return got.length === expected.length && timingSafeEqual(got, expected);
}

/** Password policy: length over composition rules (NIST SP 800-63B), plus a small deny-list. */
export function passwordProblem(pw: string, username: string): string | null {
  if (pw.length < 12) return 'password must be at least 12 characters';
  if (pw.length > 256) return 'password must be at most 256 characters';
  const lower = pw.toLowerCase();
  if (lower.includes(username.toLowerCase())) return 'password must not contain the username';
  if (/^(.)\1+$/.test(pw)) return 'password must not be a single repeated character';
  if (['password1234', '123456789012', 'qwertyuiopas', 'changeme1234', 'welcome12345'].includes(lower)) return 'password is too common';
  return null;
}

export function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ---- TOTP (RFC 6238, SHA-1, 30 s, 6 digits; widely supported by authenticator apps) ----
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new Error('invalid base32');
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function totpCode(secretB32: string, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', base32Decode(secretB32)).update(msg).digest();
  const off = h[h.length - 1]! & 0x0f;
  const bin = ((h[off]! & 0x7f) << 24) | (h[off + 1]! << 16) | (h[off + 2]! << 8) | h[off + 3]!;
  return String(bin % 1_000_000).padStart(6, '0');
}

/** Returns the matched counter (±1 step) or null. The caller rejects counters <= the last used one. */
export function verifyTotp(secretB32: string, code: string, now = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const counter = Math.floor(now / 30_000);
  for (const c of [counter, counter - 1, counter + 1]) {
    if (safeEqual(totpCode(secretB32, c), code)) return c;
  }
  return null;
}

export function newTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

export function otpauthUri(secret: string, username: string, issuer = 'Cyber Web Collector'): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(username)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// ---- Sessions ----
export const SESSION_COOKIE = 'cwc_session';

export interface SessionPolicy {
  idleMinutes: number;
  absoluteHours: number;
  mfaRequired: boolean;
}

export async function createSession(db: Queryable, userId: string, mfaVerified: boolean, p: SessionPolicy, meta: { ip: string; userAgent: string | null }): Promise<{ token: string; sessionId: string; csrfToken: string; expiresAt: Date }> {
  const token = randomBytes(32).toString('base64url');
  const csrfToken = randomBytes(24).toString('base64url');
  const sessionId = randomUUID();
  const expiresAt = new Date(Date.now() + p.absoluteHours * 3600_000);
  await db.query(
    `INSERT INTO user_sessions (id, user_id, token_sha256, csrf_token, mfa_verified, expires_at, ip, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [sessionId, userId, sha256Hex(token), csrfToken, mfaVerified, expiresAt, meta.ip, meta.userAgent?.slice(0, 300) ?? null],
  );
  return { token, sessionId, csrfToken, expiresAt };
}

interface SessionRow {
  session_id: string;
  user_id: string;
  username: string;
  display_name: string;
  roles: Role[];
  mfa_verified: boolean;
  csrf_token: string;
  must_change_password: boolean;
  totp_enabled: boolean;
  idle_expired: boolean;
}

/** Resolve a session cookie; expired, revoked or disabled-user sessions resolve to null. Touches last_seen_at. */
export async function resolveSession(pool: Pool, token: string | undefined, p: SessionPolicy): Promise<AuthedUser | null> {
  if (!token || token.length > 200) return null;
  const { rows } = await pool.query<SessionRow>(
    `SELECT s.id AS session_id, u.id AS user_id, u.username, u.display_name, u.roles, s.mfa_verified, s.csrf_token,
            u.must_change_password, u.totp_enabled, (s.last_seen_at < now() - make_interval(mins => $2)) AS idle_expired
       FROM user_sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_sha256 = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.disabled_at IS NULL`,
    [sha256Hex(token), p.idleMinutes],
  );
  const r = rows[0];
  if (!r) return null;
  if (r.idle_expired) {
    await pool.query(`UPDATE user_sessions SET revoked_at = now(), revoked_reason = 'idle_timeout' WHERE id = $1 AND revoked_at IS NULL`, [r.session_id]);
    return null;
  }
  await pool.query(`UPDATE user_sessions SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval '30 seconds'`, [r.session_id]);
  return {
    id: r.user_id, username: r.username, displayName: r.display_name, roles: r.roles, sessionId: r.session_id,
    mfaVerified: r.mfa_verified || !p.mfaRequired, mustChangePassword: r.must_change_password, totpEnabled: r.totp_enabled, csrfToken: r.csrf_token,
  };
}

export async function revokeSession(db: Queryable, sessionId: string, reason: string): Promise<void> {
  await db.query(`UPDATE user_sessions SET revoked_at = now(), revoked_reason = $2 WHERE id = $1 AND revoked_at IS NULL`, [sessionId, reason]);
}

export async function revokeAllSessions(db: Queryable, userId: string, reason: string, exceptSessionId?: string): Promise<number> {
  const r = await db.query(
    `UPDATE user_sessions SET revoked_at = now(), revoked_reason = $2 WHERE user_id = $1 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id <> $3::uuid)`,
    [userId, reason, exceptSessionId ?? null],
  );
  return r.rowCount ?? 0;
}

export function sessionCookie(token: string, p: { secure: boolean; maxAgeSeconds: number }): string {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${p.maxAgeSeconds}${p.secure ? '; Secure' : ''}`;
}

export function clearSessionCookie(secure: boolean): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`;
}
