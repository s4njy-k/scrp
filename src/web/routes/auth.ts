/**
 * Sign-in, MFA (TOTP) enrolment/verification, password change and session
 * management, plus administrator user management (checklist §7, §9).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { withTransaction } from '../../db/pool.js';
import {
  clearSessionCookie, createSession, hashPassword, newTotpSecret, otpauthUri, passwordProblem, revokeAllSessions, revokeSession,
  sessionCookie, verifyPassword, verifyTotp,
} from '../auth.js';
import { badRequest, conflict, forbidden, HttpError, notFound, reply, requireUuid, ROLES, type Ctx, type RouteSpec } from '../http.js';
import { auditCtx, parseBody, type RouteDeps } from './common.js';

// A fixed scrypt hash used to equalise timing when the username does not exist.
const DUMMY_HASH = 'scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

interface UserRow {
  id: string;
  username: string;
  display_name: string;
  password_hash: string;
  roles: string[];
  totp_secret: string | null;
  totp_enabled: boolean;
  totp_last_counter: number | null;
  must_change_password: boolean;
  failed_logins: number;
  locked: boolean;
  disabled_at: Date | null;
}

export function generateTemporaryPassword(): string {
  // 18 random bytes → 24 base64url characters; satisfies the length policy.
  return randomBytes(18).toString('base64url');
}

function publicUser(ctx: Ctx) {
  const u = ctx.user!;
  return { id: u.id, username: u.username, display_name: u.displayName, roles: u.roles, mfa_verified: u.mfaVerified, totp_enabled: u.totpEnabled, must_change_password: u.mustChangePassword };
}

function nextStep(mfaRequired: boolean, s: { mfaVerified: boolean; totpEnabled: boolean; mustChangePassword: boolean }): 'mfa' | 'enrol_mfa' | 'change_password' | null {
  if (!s.mfaVerified) return s.totpEnabled ? 'mfa' : mfaRequired ? 'enrol_mfa' : null;
  if (s.mustChangePassword) return 'change_password';
  return null;
}

export function authRoutes(d: RouteDeps): RouteSpec[] {
  const w = d.policy.web;
  const sessionPolicy = { idleMinutes: w.session_idle_minutes, absoluteHours: w.session_absolute_hours, mfaRequired: w.mfa_required };
  const cookieFor = (token: string) => sessionCookie(token, { secure: w.cookie_secure, maxAgeSeconds: w.session_absolute_hours * 3600 });

  /** Replace the current session with a new one (after MFA or password change), preventing session fixation. */
  const rotate = async (ctx: Ctx, mfaVerified: boolean, reason: string) => {
    const s = await createSession(d.pool, ctx.user!.id, mfaVerified, sessionPolicy, { ip: ctx.ip, userAgent: ctx.req.headers['user-agent'] ?? null });
    await revokeSession(d.pool, ctx.user!.sessionId, reason);
    ctx.headers['Set-Cookie'] = cookieFor(s.token);
    return s;
  };

  return [
    {
      method: 'POST', path: '/api/v1/auth/login', auth: 'none', csrf: false, rateBucket: 'login', maxBodyBytes: 4096,
      handler: async (ctx) => {
        const b = parseBody(z.object({ username: z.string().min(1).max(64), password: z.string().min(1).max(256) }).strict(), ctx.body);
        const username = b.username.trim().toLowerCase();
        const u = (await d.pool.query<UserRow>(
          `SELECT id, username, display_name, password_hash, roles, totp_secret, totp_enabled, totp_last_counter, must_change_password,
                  failed_logins, (locked_until IS NOT NULL AND locked_until > now()) AS locked, disabled_at
             FROM users WHERE username = $1`, [username],
        )).rows[0];
        const ok = await verifyPassword(b.password, u?.password_hash ?? DUMMY_HASH);
        if (!u || u.disabled_at || u.locked || !ok) {
          if (u && !u.locked && !ok) {
            await d.pool.query(
              `UPDATE users SET failed_logins = failed_logins + 1,
                  locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END
                WHERE id = $1`, [u.id, w.lockout_after_failed_logins, w.lockout_minutes],
            );
          }
          await auditCtx(d.pool, ctx, 'login_failed', { username, reason: !u ? 'unknown_user' : u.disabled_at ? 'disabled' : u.locked ? 'locked' : 'bad_password' }, { outcome: 'denied', objectType: 'user', objectId: u?.id ?? null });
          throw new HttpError(401, 'invalid_credentials', 'invalid username or password, or the account is locked');
        }
        await d.pool.query('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1', [u.id]);
        const mfaVerified = !w.mfa_required && !u.totp_enabled;
        const s = await createSession(d.pool, u.id, mfaVerified, sessionPolicy, { ip: ctx.ip, userAgent: ctx.req.headers['user-agent'] ?? null });
        ctx.headers['Set-Cookie'] = cookieFor(s.token);
        await auditCtx(d.pool, ctx, 'login_succeeded', { username, mfa_pending: !mfaVerified }, { outcome: 'ok', objectType: 'user', objectId: u.id });
        return {
          user: { id: u.id, username: u.username, display_name: u.display_name, roles: u.roles },
          csrf_token: s.csrfToken,
          next: nextStep(w.mfa_required, { mfaVerified, totpEnabled: u.totp_enabled, mustChangePassword: u.must_change_password }),
          session_expires_at: s.expiresAt.toISOString(),
        };
      },
    },
    {
      method: 'POST', path: '/api/v1/auth/logout', auth: 'password',
      handler: async (ctx) => {
        await revokeSession(d.pool, ctx.user!.sessionId, 'logout');
        await auditCtx(d.pool, ctx, 'logout', {}, { objectType: 'user', objectId: ctx.user!.id });
        return reply(204, undefined, { 'Set-Cookie': clearSessionCookie(w.cookie_secure) });
      },
    },
    {
      method: 'GET', path: '/api/v1/auth/me', auth: 'password',
      handler: async (ctx) => ({
        user: publicUser(ctx),
        csrf_token: ctx.user!.csrfToken,
        next: nextStep(w.mfa_required, ctx.user!),
        policy: { mfa_required: w.mfa_required, show_utc_and_ist: true, page_size: w.paginated_list_limit_default },
      }),
    },
    {
      method: 'POST', path: '/api/v1/auth/mfa/enrol', auth: 'password',
      handler: async (ctx) => {
        if (ctx.user!.totpEnabled) throw conflict('mfa_already_enabled', 'TOTP is already enabled; an administrator must reset it first');
        const secret = newTotpSecret();
        await d.pool.query('UPDATE users SET totp_secret = $2 WHERE id = $1 AND NOT totp_enabled', [ctx.user!.id, secret]);
        await auditCtx(d.pool, ctx, 'mfa_enrolment_started', {}, { objectType: 'user', objectId: ctx.user!.id });
        // Shown once; the user adds it to an authenticator app, then confirms with a code.
        return { secret, otpauth_uri: otpauthUri(secret, ctx.user!.username) };
      },
    },
    {
      method: 'POST', path: '/api/v1/auth/mfa/confirm', auth: 'password', maxBodyBytes: 1024,
      handler: async (ctx) => {
        const { code } = parseBody(z.object({ code: z.string().regex(/^\d{6}$/) }).strict(), ctx.body);
        const r = (await d.pool.query<{ totp_secret: string | null; totp_enabled: boolean }>('SELECT totp_secret, totp_enabled FROM users WHERE id = $1', [ctx.user!.id])).rows[0];
        if (!r?.totp_secret || r.totp_enabled) throw conflict('no_pending_enrolment', 'start enrolment first');
        const counter = verifyTotp(r.totp_secret, code);
        if (counter === null) {
          await auditCtx(d.pool, ctx, 'mfa_enrolment_failed', {}, { outcome: 'denied', objectType: 'user', objectId: ctx.user!.id });
          throw badRequest('invalid_code', 'the code did not match; check the device clock and try again');
        }
        await d.pool.query('UPDATE users SET totp_enabled = true, totp_last_counter = $2 WHERE id = $1', [ctx.user!.id, counter]);
        const s = await rotate(ctx, true, 'mfa_enrolled');
        await auditCtx(d.pool, ctx, 'mfa_enrolled', {}, { outcome: 'ok', objectType: 'user', objectId: ctx.user!.id });
        return { csrf_token: s.csrfToken, next: ctx.user!.mustChangePassword ? 'change_password' : null };
      },
    },
    {
      method: 'POST', path: '/api/v1/auth/mfa/verify', auth: 'password', rateBucket: 'login', maxBodyBytes: 1024,
      handler: async (ctx) => {
        const { code } = parseBody(z.object({ code: z.string().regex(/^\d{6}$/) }).strict(), ctx.body);
        const r = (await d.pool.query<{ totp_secret: string | null; totp_enabled: boolean; totp_last_counter: number | null }>(
          'SELECT totp_secret, totp_enabled, totp_last_counter FROM users WHERE id = $1', [ctx.user!.id],
        )).rows[0];
        if (!r?.totp_enabled || !r.totp_secret) throw conflict('mfa_not_enrolled', 'TOTP is not enabled for this account');
        const counter = verifyTotp(r.totp_secret, code);
        // Replay protection: each time-step code is usable once.
        const upd = counter === null ? null : await d.pool.query(
          'UPDATE users SET totp_last_counter = $2 WHERE id = $1 AND (totp_last_counter IS NULL OR totp_last_counter < $2)', [ctx.user!.id, counter],
        );
        if (counter === null || !upd?.rowCount) {
          await auditCtx(d.pool, ctx, 'mfa_failed', { replay: counter !== null }, { outcome: 'denied', objectType: 'user', objectId: ctx.user!.id });
          throw badRequest('invalid_code', 'invalid or already used code');
        }
        const s = await rotate(ctx, true, 'mfa_verified');
        await auditCtx(d.pool, ctx, 'mfa_verified', {}, { outcome: 'ok', objectType: 'user', objectId: ctx.user!.id });
        return { csrf_token: s.csrfToken, next: ctx.user!.mustChangePassword ? 'change_password' : null };
      },
    },
    {
      method: 'POST', path: '/api/v1/auth/password', auth: 'password', maxBodyBytes: 4096,
      handler: async (ctx) => {
        const b = parseBody(z.object({ current_password: z.string().min(1).max(256), new_password: z.string().min(1).max(256) }).strict(), ctx.body);
        if (!ctx.user!.mfaVerified) throw forbidden('complete multi-factor authentication first', 'mfa_required');
        const u = (await d.pool.query<{ password_hash: string }>('SELECT password_hash FROM users WHERE id = $1', [ctx.user!.id])).rows[0]!;
        if (!(await verifyPassword(b.current_password, u.password_hash))) throw badRequest('invalid_credentials', 'current password is incorrect');
        const problem = passwordProblem(b.new_password, ctx.user!.username);
        if (problem) throw badRequest('weak_password', problem);
        if (b.new_password === b.current_password) throw badRequest('weak_password', 'new password must differ from the current one');
        await d.pool.query('UPDATE users SET password_hash = $2, must_change_password = false, password_changed_at = now() WHERE id = $1', [ctx.user!.id, await hashPassword(b.new_password)]);
        const revoked = await revokeAllSessions(d.pool, ctx.user!.id, 'password_changed', ctx.user!.sessionId);
        const s = await rotate(ctx, ctx.user!.mfaVerified, 'password_changed');
        await auditCtx(d.pool, ctx, 'password_changed', { other_sessions_revoked: revoked }, { outcome: 'ok', objectType: 'user', objectId: ctx.user!.id });
        return { csrf_token: s.csrfToken };
      },
    },
    {
      method: 'GET', path: '/api/v1/auth/sessions', auth: 'full',
      handler: async (ctx) => ({
        sessions: (await d.pool.query(
          `SELECT id, created_at, last_seen_at, expires_at, ip, user_agent, mfa_verified, (id = $2) AS current
             FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY last_seen_at DESC LIMIT 50`,
          [ctx.user!.id, ctx.user!.sessionId],
        )).rows,
      }),
    },

    // ---- Administration ----
    {
      method: 'GET', path: '/api/v1/admin/users', auth: 'full', roles: ['admin'],
      handler: async () => ({
        users: (await d.pool.query(
          `SELECT id, username, display_name, roles, totp_enabled, must_change_password, failed_logins, locked_until, disabled_at, created_at, password_changed_at,
                  (SELECT max(last_seen_at) FROM user_sessions s WHERE s.user_id = u.id) AS last_seen_at
             FROM users u ORDER BY username`,
        )).rows,
      }),
    },
    {
      method: 'POST', path: '/api/v1/admin/users', auth: 'full', roles: ['admin'],
      handler: async (ctx) => {
        const b = parseBody(z.object({
          username: z.string().regex(/^[a-z0-9][a-z0-9._-]{2,63}$/),
          display_name: z.string().min(1).max(200),
          roles: z.array(z.enum(ROLES as unknown as [string, ...string[]])).max(7),
        }).strict(), ctx.body);
        const temp = generateTemporaryPassword();
        const id = randomUUID();
        try {
          await d.pool.query(
            `INSERT INTO users (id, username, display_name, password_hash, roles, must_change_password, created_by) VALUES ($1,$2,$3,$4,$5,true,$6)`,
            [id, b.username, b.display_name, await hashPassword(temp), [...new Set(b.roles)], ctx.user!.username],
          );
        } catch (err) {
          if ((err as { code?: string }).code === '23505') throw conflict('username_taken', 'username already exists');
          throw err;
        }
        await auditCtx(d.pool, ctx, 'user_created', { username: b.username, roles: b.roles }, { objectType: 'user', objectId: id, outcome: 'ok' });
        return reply(201, { id, username: b.username, temporary_password: temp, note: 'Give this one-time password to the user over a separate channel; they must change it and enrol MFA at first sign-in.' });
      },
    },
    {
      method: 'PATCH', path: '/api/v1/admin/users/:id', auth: 'full', roles: ['admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const b = parseBody(z.object({
          display_name: z.string().min(1).max(200).optional(),
          roles: z.array(z.enum(ROLES as unknown as [string, ...string[]])).max(7).optional(),
          disabled: z.boolean().optional(),
          reason: z.string().min(3).max(500),
        }).strict(), ctx.body);
        if (id === ctx.user!.id && (b.disabled || (b.roles && !b.roles.includes('admin')))) throw forbidden('administrators cannot disable themselves or remove their own admin role', 'self_lockout');
        return withTransaction(d.pool, async (client) => {
          const cur = (await client.query<{ roles: string[]; disabled_at: Date | null }>('SELECT roles, disabled_at FROM users WHERE id = $1 FOR UPDATE', [id])).rows[0];
          if (!cur) throw notFound('user not found');
          await client.query(
            `UPDATE users SET display_name = COALESCE($2, display_name), roles = COALESCE($3, roles),
                disabled_at = CASE WHEN $4::boolean IS NULL THEN disabled_at WHEN $4 THEN COALESCE(disabled_at, now()) ELSE NULL END
              WHERE id = $1`,
            [id, b.display_name ?? null, b.roles ? [...new Set(b.roles)] : null, b.disabled ?? null],
          );
          // Privilege changes and disabling take effect immediately.
          const revoked = b.disabled || b.roles ? await revokeAllSessions(client, id, b.disabled ? 'account_disabled' : 'roles_changed') : 0;
          await auditCtx(client, ctx, 'user_updated', { before: cur, changes: { display_name: b.display_name, roles: b.roles, disabled: b.disabled }, reason: b.reason, sessions_revoked: revoked },
            { objectType: 'user', objectId: id, outcome: 'ok' });
          return { ok: true, sessions_revoked: revoked };
        });
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/users/:id/reset-credentials', auth: 'full', roles: ['admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const b = parseBody(z.object({ reset_mfa: z.boolean().default(false), reason: z.string().min(3).max(500) }).strict(), ctx.body);
        const temp = generateTemporaryPassword();
        const r = await d.pool.query(
          `UPDATE users SET password_hash = $2, must_change_password = true, failed_logins = 0, locked_until = NULL,
              totp_enabled = CASE WHEN $3 THEN false ELSE totp_enabled END, totp_secret = CASE WHEN $3 THEN NULL ELSE totp_secret END,
              totp_last_counter = CASE WHEN $3 THEN NULL ELSE totp_last_counter END
            WHERE id = $1`, [id, await hashPassword(temp), b.reset_mfa],
        );
        if (!r.rowCount) throw notFound('user not found');
        const revoked = await revokeAllSessions(d.pool, id, 'credentials_reset');
        await auditCtx(d.pool, ctx, 'user_credentials_reset', { reset_mfa: b.reset_mfa, reason: b.reason, sessions_revoked: revoked }, { objectType: 'user', objectId: id, outcome: 'ok' });
        return { temporary_password: temp, sessions_revoked: revoked };
      },
    },
  ];
}
