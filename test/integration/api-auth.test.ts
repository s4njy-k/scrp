/**
 * Analyst API access control (checklist §7, §9, §11): sign-in with MFA
 * enrolment and forced password change, CSRF and cross-site refusal, lockout,
 * session revocation, object-level (case) authorisation, security headers.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from '../../src/db/pool.js';
import { totpCode } from '../../src/web/auth.js';
import type { ApiApp } from '../../src/web/server.js';
import { ApiClient, loggedIn, seedUser, startApi, TEST_PASSWORD } from '../apiHelpers.js';
import { freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

describe.skipIf(!hasDb)('analyst API: authentication and authorisation', () => {
  let pool: Pool;
  let app: ApiApp;
  let base: string;
  let cleanup: () => Promise<void>;
  const policy = testPolicy({ web: { lockout_after_failed_logins: 3, login_attempts_per_minute: 60 } });

  beforeAll(async () => {
    pool = await freshDb(policy);
    const t = await tempRoot();
    cleanup = t.cleanup;
    ({ app, base } = await startApi(pool, policy, t.root));
  });
  afterAll(async () => {
    await app.close();
    await pool.end();
    await cleanup();
  });

  it('walks a new account through MFA enrolment and a forced password change before any data access', async () => {
    await seedUser(pool, 'newbie', ['analyst'], { totp: false, mustChange: true });
    const c = new ApiClient(base);
    const login = await c.post('/api/v1/auth/login', { username: 'newbie', password: TEST_PASSWORD });
    expect(login.status).toBe(200);
    expect(login.body.next).toBe('enrol_mfa');
    expect(login.headers.get('set-cookie')).toMatch(/HttpOnly; SameSite=Strict/);
    expect((await c.get('/api/v1/cases')).body.error.code).toBe('mfa_enrolment_required');

    const enrol = await c.post('/api/v1/auth/mfa/enrol');
    expect(enrol.body.otpauth_uri).toMatch(/^otpauth:\/\/totp\//);
    expect((await c.post('/api/v1/auth/mfa/confirm', { code: '000000' })).status).toBe(400);
    const counter = Math.floor(Date.now() / 30_000);
    const confirm = await c.post('/api/v1/auth/mfa/confirm', { code: totpCode(enrol.body.secret, counter) });
    expect(confirm.status).toBe(200);
    expect(confirm.body.next).toBe('change_password');
    expect((await c.get('/api/v1/cases')).body.error.code).toBe('password_change_required');

    expect((await c.post('/api/v1/auth/password', { current_password: TEST_PASSWORD, new_password: 'short' })).body.error.code).toBe('weak_password');
    const changed = await c.post('/api/v1/auth/password', { current_password: TEST_PASSWORD, new_password: 'a much longer passphrase 42' });
    expect(changed.status).toBe(200);
    expect((await c.get('/api/v1/cases')).status).toBe(200);

    // A TOTP code is single-use: replaying the enrolment code at the next sign-in fails.
    const again = new ApiClient(base);
    expect((await again.post('/api/v1/auth/login', { username: 'newbie', password: 'a much longer passphrase 42' })).body.next).toBe('mfa');
    expect((await again.post('/api/v1/auth/mfa/verify', { code: totpCode(enrol.body.secret, counter) })).body.error.code).toBe('invalid_code');
  });

  it('refuses requests without a CSRF token or from another site, and sets security headers', async () => {
    const { client } = await loggedIn(base, pool, 'alice', ['analyst']);
    const noToken = await client.call('POST', '/api/v1/cases', { case_ref: 'C-1', title: 't' }, { headers: { 'x-csrf-token': 'wrong' } });
    expect(noToken.status).toBe(403);
    expect(noToken.body.error.code).toBe('csrf_failed');
    const crossSite = await client.call('POST', '/api/v1/cases', { case_ref: 'C-1', title: 't' }, { headers: { 'sec-fetch-site': 'cross-site' } });
    expect(crossSite.body.error.code).toBe('cross_site');
    const evilOrigin = await client.call('POST', '/api/v1/cases', { case_ref: 'C-1', title: 't' }, { headers: { origin: 'https://evil.example' } });
    expect(evilOrigin.body.error.code).toBe('cross_site');
    const ok = await client.post('/api/v1/cases', { case_ref: 'C-1', title: 'Refund scam cluster' });
    expect(ok.status).toBe(201);
    expect(ok.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(ok.headers.get('x-content-type-options')).toBe('nosniff');
    expect(ok.headers.get('x-frame-options')).toBe('DENY');
    expect(ok.headers.get('cache-control')).toBe('no-store');
    expect((await fetch(`${base}/..%2f..%2fpackage.json`)).status).toBe(404);
    expect((await fetch(`${base}/api/v1/nope`)).status).toBe(404);
  });

  it('enforces case-level object authorisation and masks restricted references for administrators outside the case', async () => {
    const owner = await loggedIn(base, pool, 'owner1', ['analyst']);
    const other = await loggedIn(base, pool, 'outsider', ['analyst']);
    const admin = await loggedIn(base, pool, 'admin1', ['admin']);
    const created = await owner.client.post('/api/v1/cases', { case_ref: 'NCRP-CASE-9', title: 'Loan app cluster', ncrp_refs: ['31121234567781'], fir_refs: ['FIR/123/2026'] });
    const id = created.body.id as string;

    // Outsiders cannot see or probe the case: 404, not 403.
    expect((await other.client.get(`/api/v1/cases/${id}`)).status).toBe(404);
    expect((await other.client.get('/api/v1/cases')).body.items.map((c: { id: string }) => c.id)).not.toContain(id);
    const asAdmin = await admin.client.get(`/api/v1/cases/${id}`);
    expect(asAdmin.status).toBe(200);
    expect(asAdmin.body.refs_masked).toBe(true);
    expect(asAdmin.body.ncrp_refs[0]).toBe('3112…7781');
    expect((await owner.client.get(`/api/v1/cases/${id}`)).body.ncrp_refs[0]).toBe('31121234567781');

    expect((await owner.client.post(`/api/v1/cases/${id}/members`, { username: 'outsider', case_role: 'viewer', reason: 'joint review' })).status).toBe(200);
    expect((await other.client.get(`/api/v1/cases/${id}`)).status).toBe(200);
    expect((await other.client.patch(`/api/v1/cases/${id}`, { expected_version: 1, title: 'x', reason: 'try' })).status).toBe(403);

    // Optimistic concurrency.
    expect((await owner.client.patch(`/api/v1/cases/${id}`, { title: 'no version', reason: 'edit' })).body.error.code).toBe('version_required');
    expect((await owner.client.patch(`/api/v1/cases/${id}`, { expected_version: 1, title: 'Loan app cluster (renamed)', reason: 'clarify' })).body.version).toBe(2);
    expect((await owner.client.patch(`/api/v1/cases/${id}`, { expected_version: 1, title: 'stale', reason: 'stale edit' })).body.error.code).toBe('version_conflict');
    expect((await owner.client.del(`/api/v1/cases/${id}/members/${owner.user.id}`)).body.error.code).toBe('last_owner');

    const viewed = (await pool.query(`SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'case_viewed' AND object_id = $1`, [id])).rows[0].n;
    expect(viewed).toBeGreaterThanOrEqual(3);
  });

  it('locks accounts after repeated failures and revokes sessions when an administrator disables a user', async () => {
    const victim = await seedUser(pool, 'bob', ['analyst']);
    const c = new ApiClient(base);
    for (let i = 0; i < 3; i += 1) expect((await c.post('/api/v1/auth/login', { username: 'bob', password: 'wrong password!!' })).status).toBe(401);
    expect((await c.post('/api/v1/auth/login', { username: 'bob', password: TEST_PASSWORD })).status).toBe(401);
    await pool.query(`UPDATE users SET locked_until = NULL, failed_logins = 0 WHERE username = 'bob'`);

    const bob = new ApiClient(base);
    await bob.login('bob', victim.totpSecret);
    expect((await bob.get('/api/v1/cases')).status).toBe(200);
    const admin = await loggedIn(base, pool, 'admin2', ['admin']);
    expect((await admin.client.patch(`/api/v1/admin/users/${victim.id}`, { disabled: true, reason: 'left the unit' })).body.sessions_revoked).toBe(1);
    expect((await bob.get('/api/v1/cases')).status).toBe(401);
    expect((await admin.client.patch(`/api/v1/admin/users/${admin.user.id}`, { disabled: true, reason: 'oops' })).body.error.code).toBe('self_lockout');
    expect((await bob.get('/api/v1/admin/users')).status).toBe(401);
    const analyst = await loggedIn(base, pool, 'carol', ['analyst']);
    expect((await analyst.client.get('/api/v1/admin/users')).status).toBe(403);
    const failed = (await pool.query(`SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'login_failed'`)).rows[0].n;
    expect(failed).toBeGreaterThanOrEqual(4);
    // Passwords never reach the audit log.
    const leaked = (await pool.query(`SELECT count(*)::int AS n FROM audit_events WHERE details::text ILIKE '%battery staple%'`)).rows[0].n;
    expect(leaked).toBe(0);
  });
});
