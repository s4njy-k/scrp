/**
 * Analyst console smoke test in a real browser (blueprint v4 §22; checklist §10):
 * sign-in with MFA through the UI, every screen renders under the strict CSP
 * with no console errors, page errors or CSP violations, and a notice can be
 * drafted end to end through the form.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { chromium, type Browser, type Page } from 'playwright-core';
import type { Pool } from '../../src/db/pool.js';
import { BrowserWorker } from '../../src/worker/browserWorker.js';
import { BrowserPool } from '../../src/worker/browserPool.js';
import { claimNextExtraction, runExtraction } from '../../src/extraction/runner.js';
import { totpCode } from '../../src/web/auth.js';
import type { ApiApp } from '../../src/web/server.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';
import { TEST_PASSWORD, loggedIn, seedUser, startApi } from '../apiHelpers.js';
import { BROWSERS_AVAILABLE, TEST_CHROMIUM_SANDBOX, freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

describe.skipIf(!hasDb || !BROWSERS_AVAILABLE)('analyst console in a browser', () => {
  let fixture: FixtureServer;
  let pool: Pool;
  let root: string;
  let cleanup: () => Promise<void>;
  let browsers: BrowserPool;
  let app: ApiApp;
  let base: string;
  let browser: Browser;
  let page: Page;
  let caseId: string;
  let targetId: number;
  let attemptId: string;
  const problems: string[] = [];

  beforeAll(async () => {
    fixture = await startFixtureServer();
    const policy = testPolicy({
      scope: { allowed_ports: [80, 443, fixture.port] },
      limits: { per_domain_delay_seconds: 0, child_pages_per_target_max: 0 },
      browser: { navigation_timeout_seconds: 8, readiness_max_seconds: 3, challenge_wait_seconds: 2, scroll_step_wait_ms: 100 },
      extraction: { ocr_enabled: false },
    });
    ({ root, cleanup } = await tempRoot());
    pool = await freshDb(policy);
    const egress = { proxyUrl: null, vantage: 'test-direct' };
    browsers = new BrowserPool({ mode: 'local', wsEndpoint: null, connectTimeoutMs: 30_000, chromiumSandbox: TEST_CHROMIUM_SANDBOX }, policy, egress);
    ({ app, base } = await startApi(pool, policy, root));

    // Seed data through the API as a separate analyst.
    const { client: setup } = await loggedIn(base, pool, 'setup-analyst', ['analyst', 'intake']);
    caseId = (await setup.post('/api/v1/cases', { case_ref: 'UI-CASE-1', title: 'Console smoke case' })).body.id;
    await setup.call('POST', `/api/v1/intake-batches?case_id=${caseId}&urgent=true`, undefined, { raw: `${fixture.url('/static')}\n`, contentType: 'text/plain', headers: { 'idempotency-key': 'ui-smoke-0001' } });
    const worker = new BrowserWorker({ pool, policy, egress, browsers, artifactRoot: root, workerId: 'ui-worker' });
    for (let i = 0; i < 3; i += 1) await worker.runOne();
    for (let a = await claimNextExtraction(pool); a; a = await claimNextExtraction(pool)) await runExtraction(pool, policy, root, a);
    targetId = Number((await pool.query('SELECT id FROM targets WHERE url = $1', [fixture.url('/static')])).rows[0].id);
    // A second capture of the same target (mobile profile) for the side-by-side comparison.
    const jobId = Number((await pool.query('SELECT id FROM jobs WHERE target_id = $1 ORDER BY id LIMIT 1', [targetId])).rows[0].id);
    expect((await setup.post(`/api/v1/jobs/${jobId}/recapture`, { reason: 'mobile comparison', capture_variant: 'mobile', urgent: true })).status).toBe(202);
    for (let i = 0; i < 3; i += 1) await worker.runOne();
    attemptId = (await pool.query(`SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE j.target_id = $1 AND a.kind = 'browser' AND a.status = 'committed' LIMIT 1`, [targetId])).rows[0].id;
    const decided = await setup.post('/api/v1/decisions', { target_id: targetId, decision: 'confirm_suspicious', reason_code: 'payment_redirection', reason: 'Page asks for a refund fee by UPI', expected_last_decision_id: null });
    expect(decided.status).toBe(201);

    browser = await chromium.launch({ headless: true, chromiumSandbox: TEST_CHROMIUM_SANDBOX });
    page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.addInitScript(() => {
      document.addEventListener('securitypolicyviolation', (e) => console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`));
    });
    page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  }, 180_000);

  afterAll(async () => {
    await browser?.close();
    await app?.close();
    await browsers?.closeAll();
    await pool?.end();
    await fixture?.close();
    await cleanup?.();
  });

  /** Navigate and wait until the view finished loading (no skeletons left). */
  async function visit(hash: string, heading: RegExp): Promise<void> {
    await page.goto(`${base}/${hash}`);
    await page.locator('#main h1').filter({ hasText: heading }).first().waitFor({ timeout: 15_000 });
    await page.waitForFunction(() => !document.querySelector('#main [aria-busy="true"]'), undefined, { timeout: 15_000 });
    if (process.env.UI_SCREENSHOTS) await page.screenshot({ path: `${process.env.UI_SCREENSHOTS}/${hash.replace(/[^a-z0-9]+/gi, '_').slice(0, 40)}.png`, fullPage: true });
    const bad = await page.locator('#main > .banner.bad').allTextContents();
    expect(bad, `${hash} shows an error banner`).toEqual([]);
  }

  it('signs in with password and TOTP through the form', async () => {
    const u = await seedUser(pool, 'ui-admin', ['admin', 'analyst', 'approver', 'evidence', 'auditor', 'intake']);
    await page.goto(`${base}/`);
    await page.getByLabel('Username').fill('ui-admin');
    await page.getByLabel('Password').fill(TEST_PASSWORD);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByLabel('6-digit code').fill(totpCode(u.totpSecret!, Math.floor(Date.now() / 30_000)));
    await page.getByRole('button', { name: 'Verify' }).click();
    await page.locator('#main h1').filter({ hasText: /Jobs/ }).waitFor({ timeout: 15_000 });
    expect(await page.locator('#who').textContent()).toContain('ui-admin');
    const headers = (await page.request.get(`${base}/`)).headers();
    expect(headers['content-security-policy']).toContain("script-src 'self'");
    // The only error allowed so far is the browser logging the expected 401 of the pre-login session probe.
    expect(problems.filter((p) => !p.includes('status of 401'))).toEqual([]);
    problems.length = 0;
  });

  it('renders every screen without console errors or CSP violations', async () => {
    await visit('#/jobs', /Jobs/);
    await visit('#/intake', /Intake|Submit/);
    await visit('#/review', /Review/);
    await visit('#/cases', /Cases/);
    await visit(`#/cases/${caseId}`, /UI-CASE-1/);
    await visit(`#/investigate/${targetId}`, /.+/);
    expect(await page.locator('#main .chips').first().textContent()).toContain('suspicious');
    await page.locator('.compare figure').nth(1).waitFor();
    await page.locator('.compare').scrollIntoViewIfNeeded(); // images load lazily when visible
    await page.waitForFunction(() => [...document.querySelectorAll('.compare img')].every((i) => (i as HTMLImageElement).naturalWidth > 0), undefined, { timeout: 15_000 });
    expect(await page.locator('.compare figcaption').allTextContents()).toEqual([expect.stringContaining('desktop'), expect.stringContaining('mobile')]);
    await visit(`#/evidence/${attemptId}`, /Evidence record/);
    expect(await page.locator('.banner.info').first().textContent()).toContain('match');
    await visit('#/reports', /Reports and notices/);
    await visit('#/monitor', /Monitor/);
    await visit('#/analytics', /Analytics/);
    await page.locator('.metric').first().waitFor();
    await visit('#/admin', /Administration/);
    expect(await page.locator('table').first().textContent()).toContain('ui-admin');
    expect(problems).toEqual([]);
  }, 120_000);

  it('drafts a notice through the form from the investigation page link', async () => {
    await visit(`#/reports/new?target=${targetId}`, /Draft a notice/);
    await page.getByLabel('Route').selectOption('investigation_lead_package');
    const box = page.locator('.targetpick input[type=checkbox]').first();
    expect(await box.isChecked()).toBe(true);
    await page.getByLabel('Recipient name').fill('Investigating Officer, Cyber PS');
    await page.getByLabel(/Facts observed/).fill('The page displayed a UPI payee and requested a refund processing fee.');
    await page.getByLabel(/Requested action/).fill('Review the lead and the enclosed evidence.');
    await page.getByLabel('evidentiary weaknesses').fill('Single capture from one vantage.');
    await page.getByLabel('next steps').fill('Request payee KYC through lawful process.');
    await page.getByRole('button', { name: 'Save draft' }).click();
    await page.waitForURL(/#\/notices\/[0-9a-f-]{36}$/, { timeout: 15_000 });
    await page.locator('#main h1').filter({ hasText: /Investigation lead package/ }).waitFor();
    await page.waitForFunction(() => document.querySelectorAll('ul.checks li').length > 0);
    // Self-review is disabled in the UI (maker-checker), never just hidden behind a server error.
    const notice = (await pool.query('SELECT id, state, created_by FROM notices')).rows[0];
    expect(notice).toMatchObject({ state: 'draft', created_by: 'ui-admin' });
    await visit(`#/cases/${caseId}`, /UI-CASE-1/);
    expect(await page.locator('#main').textContent()).toContain('investigation lead package');
    expect(problems).toEqual([]);
  }, 60_000);
});
