/**
 * Post-action monitoring end to end (checklist §8): an authorised rule creates
 * NEW low-priority revisit jobs, pauses under admission pressure, and each
 * revisit is compared with the baseline into a distinct, recorded outcome.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from '../../src/db/pool.js';
import { BrowserWorker } from '../../src/worker/browserWorker.js';
import { BrowserPool } from '../../src/worker/browserPool.js';
import { claimNextExtraction, runExtraction } from '../../src/extraction/runner.js';
import { evaluatePendingRevisits, scheduleDueRevisits } from '../../src/monitoring/monitor.js';
import type { ApiApp } from '../../src/web/server.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';
import { ApiClient, loggedIn, startApi } from '../apiHelpers.js';
import { BROWSERS_AVAILABLE, TEST_CHROMIUM_SANDBOX, freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

describe.skipIf(!hasDb || !BROWSERS_AVAILABLE)('monitoring revisits', () => {
  let fixture: FixtureServer;
  let pool: Pool;
  let root: string;
  let cleanup: () => Promise<void>;
  let browsers: BrowserPool;
  let app: ApiApp;
  let ana: ApiClient;
  let caseId: string;
  let worker: BrowserWorker;
  let policy: ReturnType<typeof testPolicy>;
  const egress = { proxyUrl: null, vantage: 'test-direct' };

  async function captureAll(): Promise<void> {
    for (let i = 0; i < 3; i += 1) await worker.runOne();
    for (let a = await claimNextExtraction(pool); a; a = await claimNextExtraction(pool)) await runExtraction(pool, policy, root, a);
  }

  beforeAll(async () => {
    fixture = await startFixtureServer();
    policy = testPolicy({
      scope: { allowed_ports: [80, 443, fixture.port] },
      limits: { per_domain_delay_seconds: 0, child_pages_per_target_max: 0 },
      browser: { navigation_timeout_seconds: 8, readiness_max_seconds: 3, challenge_wait_seconds: 2, scroll_step_wait_ms: 100 },
      extraction: { ocr_enabled: false },
    });
    ({ root, cleanup } = await tempRoot());
    pool = await freshDb(policy);
    browsers = new BrowserPool({ mode: 'local', wsEndpoint: null, connectTimeoutMs: 30_000, chromiumSandbox: TEST_CHROMIUM_SANDBOX }, policy, egress);
    worker = new BrowserWorker({ pool, policy, egress, browsers, artifactRoot: root, workerId: 'mon-worker' });
    let base: string;
    ({ app, base } = await startApi(pool, policy, root));
    ana = (await loggedIn(base, pool, 'ana', ['analyst', 'intake', 'evidence'])).client;
    caseId = (await ana.post('/api/v1/cases', { case_ref: 'MON-1', title: 'Monitoring' })).body.id;
    await ana.call('POST', `/api/v1/intake-batches?case_id=${caseId}&urgent=true`, undefined, { raw: `${fixture.url('/static')}\n`, contentType: 'text/plain', headers: { 'idempotency-key': 'mon-intake-0001' } });
    await captureAll();
  }, 120_000);
  afterAll(async () => {
    await app.close();
    await browsers.closeAll();
    await pool.end();
    await fixture.close();
    await cleanup();
  });

  it('schedules proportionate revisits as new low-priority jobs and records a classified comparison', async () => {
    const target = (await pool.query('SELECT id FROM targets LIMIT 1')).rows[0].id;
    expect((await ana.post('/api/v1/monitoring/rules', { target_id: target, case_id: caseId, interval_hours: 1, reason: 'verify takedown' })).body.error.code).toBe('interval_too_short');
    const rule = await ana.post('/api/v1/monitoring/rules', { target_id: target, case_id: caseId, interval_hours: 12, reason: 'verify takedown after registrar notice' });
    expect(rule.status).toBe(201);
    expect(rule.body.baseline_attempt).toMatch(/^[0-9a-f-]{36}$/);
    expect((await ana.post('/api/v1/monitoring/rules', { target_id: target, case_id: caseId, interval_hours: 12, reason: 'duplicate rule' })).body.error.code).toBe('rule_exists');

    await pool.query(`UPDATE monitoring_rules SET next_due_at = now()`);
    await pool.query(`UPDATE system_state SET value = '{"paused": false, "low_priority_paused": true, "reasons": ["disk below threshold"]}' WHERE key = 'admission'`);
    expect(await scheduleDueRevisits(pool, policy)).toMatchObject({ created: 0, skipped_reason: expect.stringMatching(/admission paused/) });
    await pool.query(`UPDATE system_state SET value = '{"paused": false, "low_priority_paused": false, "reasons": []}' WHERE key = 'admission'`);
    expect((await scheduleDueRevisits(pool, policy)).created).toBe(1);
    const job = (await pool.query(`SELECT id, priority, urgent, scope FROM jobs WHERE scope ? 'monitoring_rule_id'`)).rows[0];
    expect(job).toMatchObject({ priority: -10, urgent: false });
    expect((await scheduleDueRevisits(pool, policy)).created).toBe(0); // not due again yet

    await captureAll();
    expect(await evaluatePendingRevisits(pool, policy, root)).toBe(1);
    const obs = (await pool.query('SELECT outcome_class, differences FROM monitoring_observations')).rows[0];
    expect(obs.outcome_class).toBe('still_live');
    expect(obs.differences.text_similarity).toBeGreaterThan(0.9);
    expect(obs.differences.screenshot_dhash_distance).toBeLessThanOrEqual(12);
    expect((await pool.query('SELECT count(DISTINCT a.id)::int AS n FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE j.target_id = $1', [target])).rows[0].n).toBe(2);

    const listed = await ana.get(`/api/v1/monitoring/rules?case_id=${caseId}`);
    expect(listed.body.items[0].latest_observation.outcome_class).toBe('still_live');
    const manual = await ana.post(`/api/v1/monitoring/rules/${rule.body.id}/observations`, { outcome_class: 'provider_confirmed_suspension', note: 'registrar says suspended' });
    expect(manual.body.error.code).toBe('proof_required');
    expect((await ana.post(`/api/v1/monitoring/rules/${rule.body.id}/stop`, { reason: 'case closed' })).body.active).toBe(false);
  }, 180_000);

  it('captures a selected mobile profile as an independently recorded attempt', async () => {
    await ana.call('POST', `/api/v1/intake-batches?case_id=${caseId}&urgent=true&capture_variant=both`, undefined, { raw: `${fixture.url('/contact')}\n`, contentType: 'text/plain', headers: { 'idempotency-key': 'mon-intake-0002' } });
    await captureAll();
    const rows = (await pool.query(`SELECT a.capture_variant, a.artifact_dir FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN targets t ON t.id = j.target_id
      WHERE t.url = $1 AND a.status = 'committed' ORDER BY a.capture_variant`, [fixture.url('/contact')])).rows;
    expect(rows.map((r) => r.capture_variant)).toEqual(['desktop', 'mobile']);
    const { readFile } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const mobile = JSON.parse(await readFile(join(root, rows[1].artifact_dir, 'manifest.json'), 'utf8'));
    expect(mobile.profile.captureVariant).toBe('mobile');
    expect(mobile.captureContext.mobile).toBe(true);
    expect(mobile.captureContext.viewport.width).toBeLessThan(500);
    expect(mobile.captureContext.user_agent).toMatch(/Mobile/);
  }, 120_000);
});
