/**
 * Case isolation when the same deduplicated target belongs to several cases
 * (checklist §7 object-level authorisation, §11 cross-case isolation).
 * Evidence packages, investigation details, monitoring revisits and verified
 * closure must each stay within the case they are filed under.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from '../../src/db/pool.js';
import { BrowserWorker } from '../../src/worker/browserWorker.js';
import { BrowserPool } from '../../src/worker/browserPool.js';
import { scheduleDueRevisits } from '../../src/monitoring/monitor.js';
import type { ApiApp } from '../../src/web/server.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';
import { ApiClient, loggedIn, startApi } from '../apiHelpers.js';
import { BROWSERS_AVAILABLE, TEST_CHROMIUM_SANDBOX, freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

describe.skipIf(!hasDb || !BROWSERS_AVAILABLE)('cross-case isolation for shared targets', () => {
  let fixture: FixtureServer;
  let pool: Pool;
  let root: string;
  let cleanup: () => Promise<void>;
  let browsers: BrowserPool;
  let app: ApiApp;
  let worker: BrowserWorker;
  let policy: ReturnType<typeof testPolicy>;
  let alice: ApiClient; // member of both cases
  let bob: ApiClient; // case A only
  let carol: ApiClient; // case B only
  let caseA: string;
  let caseB: string;
  const t: Record<string, number> = {};
  const job: Record<string, number> = {};
  const egress = { proxyUrl: null, vantage: 'test-direct' };

  async function runWorker(n = 4): Promise<void> {
    for (let i = 0; i < n; i += 1) await worker.runOne();
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
    worker = new BrowserWorker({ pool, policy, egress, browsers, artifactRoot: root, workerId: 'xcase-worker' });
    let base: string;
    ({ app, base } = await startApi(pool, policy, root));
    alice = (await loggedIn(base, pool, 'alice', ['analyst', 'intake', 'evidence', 'approver'])).client;
    bob = (await loggedIn(base, pool, 'bob', ['analyst', 'evidence'])).client;
    carol = (await loggedIn(base, pool, 'carol', ['analyst', 'evidence'])).client;
    caseA = (await alice.post('/api/v1/cases', { case_ref: 'XCASE-A', title: 'Case A' })).body.id;
    caseB = (await alice.post('/api/v1/cases', { case_ref: 'XCASE-B', title: 'Case B' })).body.id;
    await alice.post(`/api/v1/cases/${caseA}/members`, { username: 'bob', case_role: 'investigator', reason: 'case A team' });
    await alice.post(`/api/v1/cases/${caseB}/members`, { username: 'carol', case_role: 'investigator', reason: 'case B team' });
    const intake = (caseId: string, urls: string[], key: string) =>
      alice.call('POST', `/api/v1/intake-batches?case_id=${caseId}&urgent=true`, undefined, { raw: `${urls.join('\n')}\n`, contentType: 'text/plain', headers: { 'idempotency-key': key } });
    // /static is reported in both cases (one deduplicated target and job); /rich only in A; /qr only in B.
    await intake(caseA, [fixture.url('/static'), fixture.url('/rich')], 'xcase-intake-a1');
    await intake(caseB, [fixture.url('/static'), fixture.url('/qr')], 'xcase-intake-b1');
    await runWorker(5);
    for (const [k, path] of [['shared', '/static'], ['onlyA', '/rich'], ['onlyB', '/qr']] as const) {
      t[k] = Number((await pool.query('SELECT id FROM targets WHERE url = $1', [fixture.url(path)])).rows[0].id);
      job[k] = Number((await pool.query('SELECT id FROM jobs WHERE target_id = $1 AND parent_job_id IS NULL ORDER BY id LIMIT 1', [t[k]])).rows[0].id);
    }
    const links = (await pool.query('SELECT case_ref FROM job_case_links WHERE job_id = $1 ORDER BY 1', [job.shared])).rows.map((r) => r.case_ref);
    expect(links).toEqual(['XCASE-A', 'XCASE-B']);
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await browsers?.closeAll();
    await pool?.end();
    await fixture?.close();
    await cleanup?.();
  });

  it('refuses to package evidence under a case it is not linked to', async () => {
    const attemptB = (await pool.query(`SELECT id FROM attempts WHERE job_id = $1 AND status = 'committed' LIMIT 1`, [job.onlyB])).rows[0].id;
    const byJob = await alice.post('/api/v1/packages', { case_id: caseA, job_id: job.onlyB, purpose: 'relabel case B evidence as case A' });
    expect(byJob.status).toBe(400);
    expect(byJob.body.error.code).toBe('evidence_not_in_case');
    const byAttempt = await alice.post('/api/v1/packages', { case_id: caseA, attempt_ids: [attemptB], purpose: 'relabel case B evidence as case A' });
    expect(byAttempt.body.error.code).toBe('evidence_not_in_case');
    expect((await pool.query('SELECT count(*)::int AS n FROM evidence_packages')).rows[0].n).toBe(0);
    // Evidence that does belong to the case can be packaged.
    expect((await alice.post('/api/v1/packages', { case_id: caseA, job_id: job.shared, purpose: 'case A hand-off' })).status).toBe(201);
  });

  it('shows notes and monitoring rules only to members of the case they belong to', async () => {
    const noCase = await alice.post('/api/v1/annotations', { object_type: 'target', object_id: String(t.shared), body: 'case A operational note' });
    expect(noCase.body.error.code).toBe('case_required');
    expect((await carol.post('/api/v1/annotations', { object_type: 'target', object_id: String(t.shared), body: 'wrong case', case_id: caseA })).body.error.code).toBe('case_mismatch');
    expect((await alice.post('/api/v1/annotations', { object_type: 'target', object_id: String(t.shared), body: 'case A operational note', case_id: caseA })).status).toBe(201);
    expect((await bob.post('/api/v1/annotations', { object_type: 'target', object_id: String(t.shared), body: 'bob note, only case available' })).status).toBe(201);
    expect((await alice.post('/api/v1/monitoring/rules', { target_id: t.shared, case_id: caseA, interval_hours: 24, reason: 'case A takedown verification' })).status).toBe(201);

    const asCarol = (await carol.get(`/api/v1/targets/${t.shared}/investigation`)).body;
    expect(asCarol.annotations).toEqual([]);
    expect(asCarol.monitoring).toEqual([]);
    const asBob = (await bob.get(`/api/v1/targets/${t.shared}/investigation`)).body;
    expect(asBob.annotations.map((a: { body: string; case_ref: string }) => [a.body, a.case_ref]).sort()).toEqual([['bob note, only case available', 'XCASE-A'], ['case A operational note', 'XCASE-A']]);
    expect(asBob.monitoring.map((m: { reason: string }) => m.reason)).toEqual(['case A takedown verification']);
  });

  it('builds a revisit from, and links it only to, the monitoring rule\'s case', async () => {
    const rule = await carol.post('/api/v1/monitoring/rules', { target_id: t.shared, case_id: caseB, interval_hours: 24, reason: 'case B takedown verification' });
    expect(rule.status).toBe(201);
    await pool.query('UPDATE monitoring_rules SET next_due_at = now() WHERE id = $1', [rule.body.id]);
    expect((await scheduleDueRevisits(pool, policy)).created).toBe(1);
    const revisit = (await pool.query(`SELECT id, case_ref FROM jobs WHERE scope->>'monitoring_rule_id' = $1`, [rule.body.id])).rows[0];
    expect(revisit.case_ref).toBe('XCASE-B');
    expect((await pool.query('SELECT case_ref FROM job_case_links WHERE job_id = $1', [revisit.id])).rows.map((r) => r.case_ref)).toEqual(['XCASE-B']);
    // Members of case A only cannot open the case B revisit.
    expect((await bob.get(`/api/v1/jobs/${revisit.id}`)).status).toBe(404);
    expect((await carol.get(`/api/v1/jobs/${revisit.id}`)).status).toBe(200);
  });

  it('closes a notice as verified only after a fresh capture of every target within the notice\'s case', async () => {
    const issuedAt = new Date(Date.now() - 1000).toISOString();
    const nid = randomUUID();
    await pool.query(
      `INSERT INTO notices (id, case_id, route, state, recipient, created_by, issued_at) VALUES ($1, $2, 'registrar_abuse', 'complied', $3, 'bob', $4)`,
      [nid, caseA, { name: 'Registrar abuse desk', kind: 'registrar' }, issuedAt],
    );
    for (const target of [t.shared, t.onlyA]) await pool.query(`INSERT INTO notice_targets (notice_id, target_id, evidence_attempt_ids) VALUES ($1, $2, '{}')`, [nid, target]);

    // A fresh capture made for case B (the revisit from the previous test) does not verify case A's notice.
    await runWorker(2);
    expect((await pool.query(`SELECT count(*)::int AS n FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE j.target_id = $1 AND a.started_at > $2 AND a.status = 'committed'`, [t.shared, issuedAt])).rows[0].n).toBeGreaterThan(0);
    const close = () => alice.post(`/api/v1/notices/${nid}/transition`, { action: 'close', close_as: 'verified_closed' });
    let r = await close();
    expect(r.body.error.code).toBe('verification_capture_required');
    expect(r.body.error.details.targets.map((x: { target_id: number }) => x.target_id).sort()).toEqual([t.shared, t.onlyA].sort());

    // Revisiting one target within case A is not enough while another remains unverified.
    expect((await alice.post(`/api/v1/jobs/${job.shared}/recapture`, { reason: 'verify takedown for case A', urgent: true })).status).toBe(202);
    await runWorker(2);
    r = await close();
    expect(r.body.error.details.targets.map((x: { target_id: number }) => x.target_id)).toEqual([t.onlyA]);

    // A withdrawn target needs no verification; then the notice can close.
    await pool.query(`UPDATE notice_targets SET target_status = 'withdrawn' WHERE notice_id = $1 AND target_id = $2`, [nid, t.onlyA]);
    r = await close();
    expect(r.body.state).toBe('verified_closed');
  }, 120_000);
});
