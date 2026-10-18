/**
 * Analyst API end to end on local fixtures (checklist §2, §3, §5, §7, §10, §11):
 * idempotent intake (text and XLSX, preview), live job views and SSE, the
 * provisional/final first image, the single-target investigation view,
 * hash-verified evidence access with role and integrity checks, Verify Evidence,
 * packages, false-positive suppression, scoped entity search and audit trail.
 */
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from '../../src/db/pool.js';
import { BrowserWorker } from '../../src/worker/browserWorker.js';
import { BrowserPool } from '../../src/worker/browserPool.js';
import { claimNextExtraction, runExtraction } from '../../src/extraction/runner.js';
import type { ApiApp } from '../../src/web/server.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';
import { buildXlsx } from '../fixtures/xlsx.js';
import { ApiClient, loggedIn, startApi } from '../apiHelpers.js';
import { BROWSERS_AVAILABLE, TEST_CHROMIUM_SANDBOX, freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

describe.skipIf(!hasDb || !BROWSERS_AVAILABLE)('analyst API: intake to investigation', () => {
  let fixture: FixtureServer;
  let pool: Pool;
  let root: string;
  let cleanup: () => Promise<void>;
  let browsers: BrowserPool;
  let app: ApiApp;
  let base: string;
  let ana: ApiClient;
  let analystOnly: ApiClient;
  let outsider: ApiClient;
  let caseId: string;
  let policy: ReturnType<typeof testPolicy>;
  const egress = { proxyUrl: null, vantage: 'test-direct' };

  beforeAll(async () => {
    fixture = await startFixtureServer();
    policy = testPolicy({
      scope: { allowed_ports: [80, 443, fixture.port] },
      limits: { per_domain_delay_seconds: 0, child_pages_per_target_max: 0 },
      browser: { navigation_timeout_seconds: 8, readiness_max_seconds: 3, challenge_wait_seconds: 2, scroll_step_wait_ms: 100 },
      extraction: { ocr_enabled: false },
      web: { sse_poll_ms: 500 },
    });
    ({ root, cleanup } = await tempRoot());
    pool = await freshDb(policy);
    browsers = new BrowserPool({ mode: 'local', wsEndpoint: null, connectTimeoutMs: 30_000, chromiumSandbox: TEST_CHROMIUM_SANDBOX }, policy, egress);
    ({ app, base } = await startApi(pool, policy, root));
    ana = (await loggedIn(base, pool, 'ana', ['analyst', 'intake', 'evidence', 'approver'])).client;
    analystOnly = (await loggedIn(base, pool, 'ravi', ['analyst'])).client;
    outsider = (await loggedIn(base, pool, 'mallory', ['analyst', 'intake', 'evidence'])).client;
    caseId = (await ana.post('/api/v1/cases', { case_ref: 'I4C-2026-0001', title: 'UPI refund scam wave', category: 'financial_fraud' })).body.id;
    await ana.post(`/api/v1/cases/${caseId}/members`, { username: 'ravi', case_role: 'investigator', reason: 'assigned analyst' });
  }, 60_000);
  afterAll(async () => {
    await app.close();
    await browsers.closeAll();
    await pool.end();
    await fixture.close();
    await cleanup();
  });

  const intake = (c: ApiClient, body: Buffer | string, q: string, headers: Record<string, string> = {}, type = 'text/plain') =>
    c.call('POST', `/api/v1/intake-batches?case_id=${caseId}&${q}`, undefined, { raw: body, contentType: type, headers });

  it('previews, then durably and idempotently accepts intake; XLSX works; outsiders cannot submit to the case', async () => {
    const list = `${fixture.url('/qr')}\n# comment\n${fixture.url('/static')}?campaign=sms#pay\nftp://not-allowed.example/\n`;
    const preview = await intake(ana, list, 'dry_run=true');
    expect(preview.status).toBe(200);
    expect(preview.body).toMatchObject({ dry_run: true, accepted: 2, rejected: 1 });
    expect((await pool.query('SELECT count(*)::int AS n FROM jobs')).rows[0].n).toBe(0);

    expect((await intake(ana, list, '')).body.error.code).toBe('idempotency_key_required');
    const first = await intake(ana, list, 'urgent=true', { 'idempotency-key': 'intake-key-0001' });
    expect(first.status).toBe(202);
    expect(first.body.batch_id).toMatch(/^[0-9a-f-]{36}$/);
    const replay = await intake(ana, list, '', { 'idempotency-key': 'intake-key-0001' });
    expect(replay.status).toBe(200);
    expect(replay.body).toMatchObject({ replayed: true, batch_id: first.body.batch_id });
    expect((await intake(ana, `${list}\nhttps://x.example/`, '', { 'idempotency-key': 'intake-key-0001' })).body.error.code).toBe('idempotency_key_reused');
    expect((await pool.query('SELECT count(*)::int AS n FROM jobs')).rows[0].n).toBe(2);
    const batch = await ana.get(`/api/v1/intake-batches/${first.body.batch_id}`);
    expect(batch.body.lines.find((l: { rejected: boolean }) => l.rejected).reason).toMatch(/scheme/);

    const xlsx = buildXlsx([['target', 'priority', 'capture_variant'], [`${fixture.url('/about')}`, 3, 'both']]);
    const x = await intake(ana, xlsx, 'format=xlsx', { 'idempotency-key': 'intake-key-xlsx1' }, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    expect(x.status).toBe(202);
    expect(x.body.jobs_created).toBe(2); // desktop + mobile: independently recorded attempts

    expect((await intake(outsider, list, '', { 'idempotency-key': 'intake-key-evil' })).status).toBe(404);
    expect((await analystOnly.call('POST', `/api/v1/intake-batches?case_id=${caseId}`, undefined, { raw: list, contentType: 'text/plain', headers: { 'idempotency-key': 'k-analyst-01' } })).status).toBe(403);
  });

  it('captures, streams progress, serves the first image and builds the investigation view', async () => {
    // Park the low-priority /about jobs so the two urgent targets are captured now.
    await pool.query(`UPDATE jobs SET next_eligible_at = 'infinity', state = 'DEFERRED' WHERE target_id IN (SELECT id FROM targets WHERE url LIKE '%/about')`);
    const sse = await fetch(`${base}/api/v1/jobs/events?case_ref=I4C-2026-0001&since=${encodeURIComponent(new Date(Date.now() - 60_000).toISOString())}`, { headers: { cookie: ana.cookie! } });
    expect(sse.headers.get('content-type')).toMatch(/text\/event-stream/);
    const reader = sse.body!.getReader();
    const first = await Promise.race([reader.read(), new Promise<null>((r) => setTimeout(() => r(null), 5000))]);
    expect(first && new TextDecoder().decode(first.value)).toMatch(/retry:|event: job/);
    await reader.cancel();

    const worker = new BrowserWorker({ pool, policy, egress, browsers, artifactRoot: root, workerId: 'api-worker' });
    await worker.runOne();
    await worker.runOne();
    for (let a = await claimNextExtraction(pool); a; a = await claimNextExtraction(pool)) await runExtraction(pool, policy, root, a);

    const jobs = await ana.get('/api/v1/jobs?case_ref=I4C-2026-0001&state=COMPLETE');
    expect(jobs.body.items.length).toBe(2);
    const qrJob = jobs.body.items.find((j: { url: string }) => j.url.endsWith('/qr'));
    expect(qrJob).toMatchObject({ acquisition: 'content_captured', verdict: 'unreviewed', action: 'none', live_stage: 'ready_for_review' });
    expect(qrJob.case_refs).toEqual(['I4C-2026-0001']);
    const img = await fetch(`${base}/api/v1/attempts/${qrJob.first_image_attempt_id}/first-image`, { headers: { cookie: ana.cookie! } });
    expect(img.status).toBe(200);
    expect(img.headers.get('content-type')).toBe('image/png');
    expect(img.headers.get('x-evidence-status')).toBe('final');
    expect(img.headers.get('content-security-policy')).toContain('sandbox');

    const inv = await analystOnly.get(`/api/v1/targets/${qrJob.target_id}/investigation`);
    expect(inv.status).toBe(200);
    expect(inv.body.images.length).toBeGreaterThan(0);
    expect(inv.body.verdict).toBe('unreviewed');
    const upi = inv.body.identifiers.find((i: { field_type: string; methods: string[] }) => i.field_type === 'upi_vpa' && i.methods.includes('qr'));
    expect(upi.normalised_value).toBe('fraudster.test@okaxis');
    expect(upi.provenance[0]).toMatchObject({ method: 'qr' });
    expect(upi.provenance[0].artifact_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(inv.body.timeline[0].final_url).toContain('/qr');
    expect((await outsider.get(`/api/v1/targets/${qrJob.target_id}/investigation`)).status).toBe(404);
    expect((await outsider.get(`/api/v1/jobs/${qrJob.id}`)).status).toBe(404);
  }, 180_000);

  it('serves evidence only after re-verifying hashes, with role checks and safe content handling', async () => {
    const att = (await pool.query(`SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN targets t ON t.id = j.target_id WHERE t.url LIKE '%/qr' AND a.status = 'committed'`)).rows[0].id as string;
    const arts = (await analystOnly.get(`/api/v1/captures/${att}/artifacts`)).body.items as { id: number; artifact_type: string; relative_path: string; restricted: boolean }[];
    const png = arts.find((a) => a.artifact_type === 'screenshot_settled')!;
    const html = arts.find((a) => a.artifact_type === 'rendered_dom')!;
    const har = arts.find((a) => a.artifact_type === 'har')!;

    const inlinePng = await fetch(`${base}/api/v1/artifacts/${png.id}/content?disposition=inline`, { headers: { cookie: analystOnly.cookie! } });
    expect(inlinePng.status).toBe(200);
    expect((await analystOnly.get(`/api/v1/artifacts/${html.id}/content`)).body.error.code).toBe('evidence_role_required');
    const dl = await fetch(`${base}/api/v1/artifacts/${html.id}/content?disposition=inline`, { headers: { cookie: ana.cookie! } });
    expect(dl.status).toBe(200);
    expect(dl.headers.get('content-disposition')).toMatch(/^attachment;/); // captured HTML is never rendered inline
    expect(dl.headers.get('content-type')).toBe('application/octet-stream');
    expect((await ana.get(`/api/v1/artifacts/${har.id}/content`)).body.error.code).toBe('restricted_artifact');
    expect((await ana.get(`/api/v1/artifacts/${har.id}/content`, { 'x-purpose': 'network analysis for case I4C-2026-0001' })).status).toBe(200);

    const manifest = await ana.get(`/api/v1/captures/${att}/manifest`);
    expect(manifest.body.integrity.matches).toBe(true);
    const etag = manifest.headers.get('etag')!;
    expect((await fetch(`${base}/api/v1/captures/${att}/manifest`, { headers: { cookie: ana.cookie!, 'if-none-match': etag } })).status).toBe(304);

    expect((await ana.post(`/api/v1/captures/${att}/verify`)).body.result).toBe('pass');
    const dir = (await pool.query('SELECT artifact_dir FROM attempts WHERE id = $1', [att])).rows[0].artifact_dir;
    await writeFile(join(root, dir, 'dom', 'rendered.html'), '<html>tampered</html>');
    expect((await ana.get(`/api/v1/artifacts/${html.id}/content`)).body.error.code).toBe('integrity_mismatch');
    expect((await ana.post(`/api/v1/captures/${att}/verify`)).body.result).toBe('fail');
    const refused = await ana.post('/api/v1/packages', { case_id: caseId, attempt_ids: [att], purpose: 'hand-over to IO' });
    expect(refused.body.error.code).toBe('package_refused');

    const other = (await pool.query(`SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN targets t ON t.id = j.target_id WHERE t.url LIKE '%/static%' AND a.status = 'committed'`)).rows[0].id as string;
    const pkg = await ana.post('/api/v1/packages', { case_id: caseId, attempt_ids: [other], purpose: 'hand-over to IO' });
    expect(pkg.status).toBe(201);
    const tar = await fetch(`${base}/api/v1/packages/${pkg.body.package_id}/archive`, { headers: { cookie: ana.cookie! } });
    expect(tar.headers.get('x-package-index-sha256')).toBe(pkg.body.index_sha256);
    expect((await analystOnly.get(`/api/v1/packages/${pkg.body.package_id}/archive`)).status).toBe(403);
  });

  it('records append-only decisions, suppresses false positives and requires new evidence to override', async () => {
    const target = (await pool.query(`SELECT id FROM targets WHERE url LIKE '%/static%' LIMIT 1`)).rows[0].id as number;
    const fp = await analystOnly.post('/api/v1/decisions', { target_id: target, decision: 'false_positive', reason_code: 'legitimate_official', reason: 'Official refund page of the bank', expected_last_decision_id: null });
    expect(fp.status).toBe(201);
    expect((await analystOnly.post('/api/v1/decisions', { target_id: target, decision: 'retain', reason_code: 'other', reason: 'stale view', expected_last_decision_id: null })).body.error.code).toBe('version_conflict');
    const inv = await ana.get(`/api/v1/targets/${target}/investigation`);
    expect(inv.body.verdict).toBe('false_positive');
    expect(inv.body.suppression.suppressed).toBe(true);
    expect((await analystOnly.post('/api/v1/decisions', { target_id: target, decision: 'override_suppression', reason_code: 'new_evidence', reason: 'analyst cannot override', expected_last_decision_id: fp.body.decision_id })).status).toBe(403);
    const noEvidence = await ana.post('/api/v1/decisions', { target_id: target, decision: 'override_suppression', reason_code: 'new_evidence', reason: 'new complaint', expected_last_decision_id: fp.body.decision_id });
    expect(noEvidence.body.error.code).toBe('new_evidence_required');
    await expect(pool.query('DELETE FROM analyst_decisions')).rejects.toThrow(/append-only/);

    const rec = await analystOnly.post('/api/v1/decisions', { target_id: target, decision: 'recapture', reason_code: 'needs_recapture', reason: 'check again later', expected_last_decision_id: fp.body.decision_id });
    expect(rec.body.recapture_job_id).toBeGreaterThan(0);
  });

  it('scopes entity search to the viewer, requires a purpose for global searches and audits it', async () => {
    expect((await analystOnly.get('/api/v1/entities?type=upi_vpa&value=fraudster.test@okaxis')).body.error.code).toBe('purpose_required');
    const hit = await analystOnly.get('/api/v1/entities?type=upi_vpa&value=FRAUDSTER.test@okaxis', { 'x-purpose': 'linking complaints for I4C-2026-0001' });
    expect(hit.body.distinct_targets).toBe(1);
    const scoped = await analystOnly.get('/api/v1/entities?type=upi_vpa&value=fraudster.test@okaxis&case_ref=I4C-2026-0001');
    expect(scoped.body.results.length).toBeGreaterThan(0);
    const blind = await outsider.get('/api/v1/entities?type=upi_vpa&value=fraudster.test@okaxis', { 'x-purpose': 'fishing expedition' });
    expect(blind.body.results).toEqual([]);
    const audit = await ana.get(`/api/v1/audit-events?case_id=${caseId}`);
    expect(audit.body.items.some((e: { event_type: string }) => e.event_type === 'import_batch')).toBe(true);
    const searches = (await pool.query(`SELECT details FROM audit_events WHERE event_type = 'protected_identifier_search'`)).rows;
    expect(searches.length).toBeGreaterThanOrEqual(3);
    expect(JSON.stringify(searches)).not.toContain('fraudster.test@okaxis'); // the searched value itself is hashed in the log
    expect((await analystOnly.get('/api/v1/audit-events')).body.error.code).toBe('case_scope_required');
  });
});
