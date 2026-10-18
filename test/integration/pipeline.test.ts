/**
 * End-to-end on local fixtures: import → HTTP triage → browser evidence →
 * extraction (DOM, QR) → export, plus crash reconciliation.
 */
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, utimes, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from '../../src/db/pool.js';
import { importText } from '../../src/importer/importer.js';
import { HttpTriageWorker } from '../../src/coordinator/httpTriageWorker.js';
import { BrowserWorker } from '../../src/worker/browserWorker.js';
import { BrowserPool } from '../../src/worker/browserPool.js';
import { claimNextExtraction, runExtraction } from '../../src/extraction/runner.js';
import { writeExport } from '../../src/export/exporter.js';
import { reconcile } from '../../src/coordinator/reconciler.js';
import { collectStatus } from '../../src/observability/status.js';
import { leaseNext } from '../../src/queue/queue.js';
import { AttemptWriter } from '../../src/storage/artifactStore.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';
import { BROWSERS_AVAILABLE, TEST_CHROMIUM_SANDBOX, freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

let fixture: FixtureServer;
let root: string;
let cleanup: () => Promise<void>;
let pool: Pool;
let policy: ReturnType<typeof testPolicy>;
let browsers: BrowserPool;
const egress = { proxyUrl: null, vantage: 'test-direct' };

async function drain(fn: () => Promise<void>, times: number): Promise<void> {
  for (let i = 0; i < times; i += 1) await fn();
}

async function extractAll(): Promise<number> {
  let n = 0;
  for (;;) {
    const a = await claimNextExtraction(pool);
    if (!a) return n;
    await runExtraction(pool, policy, root, a);
    n += 1;
  }
}

describe.skipIf(!hasDb || !BROWSERS_AVAILABLE)('end-to-end collection pipeline', () => {
  beforeAll(async () => {
    fixture = await startFixtureServer();
    policy = testPolicy({
      scope: { allowed_ports: [80, 443, fixture.port] },
      limits: { per_domain_delay_seconds: 0, child_pages_per_target_max: 2 },
      browser: { navigation_timeout_seconds: 8, readiness_max_seconds: 3, challenge_wait_seconds: 2, scroll_step_wait_ms: 100 },
      extraction: { ocr_enabled: false },
    });
    ({ root, cleanup } = await tempRoot());
    browsers = new BrowserPool({ mode: 'local', wsEndpoint: null, connectTimeoutMs: 30_000, chromiumSandbox: TEST_CHROMIUM_SANDBOX }, policy, egress);
  });
  beforeEach(async () => {
    if (pool) await pool.end();
    pool = await freshDb(policy);
  });
  afterAll(async () => {
    await browsers.closeAll();
    await pool?.end();
    await fixture.close();
    await cleanup();
  });

  it('collects browser evidence, extracts identifiers (DOM + QR), spawns bounded child pages and exports', async () => {
    const csv = ['target,source_ref,case_ref,priority,urgent',
      `${fixture.url('/static')},CMP-1,CASE-7,5,false`,
      `${fixture.url('/qr')},CMP-2,CASE-7,5,true`].join('\n');
    const s = await importText(pool, policy, csv, { defaultProfile: 'browser_evidence', windowKey: 'w1', importedBy: 'test', filename: 'x.csv', format: 'csv' });
    expect(s.accepted).toBe(2);

    const triage = new HttpTriageWorker({ pool, policy, egress, artifactRoot: root });
    await drain(() => triage.runOne(), 2);
    const afterTriage = (await pool.query(`SELECT j.stage, j.state, t.url FROM jobs j JOIN targets t ON t.id = j.target_id ORDER BY j.id`)).rows;
    // Usable static HTML still needs the browser for an evidence profile; the urgent job skipped triage.
    expect(afterTriage.every((r) => r.stage === 'browser_primary')).toBe(true);

    const worker = new BrowserWorker({ pool, policy, egress, browsers, artifactRoot: root, workerId: 'test-worker' });
    // Two global permits, one job each (same registrable domain 127.0.0.1 → one at a time).
    await drain(() => worker.runOne(), 2);
    const jobs = (await pool.query(`SELECT j.id, j.state, j.outcome, t.url FROM jobs j JOIN targets t ON t.id = j.target_id WHERE j.parent_job_id IS NULL ORDER BY j.id`)).rows;
    expect(jobs.map((j) => j.state)).toEqual(['COMPLETE', 'COMPLETE']);
    expect(jobs.map((j) => j.outcome)).toEqual(['CONTENT_CAPTURED', 'CONTENT_CAPTURED']);

    expect(await extractAll()).toBeGreaterThanOrEqual(3);
    const ids = (await pool.query(`SELECT field_type, normalised_value, method, validation_state, display_context FROM identifiers`)).rows;
    const has = (f: string, v: string, method?: string) => ids.some((i) => i.field_type === f && i.normalised_value === v && (!method || i.method === method));
    expect(has('upi_vpa', 'refunds.desk@ybl', 'dom')).toBe(true);
    expect(has('phone', '+919876543210')).toBe(true);
    expect(has('ifsc', 'SBIN0001234')).toBe(true);
    expect(has('telegram', 't.me/acme_refund_support')).toBe(true);
    expect(has('upi_vpa', 'fraudster.test@okaxis', 'qr')).toBe(true);
    expect(ids.find((i) => i.field_type === 'qr_payload')?.normalised_value).toContain('upi://pay?pa=fraudster.test@okaxis');
    const fieldStatus = (await pool.query(`SELECT status FROM identifier_field_status WHERE field_type = 'crypto_btc'`)).rows.map((r) => r.status);
    expect(fieldStatus).toContain('not_observed');

    const children = (await pool.query(`SELECT t.url FROM jobs j JOIN targets t ON t.id = j.target_id WHERE j.parent_job_id IS NOT NULL`)).rows.map((r) => r.url);
    expect(children.length).toBeGreaterThan(0);
    expect(children.length).toBeLessThanOrEqual(2);
    const edges = (await pool.query(`SELECT edge_type, contacted FROM domain_edges WHERE edge_type = 'link_discovered'`)).rows;
    expect(edges.every((e) => e.contacted === false)).toBe(true);

    const exp = await writeExport(pool, root, new Date().toISOString().slice(0, 10), 'jsonl');
    const lines = (await readFile(join(root, exp.relativePath), 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
    expect(lines.length).toBeGreaterThanOrEqual(2);
    expect(JSON.stringify(lines)).not.toMatch(/storage-state|"cookies"/);

    const status = await collectStatus(pool, 24) as { required_artifact_completion: { complete: number; denominator_finished_browser_evidence_jobs: number } };
    expect(status.required_artifact_completion.complete).toBeGreaterThanOrEqual(2);
  }, 240_000);

  it('records a challenge outcome without completing the job', async () => {
    await importText(pool, policy, `target,urgent\n${fixture.url('/challenge')},true`, { defaultProfile: 'browser_evidence', windowKey: 'w1', importedBy: 'test', filename: 'c.csv', format: 'csv' });
    const worker = new BrowserWorker({ pool, policy: { ...policy, browser: { ...policy.browser, alternate_engine: 'none' } }, egress, browsers, artifactRoot: root, workerId: 'w-ch' });
    await worker.runOne();
    const job = (await pool.query(`SELECT state, outcome FROM jobs`)).rows[0];
    expect(job).toEqual({ state: 'MANUAL_REVIEW', outcome: 'CHALLENGE_PAGE_CAPTURED' });
  }, 120_000);

  it('reconciles a crash between directory rename and database commit, and salvages tmp directories', async () => {
    await importText(pool, policy, `target,urgent\n${fixture.url('/static')},true\n${fixture.url('/about')},true`, { defaultProfile: 'browser_evidence', windowKey: 'w1', importedBy: 'test', filename: 'r.csv', format: 'csv' });
    const req = { workerId: 'crashy', stages: ['browser_primary' as const], needsBrowserPermit: true, engine: 'chromium', adapter: 'playwright', vantage: 'test' };
    // Case 1: finalised directory exists, DB still says pending.
    const l1 = (await leaseNext(pool, policy, req))!;
    const w1 = new AttemptWriter(root, l1.attemptId, 1 << 20);
    await w1.init();
    await w1.writeArtifact('dom/rendered.txt', 'saved before crash', { type: 'rendered_text', observedStart: null, observedEnd: null, creationMethod: 't', completeness: 'complete', limitations: [] });
    await w1.finalise({ attemptId: l1.attemptId, jobId: l1.job.id, attemptNo: 1, kind: 'browser', engine: 'chromium', adapter: 'playwright', vantage: 'test', requestedUrl: l1.target.url,
      finalUrl: l1.target.url, startedAt: new Date().toISOString(), endedAt: new Date().toISOString(), outcome: 'CONTENT_INCOMPLETE', classification: 'content_incomplete',
      requiredArtifacts: [], requiredSatisfied: false, missingRequired: [], limitations: [] });
    // Case 2: worker killed mid-write (tmp directory only). Different registrable domain is not needed: per-domain cap released by expiry below.
    await pool.query(`UPDATE jobs SET lease_expires_at = now() - interval '1 second'`);
    await pool.query(`UPDATE global_permits SET expires_at = now() - interval '1 second'`);
    await reconcile(pool, policy, root);
    await pool.query(`UPDATE jobs SET next_eligible_at = now(), state = 'QUEUED' WHERE id <> $1 AND state <> 'FAILED_FINAL'`, [l1.job.id]);
    await pool.query(`DELETE FROM domain_pacing`);
    const l2 = (await leaseNext(pool, policy, { ...req, workerId: 'killed' }))!;
    expect(l2).not.toBeNull();
    await mkdir(join(root, 'tmp', l2.attemptId, 'screenshots'), { recursive: true });
    await writeFile(join(root, 'tmp', l2.attemptId, 'screenshots', '01-early-viewport.png'), Buffer.from('partial'));
    await pool.query(`UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1`, [l2.job.id]);

    // Inside the quiet period the directory is left alone (the worker may still be writing).
    expect((await reconcile(pool, policy, root)).tmpSalvaged).toBe(0);
    const old = new Date(Date.now() - (policy.queue.lease_seconds + 10) * 1000);
    await utimes(join(root, 'tmp', l2.attemptId, 'screenshots', '01-early-viewport.png'), old, old);
    await utimes(join(root, 'tmp', l2.attemptId, 'screenshots'), old, old);
    await utimes(join(root, 'tmp', l2.attemptId), old, old);

    const report = await reconcile(pool, policy, root);
    expect(report.tmpSalvaged).toBe(1);
    const a1 = (await pool.query(`SELECT status, artifact_dir FROM attempts WHERE id = $1`, [l1.attemptId])).rows[0];
    expect(a1.status).toBe('recovered');
    expect(a1.artifact_dir).toMatch(/^captures\//);
    const a2 = (await pool.query(`SELECT status, artifact_dir FROM attempts WHERE id = $1`, [l2.attemptId])).rows[0];
    expect(a2.status).toBe('interrupted');
    expect(a2.artifact_dir).toMatch(/^incomplete\//);
    const salvaged = JSON.parse(await readFile(join(root, a2.artifact_dir, 'manifest.json'), 'utf8'));
    expect(salvaged.artifacts[0]).toMatchObject({ type: 'screenshot_early', completeness: 'partial' });
    // Unknown directory without an attempt row is reported, never deleted.
    const before = (await reconcile(pool, policy, root)).orphanFinalUnknown; // earlier tests share ARTIFACT_ROOT
    const orphan = randomUUID();
    await mkdir(join(root, 'captures', '2026', '10', '17'), { recursive: true });
    await mkdir(join(root, 'tmp', 'x'), { recursive: true });
    await rename(join(root, 'tmp', 'x'), join(root, 'captures', '2026', '10', '17', orphan));
    const r3 = await reconcile(pool, policy, root);
    expect(r3.orphanFinalUnknown).toBe(before + 1);
  }, 120_000);
});
