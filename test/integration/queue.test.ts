import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { importText } from '../../src/importer/importer.js';
import { commitAttempt, leaseNext, reclaimExpiredLeases, releaseUnstarted, renewLease, type AttemptResult, type LeaseRequest } from '../../src/queue/queue.js';
import type { Pool } from '../../src/db/pool.js';
import { freshDb, hasDb, testPolicy } from '../helpers.js';

const policy = testPolicy({ limits: { per_domain_delay_seconds: 0 } });
let pool: Pool;

const browserReq = (workerId = 'w1'): LeaseRequest => ({ workerId, stages: ['browser_primary', 'browser_alternate'], needsBrowserPermit: true, engine: 'chromium', adapter: 'playwright', vantage: 'test' });
const httpReq = (workerId = 'h1'): LeaseRequest => ({ workerId, stages: ['http'], needsBrowserPermit: false, engine: 'undici', adapter: 'http-triage', vantage: 'test' });

async function load(lines: string[], profile: 'browser_evidence' | 'data_triage' = 'browser_evidence', window = '2026-10-17') {
  return importText(pool, policy, ['target,source_ref,case_ref,priority,urgent', ...lines].join('\n'), { defaultProfile: profile, windowKey: window, importedBy: 'test', filename: 't.csv', format: 'csv' });
}

const finishResult = (state: 'COMPLETE' | 'FAILED_FINAL' = 'COMPLETE'): AttemptResult => ({
  status: 'committed', manifest: null, manifestSha256: null, artifactDir: null, totalBytes: 0, activeSeconds: 5, engineVersion: 'x', userAgent: 'x',
  settings: {}, error: null, edges: [], decision: { kind: 'finish', state, outcome: 'CONTENT_CAPTURED', reason: 'test' }, extractionApplicable: false,
});

describe.skipIf(!hasDb)('PostgreSQL job ledger (§12)', () => {
  beforeEach(async () => {
    if (pool) await pool.end();
    pool = await freshDb(policy);
  });
  afterAll(async () => { await pool?.end(); });

  it('records every input line, including rejections, and merges duplicate seeds without losing provenance', async () => {
    const s = await load([
      'https://a.example.com/x?victim=1#/r,SRC-1,CASE-1,5,false',
      'https://a.example.com/x?victim=1#/r,SRC-2,CASE-1,9,true',
      'ftp://bad.example.com/,SRC-3,,0,false',
      'https://user:pw@b.example.com/,SRC-4,,0,false',
      'urgent.example.org,SRC-5,,0,true',
    ]);
    expect(s).toMatchObject({ lines: 5, accepted: 3, rejected: 2, jobsCreated: 2, jobsMerged: 1 });
    expect(s.rejections.map((r) => r.reason).sort()).toEqual(['unsupported_scheme:ftp', 'userinfo_credentials_in_url']);
    const { rows } = await pool.query(`SELECT j.priority, j.urgent, j.stage, count(js.*)::int AS sources FROM jobs j JOIN job_sources js ON js.job_id = j.id JOIN targets t ON t.id = j.target_id WHERE t.url LIKE 'https://a.example.com%' GROUP BY j.id`);
    expect(rows[0]).toMatchObject({ priority: 9, urgent: true, stage: 'browser_primary', sources: 2 });
    const seed = await pool.query(`SELECT count(*)::int AS n FROM targets WHERE candidate_of_input = 'urgent.example.org'`);
    expect(seed.rows[0].n).toBe(2); // https + http candidates tracked; only https scheduled
    const rejected = await pool.query(`SELECT count(*)::int AS n FROM source_records WHERE rejected`);
    expect(rejected.rows[0].n).toBe(2);
  });

  it('caps global browser permits across engines and allows at most one alternate', async () => {
    await load(['https://one.example.com/,,,0,true', 'https://two.example.net/,,,0,true', 'https://three.example.org/,,,0,true']);
    const a = await leaseNext(pool, policy, browserReq('w1'));
    const b = await leaseNext(pool, policy, browserReq('w2'));
    const c = await leaseNext(pool, policy, browserReq('w3'));
    expect(a && b).toBeTruthy();
    expect(c).toBeNull(); // two permits only
    expect(new Set([a!.permitSlot, b!.permitSlot]).size).toBe(2);
    await commitAttempt(pool, policy, a!, finishResult());
    expect(await leaseNext(pool, policy, browserReq('w3'))).not.toBeNull();
  });

  it('acquires jobs concurrently without double-leasing (SKIP LOCKED)', async () => {
    await load(Array.from({ length: 12 }, (_, i) => `https://site${i}.example${i}.com/,,,0,false`));
    const leases = await Promise.all(Array.from({ length: 12 }, (_, i) => leaseNext(pool, policy, httpReq(`h${i}`))));
    const got = leases.filter(Boolean).map((l) => l!.job.id);
    expect(got.length).toBeGreaterThan(0);
    expect(new Set(got).size).toBe(got.length);
  });

  it('enforces per-domain top-level concurrency of one', async () => {
    await load(['https://a.shared.example.com/1,,,0,false', 'https://b.shared.example.com/2,,,0,false']);
    const first = await leaseNext(pool, policy, httpReq('h1'));
    const second = await leaseNext(pool, policy, httpReq('h2'));
    expect(first).not.toBeNull();
    expect(second).toBeNull();
  });

  it('fences a worker that lost its lease: it cannot overwrite the new owner', async () => {
    await load(['https://fence.example.com/,,,0,true']);
    const old = (await leaseNext(pool, policy, browserReq('old')))!;
    await pool.query(`UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1`, [old.job.id]);
    await pool.query(`UPDATE global_permits SET expires_at = now() - interval '1 second'`);
    expect(await reclaimExpiredLeases(pool, policy)).toBe(1);
    await pool.query(`UPDATE jobs SET next_eligible_at = now() WHERE id = $1`, [old.job.id]);
    const fresh = (await leaseNext(pool, policy, browserReq('new')))!;
    expect(fresh.token).toBeGreaterThan(old.token);
    expect(await renewLease(pool, old, 120)).toBe(false);
    const r = await commitAttempt(pool, policy, old, finishResult('COMPLETE'));
    expect(r.ownershipHeld).toBe(false);
    const job = (await pool.query('SELECT state, lease_token FROM jobs WHERE id = $1', [old.job.id])).rows[0];
    expect(job).toMatchObject({ state: 'LEASED', lease_token: fresh.token });
    const oldAttempt = (await pool.query('SELECT status FROM attempts WHERE id = $1', [old.attemptId])).rows[0];
    expect(oldAttempt.status).toBe('committed_lease_lost');
    const interrupted = (await pool.query(`SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'lease_reclaimed'`)).rows[0];
    expect(interrupted.n).toBe(1);
  });

  it('commits idempotently', async () => {
    await load(['https://idem.example.com/,,,0,true']);
    const l = (await leaseNext(pool, policy, browserReq()))!;
    await commitAttempt(pool, policy, l, finishResult());
    const again = await commitAttempt(pool, policy, l, finishResult());
    expect(again.ownershipHeld).toBe(true);
    const n = (await pool.query(`SELECT count(*)::int AS n FROM audit_events WHERE event_type = 'attempt_committed'`)).rows[0].n;
    expect(n).toBe(1);
  });

  it('charges the shared budget at lease time and ends infrastructure-deferred when exhausted', async () => {
    await load(['https://budget.example.com/,,,0,true']);
    for (let i = 0; i < 2; i += 1) {
      const l = (await leaseNext(pool, policy, browserReq(`w${i}`)))!;
      expect(l).not.toBeNull();
      await pool.query(`UPDATE jobs SET lease_expires_at = now() - interval '1 second', next_eligible_at = now() WHERE id = $1`, [l.job.id]);
      await reclaimExpiredLeases(pool, policy);
      await pool.query(`UPDATE jobs SET next_eligible_at = now() WHERE id = $1`, [l.job.id]);
    }
    const job = (await pool.query(`SELECT state, outcome, browser_attempts FROM jobs`)).rows[0];
    expect(job).toMatchObject({ state: 'FAILED_FINAL', outcome: 'INFRASTRUCTURE_DEFERRED', browser_attempts: 2 });
    const statuses = (await pool.query(`SELECT status FROM attempts ORDER BY attempt_no`)).rows.map((r) => r.status);
    expect(statuses).toEqual(['interrupted', 'interrupted']);
  });

  it('refunds the budget when a lease is released before any target contact', async () => {
    await load(['https://refund.example.com/,,,0,true']);
    const l = (await leaseNext(pool, policy, browserReq()))!;
    await releaseUnstarted(pool, l, 'browser unavailable', 0);
    const job = (await pool.query(`SELECT state, browser_attempts FROM jobs`)).rows[0];
    expect(job).toMatchObject({ state: 'QUEUED', browser_attempts: 0 });
    expect((await pool.query(`SELECT holder_job_id FROM global_permits WHERE holder_job_id IS NOT NULL`)).rowCount).toBe(0);
  });

  it('pauses admission and admits only urgent work under low-priority pause', async () => {
    await load(['https://low.example.com/,,,0,false', 'https://hot.example.net/,,,0,true']);
    await pool.query(`UPDATE system_state SET value = '{"paused": true, "low_priority_paused": false, "reasons": ["disk_free_low"]}' WHERE key = 'admission'`);
    expect(await leaseNext(pool, policy, httpReq())).toBeNull();
    expect(await leaseNext(pool, policy, browserReq())).toBeNull();
    await pool.query(`UPDATE system_state SET value = '{"paused": false, "low_priority_paused": true, "reasons": ["captures_soft_limit_reached"]}' WHERE key = 'admission'`);
    expect(await leaseNext(pool, policy, httpReq())).toBeNull(); // low-priority http job held back
    expect(await leaseNext(pool, policy, browserReq())).not.toBeNull(); // urgent browser job admitted
  });

  it('creates the separate HTTP scheme candidate job when HTTPS fails at TLS level', async () => {
    await load(['fallback.example.com,,,0,false'], 'data_triage');
    const l = (await leaseNext(pool, policy, httpReq()))!;
    await commitAttempt(pool, policy, l, { ...finishResult(), decision: { kind: 'finish', state: 'FAILED_FINAL', outcome: 'TLS_FAILURE', reason: 'tls', spawnSchemeFallback: true } });
    const child = (await pool.query(`SELECT j.parent_job_id, t.scheme, j.stage FROM jobs j JOIN targets t ON t.id = j.target_id WHERE j.parent_job_id IS NOT NULL`)).rows[0];
    expect(child).toMatchObject({ parent_job_id: l.job.id, scheme: 'http', stage: 'http' });
  });
});
