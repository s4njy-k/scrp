import { mkdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from '../../src/db/pool.js';
import { importText } from '../../src/importer/importer.js';
import { applyRetention } from '../../src/coordinator/retention.js';
import { HttpTriageWorker } from '../../src/coordinator/httpTriageWorker.js';
import { freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

const policy = testPolicy({ limits: { per_domain_delay_seconds: 0 } });
let pool: Pool;

async function attemptWithDir(root: string, jobId: number): Promise<{ id: string; dir: string }> {
  const id = crypto.randomUUID();
  const rel = `captures/2026/10/01/${id}`;
  await mkdir(join(root, rel), { recursive: true });
  await writeFile(join(root, rel, 'manifest.json'), '{}');
  await pool.query(
    `INSERT INTO attempts (id, job_id, attempt_no, kind, engine, adapter, vantage, lease_token, worker_id, retention_class, status, artifact_dir, expires_at)
     VALUES ($1,$2,1,'browser','chromium','playwright','t',1,'w','standard','committed',$3, now() - interval '1 day')`,
    [id, jobId, rel],
  );
  return { id, dir: join(root, rel) };
}

describe.skipIf(!hasDb)('retention honours every linked case hold (§15)', () => {
  beforeEach(async () => {
    if (pool) await pool.end();
    pool = await freshDb(policy);
  });
  afterAll(async () => { await pool?.end(); });

  it('keeps evidence when a seed merged into the job belongs to a held case', async () => {
    const { root, cleanup } = await tempRoot();
    try {
      // Same URL from two cases: one job, case_ref = CASE-A, provenance includes CASE-B.
      await importText(pool, policy, 'target,case_ref\nhttps://merged.example.com/x,CASE-A\nhttps://merged.example.com/x,CASE-B',
        { defaultProfile: 'browser_evidence', windowKey: 'w', importedBy: 't', filename: 'm.csv', format: 'csv' });
      const job = (await pool.query(`UPDATE jobs SET state = 'COMPLETE', stage = 'done' RETURNING id, case_ref`)).rows[0];
      expect(job.case_ref).toBe('CASE-A');
      const a = await attemptWithDir(root, job.id);
      await pool.query(`INSERT INTO case_holds (case_ref, reason, placed_by) VALUES ('CASE-B', 'court order', 't')`);

      const held = await applyRetention(pool, policy, root, { deleteEnabled: true });
      expect(held).toEqual({ eligible: 0, deleted: 0 });
      expect((await stat(a.dir)).isDirectory()).toBe(true);

      await pool.query(`UPDATE case_holds SET released_at = now(), released_by = 't'`);
      const released = await applyRetention(pool, policy, root, { deleteEnabled: true });
      expect(released.deleted).toBe(1);
      await expect(stat(a.dir)).rejects.toThrow();
      const events = (await pool.query(`SELECT event_type FROM audit_events WHERE attempt_id = $1 ORDER BY id`, [a.id])).rows.map((r) => r.event_type);
      expect(events).toEqual(['attempt_deletion_started', 'attempt_artifacts_deleted']);
    } finally {
      await cleanup();
    }
  });

  it('backs off instead of spinning when due work cannot be leased', async () => {
    await importText(pool, policy, 'target\nhttps://a.same.example.com/1\nhttps://b.same.example.com/2',
      { defaultProfile: 'data_triage', windowKey: 'w', importedBy: 't', filename: 'b.csv', format: 'csv' });
    // Occupy the registrable domain so neither job can be leased.
    await pool.query(`UPDATE jobs SET state = 'LEASED', lease_token = 1, lease_expires_at = now() + interval '1 hour' WHERE id = (SELECT min(id) FROM jobs)`);
    const w = new HttpTriageWorker({ pool, policy, egress: { proxyUrl: null, vantage: 't' }, artifactRoot: '/nonexistent' });
    const hasDueWork = () => (w as unknown as { hasDueWork(): Promise<boolean> }).hasDueWork();
    expect(await hasDueWork()).toBe(true); // a job is due...
    await w.runOne(); // ...but cannot be leased (domain busy)
    expect(await hasDueWork()).toBe(false); // so the pool idles instead of re-running immediately
  });
});
