/**
 * Retention (blueprint §15). Case holds override routine deletion; held
 * evidence is never silently deleted. Expiry and deletion are recorded in
 * metadata and the audit log. Disabled unless RETENTION_DELETE_ENABLED=true:
 * by default the job only reports what WOULD expire.
 */
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { Policy } from '../config/policy.js';
import { audit, type Pool } from '../db/pool.js';
import { logger } from '../observability/logger.js';

/**
 * A job is held when ANY case linked to it is under an unreleased hold: the job's
 * own case_ref, or the case_ref of any seed merged into it by deduplication
 * (job_sources -> source_records). Child and fallback jobs inherit job_sources.
 */
export const HELD_JOB_SQL = `EXISTS (
    SELECT 1 FROM case_holds h
     WHERE h.released_at IS NULL
       AND (h.case_ref = j.case_ref
            OR h.case_ref IN (SELECT s.case_ref FROM job_sources js JOIN source_records s ON s.id = js.source_record_id WHERE js.job_id = j.id)))`;

/**
 * Evidence that something else depends on is never disposed of by the routine
 * job (blueprint v4 §27.3): attempts cited by a non-withdrawn notice or
 * certificate, and attempts of jobs linked to a case that is still open.
 */
export const CITED_ATTEMPT_SQL = `(
    EXISTS (SELECT 1 FROM notice_targets nt JOIN notices n ON n.id = nt.notice_id WHERE a.id = ANY(nt.evidence_attempt_ids) AND n.state <> 'withdrawn')
    OR EXISTS (SELECT 1 FROM certificates c WHERE a.id = ANY(c.attempt_ids) AND c.state <> 'withdrawn')
    OR EXISTS (SELECT 1 FROM job_case_links l JOIN cases cs ON cs.case_ref = l.case_ref WHERE l.job_id = j.id AND cs.status = 'open'))`;

export async function applyRetention(pool: Pool, policy: Policy, root: string, opts: { deleteEnabled: boolean; limit?: number }): Promise<{ eligible: number; deleted: number }> {
  if (policy.storage.delete_case_hold_artifacts !== false) throw new Error('delete_case_hold_artifacts must be false');
  const { rows } = await pool.query<{ id: string; artifact_dir: string; job_id: number }>(
    `SELECT a.id, a.artifact_dir, a.job_id FROM attempts a JOIN jobs j ON j.id = a.job_id
      WHERE a.expires_at IS NOT NULL AND a.expires_at < now() AND a.deleted_at IS NULL AND a.artifact_dir IS NOT NULL
        AND NOT (${HELD_JOB_SQL})
        AND NOT (${CITED_ATTEMPT_SQL})
        -- Never delete while the job is still active.
        AND j.state NOT IN ('QUEUED','LEASED','CAPTURING','FINALISING','DEFERRED')
      ORDER BY a.expires_at LIMIT $1`,
    [opts.limit ?? 500],
  );
  let deleted = 0;
  for (const r of rows) {
    if (!opts.deleteEnabled) continue;
    if (!/^(captures|incomplete)\/\d{4}\/\d{2}\/\d{2}\/[0-9a-f-]{36}$/.test(r.artifact_dir)) {
      logger.error({ attempt: r.id, dir: r.artifact_dir }, 'refusing to delete unexpected artifact path');
      continue;
    }
    // Re-check the hold inside the deletion step (a hold may have been placed meanwhile).
    const hold = await pool.query(`SELECT 1 FROM jobs j JOIN attempts a ON a.job_id = j.id WHERE j.id = $1 AND a.id = $2 AND ((${HELD_JOB_SQL}) OR (${CITED_ATTEMPT_SQL}))`, [r.job_id, r.id]);
    if (hold.rowCount) continue;
    // Record intent first so an interrupted deletion is still visible in the audit trail.
    await audit(pool, 'retention', 'attempt_deletion_started', { dir: r.artifact_dir }, { jobId: r.job_id, attemptId: r.id });
    await rm(join(root, r.artifact_dir), { recursive: true, force: true });
    await rm(join(root, 'derived', r.id), { recursive: true, force: true });
    await pool.query(`UPDATE attempts SET deleted_at = now() WHERE id = $1`, [r.id]);
    await audit(pool, 'retention', 'attempt_artifacts_deleted', { dir: r.artifact_dir, policy_classes: policy.retention.classes }, { jobId: r.job_id, attemptId: r.id });
    deleted += 1;
  }
  if (rows.length) logger.info({ eligible: rows.length, deleted, delete_enabled: opts.deleteEnabled }, 'retention pass');
  return { eligible: rows.length, deleted };
}
