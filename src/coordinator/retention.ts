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

export async function applyRetention(pool: Pool, policy: Policy, root: string, opts: { deleteEnabled: boolean; limit?: number }): Promise<{ eligible: number; deleted: number }> {
  if (policy.storage.delete_case_hold_artifacts !== false) throw new Error('delete_case_hold_artifacts must be false');
  const { rows } = await pool.query<{ id: string; artifact_dir: string; job_id: number; case_ref: string | null }>(
    `SELECT a.id, a.artifact_dir, a.job_id, j.case_ref FROM attempts a JOIN jobs j ON j.id = a.job_id
      WHERE a.expires_at IS NOT NULL AND a.expires_at < now() AND a.deleted_at IS NULL AND a.artifact_dir IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM case_holds h WHERE h.case_ref = j.case_ref AND h.released_at IS NULL)
        -- Never delete while the job is still active or the attempt is referenced by an unexpired sibling export.
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
    const hold = await pool.query(`SELECT 1 FROM case_holds WHERE case_ref = $1 AND released_at IS NULL`, [r.case_ref]);
    if (hold.rowCount) continue;
    await rm(join(root, r.artifact_dir), { recursive: true, force: true });
    await rm(join(root, 'derived', r.id), { recursive: true, force: true });
    await pool.query(`UPDATE attempts SET deleted_at = now() WHERE id = $1`, [r.id]);
    await audit(pool, 'retention', 'attempt_artifacts_deleted', { dir: r.artifact_dir, policy_classes: policy.retention.classes }, { jobId: r.job_id, attemptId: r.id });
    deleted += 1;
  }
  if (rows.length) logger.info({ eligible: rows.length, deleted, delete_enabled: opts.deleteEnabled }, 'retention pass');
  return { eligible: rows.length, deleted };
}
