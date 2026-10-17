/**
 * Admission control and resource health (blueprint §15, §16).
 *  - Host free space below host_free_gb_pause_below pauses all new acquisition;
 *    it resumes only above host_free_gb_resume_above (hysteresis).
 *  - Retained capture bytes above captures_gb_soft_limit pause low-priority
 *    admission before urgent tasks exhaust storage.
 *  - Gateway unhealthy pauses acquisition (no unprotected fallback).
 * Directory-size checks are not a hard quota; writers are bounded regardless.
 */
import type { Policy } from '../config/policy.js';
import { audit, type Pool } from '../db/pool.js';
import { logger } from '../observability/logger.js';
import { diskFreeBytes } from '../storage/artifactStore.js';

const GB = 1e9;

export interface AdmissionState {
  paused: boolean;
  low_priority_paused: boolean;
  reasons: string[];
  host_free_gb?: number;
  captures_gb?: number;
  gateway_healthy?: boolean;
  checked_at?: string;
}

export async function evaluateAdmission(pool: Pool, policy: Policy, root: string, gatewayHealthy: boolean): Promise<AdmissionState> {
  const prev = (await pool.query<{ value: AdmissionState }>(`SELECT value FROM system_state WHERE key = 'admission'`)).rows[0]?.value
    ?? { paused: false, low_priority_paused: false, reasons: [] };
  const { free } = await diskFreeBytes(root);
  const freeGb = free / GB;
  const used = await pool.query<{ bytes: string | null }>(
    `SELECT COALESCE(sum(total_bytes), 0)::text AS bytes FROM attempts WHERE deleted_at IS NULL AND artifact_dir IS NOT NULL`,
  );
  const capturesGb = Number(used.rows[0]?.bytes ?? 0) / GB;

  const reasons: string[] = [];
  const wasDiskPaused = prev.reasons.includes('disk_free_low');
  const diskPaused = wasDiskPaused ? freeGb <= policy.storage.host_free_gb_resume_above : freeGb < policy.storage.host_free_gb_pause_below;
  if (diskPaused) reasons.push('disk_free_low');
  if (!gatewayHealthy) reasons.push('egress_gateway_unhealthy');
  const lowPriority = capturesGb >= policy.storage.captures_gb_soft_limit;
  if (lowPriority) reasons.push('captures_soft_limit_reached');

  const next: AdmissionState = {
    paused: diskPaused || !gatewayHealthy,
    low_priority_paused: lowPriority,
    reasons,
    host_free_gb: Number(freeGb.toFixed(2)),
    captures_gb: Number(capturesGb.toFixed(3)),
    gateway_healthy: gatewayHealthy,
    checked_at: new Date().toISOString(),
  };
  await pool.query(`UPDATE system_state SET value = $1, updated_at = now() WHERE key = 'admission'`, [next]);
  if (prev.paused !== next.paused || prev.low_priority_paused !== next.low_priority_paused) {
    logger.warn({ admission: next }, 'admission state changed');
    await audit(pool, 'coordinator', 'admission_changed', { from: prev, to: next });
  }
  return next;
}
