/**
 * Useful-result metrics (blueprint §16): measured from the ledger, not from
 * HTTP status or process uptime. Denominators are always reported.
 */
import type { Pool } from '../db/pool.js';

export async function collectStatus(pool: Pool, sinceHours = 24): Promise<Record<string, unknown>> {
  const q = async <T extends Record<string, unknown>>(sql: string, params: unknown[] = []) => (await pool.query<T>(sql, params)).rows;
  const since = `now() - make_interval(hours => $1)`;

  const [queue] = await q<{ due: number; oldest_due_seconds: number | null; active: number; deferred: number; manual_review: number }>(
    `SELECT count(*) FILTER (WHERE state IN ('QUEUED','DEFERRED') AND next_eligible_at <= now())::int AS due,
            EXTRACT(EPOCH FROM now() - min(next_eligible_at) FILTER (WHERE state IN ('QUEUED','DEFERRED') AND next_eligible_at <= now()))::int AS oldest_due_seconds,
            count(*) FILTER (WHERE state IN ('LEASED','CAPTURING','FINALISING'))::int AS active,
            count(*) FILTER (WHERE state = 'DEFERRED')::int AS deferred,
            count(*) FILTER (WHERE state = 'MANUAL_REVIEW')::int AS manual_review
       FROM jobs`,
  );
  const backlog = await q(`SELECT stage, urgent, count(*)::int AS n FROM jobs WHERE state IN ('QUEUED','DEFERRED') GROUP BY stage, urgent ORDER BY stage, urgent DESC`);
  const states = await q(`SELECT profile, state, outcome, count(*)::int AS n FROM jobs WHERE finished_at > ${since} GROUP BY profile, state, outcome ORDER BY profile, n DESC`, [sinceHours]);
  const [evidence] = await q<{ finished: number; complete: number; partial: number; blocked_or_unavailable: number; infrastructure: number }>(
    `SELECT count(*)::int AS finished,
            count(*) FILTER (WHERE state = 'COMPLETE')::int AS complete,
            count(*) FILTER (WHERE state = 'PARTIAL')::int AS partial,
            count(*) FILTER (WHERE outcome IN ('ACCESS_BLOCKED','AUTH_REQUIRED','CHALLENGE_PAGE_CAPTURED','DNS_FAILURE','TLS_FAILURE','NOT_FOUND','ORIGIN_UNAVAILABLE'))::int AS blocked_or_unavailable,
            count(*) FILTER (WHERE outcome = 'INFRASTRUCTURE_DEFERRED')::int AS infrastructure
       FROM jobs WHERE profile = 'browser_evidence' AND finished_at > ${since}`, [sinceHours]);
  const screenshots = await q(
    `SELECT ar.artifact_type, ar.completeness, count(*)::int AS n FROM artifacts ar JOIN attempts a ON a.id = ar.attempt_id
      WHERE a.started_at > ${since} AND ar.artifact_type IN ('screenshot_early','screenshot_settled','screenshot_full_or_tiles','screenshot_tile','element_crop')
      GROUP BY 1, 2 ORDER BY 1, 2`, [sinceHours]);
  const fields = await q(
    `SELECT f.field_type, f.status, count(*)::int AS n FROM identifier_field_status f JOIN attempts a ON a.id = f.attempt_id
      WHERE a.started_at > ${since} GROUP BY 1, 2 ORDER BY 1, 2`, [sinceHours]);
  const adapter = await q(
    `SELECT a.engine, count(*)::int AS attempts,
            count(*) FILTER (WHERE a.outcome = 'CONTENT_CAPTURED')::int AS content_captured,
            round(avg(a.active_seconds)::numeric, 1) AS avg_seconds, COALESCE(sum(a.total_bytes), 0)::bigint AS bytes
       FROM attempts a WHERE a.started_at > ${since} GROUP BY a.engine ORDER BY a.engine`, [sinceHours]);
  const [alternate] = await q<{ attempts: number; recoveries: number }>(
    `SELECT count(*)::int AS attempts, count(*) FILTER (WHERE a.outcome = 'CONTENT_CAPTURED')::int AS recoveries
       FROM attempts a WHERE a.started_at > ${since} AND a.settings->>'stage' IN ('browser_alternate','scrapling')`, [sinceHours]);
  const [integrity] = await q<{ lease_losses: number; reclaimed: number; hash_mismatches: number; orphans_recovered: number }>(
    `SELECT count(*) FILTER (WHERE event_type = 'commit_after_lease_loss')::int AS lease_losses,
            count(*) FILTER (WHERE event_type = 'lease_reclaimed')::int AS reclaimed,
            count(*) FILTER (WHERE event_type = 'artifact_hash_mismatch')::int AS hash_mismatches,
            count(*) FILTER (WHERE event_type IN ('orphan_final_directory_recovered','tmp_directory_salvaged'))::int AS orphans_recovered
       FROM audit_events WHERE at > ${since}`, [sinceHours]);
  const [dedup] = await q<{ merged: number }>(`SELECT COALESCE(sum((counts->>'jobs_merged')::int), 0)::int AS merged FROM import_batches WHERE created_at > ${since}`, [sinceHours]);
  const system = await q<{ key: string; value: unknown; updated_at: Date }>(`SELECT key, value, updated_at FROM system_state ORDER BY key`);
  const workers = await q(`SELECT worker_id, role, last_seen_at, EXTRACT(EPOCH FROM now() - last_seen_at)::int AS seconds_since, details FROM worker_heartbeats ORDER BY role, worker_id`);
  const permits = await q(`SELECT slot, holder_job_id, adapter, expires_at FROM global_permits ORDER BY slot`);

  const rate = (n: number, d: number) => (d > 0 ? Number((n / d).toFixed(4)) : null);
  return {
    generated_at: new Date().toISOString(),
    window_hours: sinceHours,
    queue: { ...queue, backlog, duplicate_seeds_merged: dedup?.merged ?? 0 },
    required_artifact_completion: {
      denominator_finished_browser_evidence_jobs: evidence?.finished ?? 0,
      complete: evidence?.complete ?? 0, partial: evidence?.partial ?? 0,
      blocked_or_unavailable: evidence?.blocked_or_unavailable ?? 0, infrastructure_deferred: evidence?.infrastructure ?? 0,
      completion_rate: rate(evidence?.complete ?? 0, evidence?.finished ?? 0),
      note: 'blocked/unavailable/infrastructure outcomes reported separately; target mix affects all rates',
    },
    outcomes: states,
    screenshot_yield: screenshots,
    identifier_field_status: fields,
    adapter_cost: adapter,
    alternate_adapter_benefit: { attempts: alternate?.attempts ?? 0, content_recoveries: alternate?.recoveries ?? 0, benefit_rate: rate(alternate?.recoveries ?? 0, alternate?.attempts ?? 0) },
    integrity,
    system_state: system,
    workers,
    browser_permits: permits,
  };
}
