/**
 * Analytics for analysts and metrics for operators (blueprint v4 §16, §22.1
 * /analytics, §22.2; checklist §9 "expose metrics", §10 "trustworthy charts").
 * Every figure states its denominator, scope, definition and refresh time, and
 * keeps observed, inferred, confirmed and actioned figures apart.
 */
import { safeEqual } from '../auth.js';
import { caseByRef, seesAllCases } from '../authz.js';
import { badRequest, forbidden, HttpError, queryInt, type Ctx, type RouteSpec } from '../http.js';
import { auditCtx, type RouteDeps } from './common.js';

const cache = new Map<string, { at: number; body: unknown }>();

export function opsRoutes(d: RouteDeps): RouteSpec[] {
  return [
    {
      method: 'GET', path: '/api/v1/analytics', auth: 'full',
      handler: async (ctx) => {
        const days = queryInt(ctx.url, 'days', 7, 1, 90);
        const caseRef = ctx.url.searchParams.get('case_ref');
        if (caseRef) {
          const c = await caseByRef(d.pool, caseRef);
          if (!c) throw badRequest('unknown_case', 'case not found');
          const { assertCaseAccess } = await import('../authz.js');
          await assertCaseAccess(d.pool, ctx.user!, c.id);
        }
        const all = seesAllCases(ctx.user!);
        const key = `${all ? 'all' : ctx.user!.id}|${caseRef ?? ''}|${days}`;
        const ttl = d.policy.web.dashboard_aggregation_cache_seconds * 1000;
        const hit = cache.get(key);
        if (hit && Date.now() - hit.at < ttl) return hit.body;
        const scope = `($1::boolean OR EXISTS (SELECT 1 FROM job_case_links l JOIN cases c ON c.case_ref = l.case_ref JOIN case_members m ON m.case_id = c.id WHERE l.job_id = j.id AND m.user_id = $2::uuid))
          AND ($3::text IS NULL OR EXISTS (SELECT 1 FROM job_case_links l2 WHERE l2.job_id = j.id AND l2.case_ref = $3))`;
        const p = [all, ctx.user!.id, caseRef, days];
        const q = async <T extends Record<string, unknown>>(sql: string) => (await d.pool.query<T>(sql, p)).rows;
        const [jobs] = await q<{ total: number; complete: number; partial: number; failed: number; manual: number; open: number }>(
          `SELECT count(*)::int AS total, count(*) FILTER (WHERE state = 'COMPLETE')::int AS complete, count(*) FILTER (WHERE state = 'PARTIAL')::int AS partial,
                  count(*) FILTER (WHERE state = 'FAILED_FINAL')::int AS failed, count(*) FILTER (WHERE state = 'MANUAL_REVIEW')::int AS manual,
                  count(*) FILTER (WHERE state IN ('QUEUED','DEFERRED','LEASED','CAPTURING','FINALISING'))::int AS open
             FROM jobs j WHERE j.created_at > now() - make_interval(days => $4) AND ${scope}`);
        const outcomes = await q<{ outcome: string | null; n: number }>(
          `SELECT j.outcome, count(*)::int AS n FROM jobs j WHERE j.created_at > now() - make_interval(days => $4) AND j.state NOT IN ('QUEUED','LEASED','CAPTURING','FINALISING') AND ${scope} GROUP BY 1 ORDER BY 2 DESC`);
        const [latency] = await q<{ n: number; p50: number | null; p95: number | null }>(
          `SELECT count(*)::int AS n, percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM a.first_image_at - a.started_at))::float8 AS p50,
                  percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM a.first_image_at - a.started_at))::float8 AS p95
             FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE a.first_image_at IS NOT NULL AND a.started_at > now() - make_interval(days => $4) AND ${scope}`);
        const [firstCapture] = await q<{ n: number; p50: number | null; p95: number | null }>(
          `SELECT count(*)::int AS n, percentile_cont(0.5) WITHIN GROUP (ORDER BY secs)::float8 AS p50, percentile_cont(0.95) WITHIN GROUP (ORDER BY secs)::float8 AS p95
             FROM (SELECT EXTRACT(EPOCH FROM min(a.first_image_at) - j.created_at) AS secs FROM jobs j JOIN attempts a ON a.job_id = j.id
                    WHERE a.first_image_at IS NOT NULL AND j.created_at > now() - make_interval(days => $4) AND j.parent_job_id IS NULL AND ${scope} GROUP BY j.id) x`);
        const verdicts = await q<{ verdict: string; n: number }>(
          `SELECT COALESCE(v.verdict, 'unreviewed') AS verdict, count(DISTINCT j.target_id)::int AS n FROM jobs j LEFT JOIN target_verdicts v ON v.target_id = j.target_id
            WHERE j.created_at > now() - make_interval(days => $4) AND j.parent_job_id IS NULL AND ${scope} GROUP BY 1 ORDER BY 2 DESC`);
        const [fpReversals] = await q<{ n: number }>(
          `SELECT count(*)::int AS n FROM analyst_decisions d JOIN jobs j ON j.target_id = d.target_id
            WHERE d.decision = 'override_suppression' AND d.created_at > now() - make_interval(days => $4) AND ${scope}`);
        const notices = await q<{ state: string; n: number }>(
          `SELECT n.state, count(DISTINCT n.id)::int AS n FROM notices n JOIN notice_targets nt ON nt.notice_id = n.id JOIN jobs j ON j.target_id = nt.target_id
            WHERE n.created_at > now() - make_interval(days => $4) AND ${scope} GROUP BY 1 ORDER BY 2 DESC`);
        const [ack] = await q<{ n: number; median_hours: number | null }>(
          `SELECT count(*)::int AS n, percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM n.received_at - n.issued_at) / 3600)::float8 AS median_hours
             FROM notices n WHERE n.issued_at IS NOT NULL AND n.received_at IS NOT NULL AND n.issued_at > now() - make_interval(days => $4)
              AND EXISTS (SELECT 1 FROM notice_targets nt JOIN jobs j ON j.target_id = nt.target_id WHERE nt.notice_id = n.id AND ${scope})`);
        const monitoring = await q<{ outcome_class: string; n: number }>(
          `SELECT o.outcome_class, count(*)::int AS n FROM monitoring_observations o JOIN jobs j ON j.id = o.job_id WHERE o.created_at > now() - make_interval(days => $4) AND ${scope} GROUP BY 1 ORDER BY 2 DESC`);
        const [verification] = await q<{ bad: number; checked: number }>(
          `SELECT count(*) FILTER (WHERE ar.verification_state IN ('mismatch','missing'))::int AS bad, count(*) FILTER (WHERE ar.verification_state <> 'unverified')::int AS checked
             FROM artifacts ar JOIN attempts a ON a.id = ar.attempt_id JOIN jobs j ON j.id = a.job_id WHERE a.started_at > now() - make_interval(days => $4) AND ${scope}`);
        const usable = (jobs?.complete ?? 0) + (jobs?.partial ?? 0);
        const finished = (jobs?.total ?? 0) - (jobs?.open ?? 0);
        const body = {
          generated_at: new Date().toISOString(), cache_seconds: d.policy.web.dashboard_aggregation_cache_seconds, window_days: days, scope: caseRef ? `case ${caseRef}` : all ? 'all cases' : 'your cases',
          observed: {
            jobs: { ...jobs, definition: 'Jobs created in the window. Open = not yet finished.' },
            usable_evidence_rate: { numerator: usable, denominator: finished, value: finished ? Number((usable / finished).toFixed(3)) : null, definition: 'COMPLETE or PARTIAL jobs among finished jobs (challenge/blocked/unavailable excluded from the numerator).' },
            outcomes: { items: outcomes, definition: 'Acquisition outcome of finished jobs. A blocked or unavailable result at this vantage is not proof the site is down elsewhere.' },
            first_image_seconds: { ...latency, definition: 'Seconds from attempt start to the first validated viewport image (per attempt).' },
            first_capture_seconds: { ...firstCapture, definition: 'Seconds from job creation (queue time included) to its first validated image.' },
            evidence_verification: { failures: verification?.bad ?? 0, artifacts_checked: verification?.checked ?? 0, definition: 'Artifacts whose bytes failed hash verification (mismatch or missing) among artifacts verified at least once.' },
          },
          inferred: { note: 'Risk scores are triage aids and are not reported as findings.' },
          confirmed: {
            verdicts: { items: verdicts, definition: 'Latest analyst verdict per target (distinct targets). Unreviewed targets are listed, not hidden.' },
            false_positive_overrides: { n: fpReversals?.n ?? 0, definition: 'Approver overrides of a false-positive suppression on new evidence.' },
          },
          actioned: {
            notices: { items: notices, definition: 'Notices by current state. Issued is not complied; complied is not verified removal.' },
            acknowledgement_hours: { ...ack, definition: 'Median hours from recorded issuance to documented receipt (only notices with both).' },
            monitoring: { items: monitoring, definition: 'Revisit outcomes recorded in the window.' },
          },
        };
        cache.set(key, { at: Date.now(), body });
        if (cache.size > 500) cache.clear();
        return body;
      },
    },
    {
      method: 'GET', path: '/api/v1/metrics', auth: 'none', csrf: false,
      handler: async (ctx) => {
        await authoriseMetrics(ctx, d);
        const lines: string[] = [];
        const gauge = (name: string, help: string, rows: { labels?: Record<string, string>; value: number | null }[]) => {
          lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} gauge`);
          for (const r of rows) {
            const l = r.labels ? `{${Object.entries(r.labels).map(([k, v]) => `${k}="${String(v).replace(/["\\\n]/g, '_')}"`).join(',')}}` : '';
            lines.push(`${name}${l} ${r.value ?? 'NaN'}`);
          }
        };
        const q = async <T extends Record<string, unknown>>(sql: string) => (await d.pool.query<T>(sql)).rows;
        gauge('cwc_jobs', 'Jobs by processing state', (await q<{ state: string; n: number }>(`SELECT state::text, count(*)::int AS n FROM jobs GROUP BY 1`)).map((r) => ({ labels: { state: r.state }, value: r.n })));
        gauge('cwc_queue_oldest_due_seconds', 'Age of the oldest due job', (await q<{ v: number | null }>(`SELECT EXTRACT(EPOCH FROM now() - min(next_eligible_at))::float8 AS v FROM jobs WHERE state IN ('QUEUED','DEFERRED') AND next_eligible_at <= now()`)).map((r) => ({ value: r.v ?? 0 })));
        gauge('cwc_leases_expired', 'Active leases past expiry (stalled workers)', (await q<{ n: number }>(`SELECT count(*)::int AS n FROM jobs WHERE state IN ('LEASED','CAPTURING','FINALISING') AND lease_expires_at < now()`)).map((r) => ({ value: r.n })));
        gauge('cwc_attempts_last_hour', 'Attempts finished in the last hour by outcome', (await q<{ outcome: string | null; n: number }>(`SELECT COALESCE(outcome::text,'none') AS outcome, count(*)::int AS n FROM attempts WHERE ended_at > now() - interval '1 hour' GROUP BY 1`)).map((r) => ({ labels: { outcome: String(r.outcome) }, value: r.n })));
        gauge('cwc_screenshots_last_hour', 'Validated screenshots saved in the last hour', (await q<{ n: number }>(`SELECT count(*)::int AS n FROM artifacts ar JOIN attempts a ON a.id = ar.attempt_id WHERE ar.artifact_type LIKE 'screenshot_%' AND ar.relative_path IS NOT NULL AND a.ended_at > now() - interval '1 hour'`)).map((r) => ({ value: r.n })));
        const lat = (await q<{ p50: number | null; p95: number | null }>(`SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM first_image_at - started_at))::float8 AS p50, percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM first_image_at - started_at))::float8 AS p95 FROM attempts WHERE first_image_at > now() - interval '24 hours'`))[0];
        gauge('cwc_first_image_seconds', 'First validated image latency over 24 h', [{ labels: { quantile: '0.5' }, value: lat?.p50 ?? null }, { labels: { quantile: '0.95' }, value: lat?.p95 ?? null }]);
        gauge('cwc_artifact_verification_failures', 'Artifacts in mismatch or missing state', (await q<{ n: number }>(`SELECT count(*)::int AS n FROM artifacts WHERE verification_state IN ('mismatch','missing')`)).map((r) => ({ value: r.n })));
        gauge('cwc_custody_unsealed_events', 'Audit events not yet sealed into the custody chain', (await q<{ n: number }>(`SELECT count(*)::int AS n FROM audit_events WHERE chain_pos IS NULL`)).map((r) => ({ value: r.n })));
        gauge('cwc_extraction_backlog', 'Attempts awaiting extraction', (await q<{ n: number }>(`SELECT count(*)::int AS n FROM attempts WHERE extraction_state IN ('pending','running')`)).map((r) => ({ value: r.n })));
        gauge('cwc_browser_permits_held', 'Global browser permits currently held', (await q<{ n: number }>(`SELECT count(*)::int AS n FROM global_permits WHERE holder_job_id IS NOT NULL AND expires_at > now()`)).map((r) => ({ value: r.n })));
        const adm = (await q<{ value: { paused: boolean; low_priority_paused: boolean } }>(`SELECT value FROM system_state WHERE key = 'admission'`))[0]?.value;
        gauge('cwc_admission_paused', 'Admission control state (1 = paused)', [{ labels: { scope: 'all' }, value: adm?.paused ? 1 : 0 }, { labels: { scope: 'low_priority' }, value: adm?.low_priority_paused ? 1 : 0 }]);
        const backup = (await q<{ age: number | null }>(`SELECT EXTRACT(EPOCH FROM now() - (value->>'last_success_at')::timestamptz)::float8 AS age FROM system_state WHERE key = 'backup'`))[0];
        gauge('cwc_backup_age_seconds', 'Age of the last recorded successful backup', [{ value: backup?.age ?? null }]);
        gauge('cwc_worker_last_seen_seconds', 'Seconds since each worker heartbeat', (await q<{ worker_id: string; role: string; age: number }>(`SELECT worker_id, role, EXTRACT(EPOCH FROM now() - last_seen_at)::float8 AS age FROM worker_heartbeats`)).map((r) => ({ labels: { role: r.role, worker: r.worker_id }, value: r.age })));
        return { status: 200, raw: Buffer.from(`${lines.join('\n')}\n`), contentType: 'text/plain; version=0.0.4; charset=utf-8' };
      },
    },
  ];
}

/** Metrics: a bearer token for scrapers (METRICS_BEARER_TOKEN), or a signed-in admin/auditor. */
async function authoriseMetrics(ctx: Ctx, d: RouteDeps): Promise<void> {
  const token = process.env.METRICS_BEARER_TOKEN;
  const auth = ctx.req.headers.authorization;
  if (token && token.length >= 24 && typeof auth === 'string' && auth.startsWith('Bearer ') && safeEqual(auth.slice(7), token)) return;
  const { parseCookies } = await import('../http.js');
  const { resolveSession, SESSION_COOKIE } = await import('../auth.js');
  const w = d.policy.web;
  const user = await resolveSession(d.pool, parseCookies(ctx.req.headers.cookie)[SESSION_COOKIE], { idleMinutes: w.session_idle_minutes, absoluteHours: w.session_absolute_hours, mfaRequired: w.mfa_required });
  if (!user) throw new HttpError(401, 'unauthenticated', 'metrics need a bearer token or an administrator/auditor session');
  if (!user.mfaVerified || !user.roles.some((r) => r === 'admin' || r === 'auditor')) throw forbidden('metrics require the admin or auditor role');
  ctx.user = user;
  await auditCtx(d.pool, ctx, 'metrics_viewed', {}, { objectType: 'metrics', objectId: 'prometheus' });
}
