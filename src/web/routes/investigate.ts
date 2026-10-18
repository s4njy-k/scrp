/**
 * Single-target investigation view, analyst decisions, extraction reviews,
 * annotations and scoped entity search (blueprint v4 §22.1 /investigate,
 * /review, §22.4, §23.2; checklist §3, §5, §7, §10).
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { withTransaction } from '../../db/pool.js';
import { formatIst } from '../../evidence/time.js';
import { DECISION_VERDICT, REASON_CODES, suppressionState } from '../../investigation/decisions.js';
import { relatedTargets } from '../../investigation/correlation.js';
import { domainContext, findLookalikes } from '../../investigation/brands.js';
import { suggestAddressees } from '../../enrichment/enrich.js';
import { assertSafeRelative } from '../../storage/artifactStore.js';
import { assertAttemptAccess, assertTargetAccess, caseByRef, hasRole, jobVisibleSql, seesAllCases } from '../authz.js';
import { badRequest, conflict, forbidden, queryInt, reply, requireIntId, type Ctx, type RouteSpec } from '../http.js';
import { JOB_SUMMARY_SELECT, presentJob, type JobSummaryRow } from './jobs.js';
import { auditCtx, parseBody, type RouteDeps } from './common.js';

/** Fields specific enough to correlate across sites (low-specificity signals are excluded). */
export const STRONG_FIELDS = ['upi_vpa', 'upi_uri', 'phone', 'whatsapp', 'telegram', 'email', 'bank_account', 'crypto_btc', 'crypto_eth', 'crypto_tron', 'gstin', 'cin'];

async function visibleJobIds(ctx: Ctx, d: RouteDeps, targetId: number): Promise<number[]> {
  return (await d.pool.query<{ id: number }>(
    `SELECT j.id FROM jobs j WHERE j.target_id = $3 AND ${jobVisibleSql('j', 1, 2)}`, [ctx.user!.id, seesAllCases(ctx.user!), targetId],
  )).rows.map((r) => r.id);
}

export function investigateRoutes(d: RouteDeps): RouteSpec[] {
  return [
    {
      method: 'GET', path: '/api/v1/targets/:id/investigation', auth: 'full',
      handler: async (ctx) => {
        const targetId = requireIntId(ctx.params.id);
        await assertTargetAccess(d.pool, ctx.user!, targetId);
        const jobIds = await visibleJobIds(ctx, d, targetId);
        const target = (await d.pool.query(
          `SELECT id, url, input_kind, scheme, hostname_ascii, hostname_unicode, port, path_and_query, fragment, registrable_domain, is_ip_literal, nonstandard_port, created_at
             FROM targets WHERE id = $1`, [targetId],
        )).rows[0];
        const jobs = (await d.pool.query<JobSummaryRow>(`${JOB_SUMMARY_SELECT} WHERE j.id = ANY($1::bigint[]) ORDER BY j.created_at DESC LIMIT 50`, [jobIds])).rows.map((r) => presentJob(r, d.policy));
        const attempts = (await d.pool.query<{ id: string; job_id: number; artifact_dir: string | null; started_at: Date; kind: string; status: string }>(
          `SELECT a.id, a.job_id, a.attempt_no, a.kind, a.engine, a.capture_variant, a.vantage, a.status, a.outcome, a.classification, a.started_at, a.ended_at,
                  a.required_satisfied, a.missing_required, a.manifest_sha256, a.artifact_dir, a.first_image_at, a.extraction_state, a.engine_version, a.deleted_at
             FROM attempts a WHERE a.job_id = ANY($1::bigint[]) ORDER BY a.started_at DESC LIMIT 100`, [jobIds],
        )).rows;
        // Read final URL, limitations and redirect chain from the newest manifests (bounded).
        const timeline = [];
        for (const a of attempts.slice(0, 30)) {
          let m: Record<string, unknown> | null = null;
          if (a.artifact_dir && timeline.length < 10) {
            try {
              assertSafeRelative(a.artifact_dir);
              m = JSON.parse(await readFile(join(d.root, a.artifact_dir, 'manifest.json'), 'utf8')) as Record<string, unknown>;
            } catch { m = null; }
          }
          timeline.push({ ...a, artifact_dir: undefined, started_at_ist: formatIst(a.started_at), final_url: m?.finalUrl ?? null, limitations: m?.limitations ?? null, redirect_chain: m?.redirectChain ?? null, capture_context: m?.captureContext ?? null, clock: m?.clock ?? null });
        }
        const best = attempts.find((a) => a.kind === 'browser' && ['committed', 'recovered'].includes(a.status) && a.artifact_dir) ?? attempts.find((a) => a.artifact_dir);
        const images = best ? (await d.pool.query(
          `SELECT ar.id, ar.artifact_type, ar.observed_start, ar.observed_end, ar.completeness, ar.limitations, ar.metadata, ar.verification_state, ar.sha256,
                  (SELECT t.id FROM artifacts t WHERE t.derived_from = ar.id AND t.artifact_type = 'thumbnail' ORDER BY t.id DESC LIMIT 1) AS thumbnail_id
             FROM artifacts ar WHERE ar.attempt_id = $1 AND ar.relative_path IS NOT NULL AND ar.relative_path LIKE '%.png' AND NOT ar.is_derivative
            ORDER BY ar.observed_start NULLS LAST, ar.id`, [best.id],
        )).rows : [];
        const identifiers = (await d.pool.query(
          `SELECT i.field_type, COALESCE(i.value_key, i.normalised_value, i.raw_value) AS value_key, max(i.normalised_value) AS normalised_value,
                  (array_agg(i.raw_value ORDER BY i.id))[1] AS raw_value,
                  array_agg(DISTINCT i.method) AS methods, array_agg(DISTINCT i.validation_state) AS validation_states,
                  array_agg(DISTINCT i.display_context) AS display_contexts, bool_or(i.signal_only) AS signal_only,
                  min(i.observed_at) AS first_observed, max(i.observed_at) AS last_observed, count(DISTINCT i.attempt_id)::int AS attempts,
                  max(i.confidence) AS confidence,
                  jsonb_agg(DISTINCT i.conflicts) FILTER (WHERE i.conflicts <> '[]'::jsonb) AS conflicts,
                  (array_agg(jsonb_build_object('attempt_id', i.attempt_id, 'artifact_id', i.source_artifact_id, 'method', i.method, 'bbox', i.bbox,
                     'locator', i.locator, 'frame_url', i.frame_url, 'source_url', i.source_url, 'context', i.context, 'artifact_sha256', i.artifact_sha256,
                     'observed_at', i.observed_at, 'extractor_version', i.extractor_version) ORDER BY (i.method = 'qr') DESC, (i.display_context = 'displayed') DESC, i.id DESC))[1:5] AS provenance
             FROM identifiers i WHERE i.job_id = ANY($1::bigint[])
            GROUP BY i.field_type, COALESCE(i.value_key, i.normalised_value, i.raw_value)
            ORDER BY CASE i.field_type WHEN 'upi_vpa' THEN 1 WHEN 'upi_uri' THEN 2 WHEN 'qr_payload' THEN 3 WHEN 'phone' THEN 4 WHEN 'whatsapp' THEN 5
                       WHEN 'telegram' THEN 6 WHEN 'email' THEN 7 WHEN 'bank_account' THEN 8 WHEN 'ifsc' THEN 9 ELSE 20 END, i.field_type, 2
            LIMIT 500`, [jobIds],
        )).rows as Record<string, unknown>[];
        const reviews = (await d.pool.query<{ field_type: string; value_key: string; state: string; corrected_value: string | null; reason_code: string; reason: string; actor: string; created_at: Date }>(
          `SELECT DISTINCT ON (field_type, value_key) field_type, value_key, state, corrected_value, reason_code, reason, actor, created_at
             FROM identifier_reviews WHERE target_id = $1 ORDER BY field_type, value_key, id DESC`, [targetId],
        )).rows;
        const reviewMap = new Map(reviews.map((r) => [`${r.field_type}|${r.value_key}`, r]));
        // Other targets in the viewer's scope that show the same strong identifier (correlation lead, not attribution).
        const strongKeys = identifiers.filter((i) => STRONG_FIELDS.includes(String(i.field_type))).map((i) => `${i.field_type}|${i.value_key}`);
        const occurrences = strongKeys.length ? (await d.pool.query<{ k: string; targets: number }>(
          `SELECT i.field_type || '|' || COALESCE(i.value_key, i.normalised_value, i.raw_value) AS k, count(DISTINCT i.target_id)::int AS targets
             FROM identifiers i JOIN jobs j ON j.id = i.job_id
            WHERE i.field_type || '|' || COALESCE(i.value_key, i.normalised_value, i.raw_value) = ANY($3::text[]) AND i.target_id <> $4 AND ${jobVisibleSql('j', 1, 2)}
            GROUP BY 1`, [ctx.user!.id, seesAllCases(ctx.user!), strongKeys, targetId],
        )).rows : [];
        const occMap = new Map(occurrences.map((o) => [o.k, o.targets]));
        for (const i of identifiers) {
          const k = `${i.field_type}|${i.value_key}`;
          const r = reviewMap.get(k);
          const validation = i.validation_states as string[];
          i.review_state = r?.state ?? (validation.includes('format_valid') && !i.signal_only ? 'candidate' : 'unverified');
          i.review = r ?? null;
          i.other_targets_in_scope = occMap.get(k) ?? 0;
        }
        const fieldStatus = best ? (await d.pool.query('SELECT field_type, status, detail FROM identifier_field_status WHERE attempt_id = $1 ORDER BY field_type', [best.id])).rows : [];
        const edges = best ? (await d.pool.query(
          `SELECT edge_type, from_url, to_url, to_host, contacted, observed_at FROM domain_edges WHERE attempt_id = $1 AND edge_type IN ('redirect','meta_refresh','js_navigation','popup','form_action') ORDER BY observed_at NULLS LAST, id LIMIT 100`, [best.id],
        )).rows : [];
        const contactedHosts = best ? (await d.pool.query(
          `SELECT to_host, count(*)::int AS requests, array_agg(DISTINCT edge_type) AS kinds FROM domain_edges WHERE attempt_id = $1 AND contacted GROUP BY to_host ORDER BY 2 DESC LIMIT 40`, [best.id],
        )).rows : [];
        const risk = (await d.pool.query('SELECT * FROM risk_assessments WHERE target_id = $1 ORDER BY id DESC LIMIT 1', [targetId])).rows[0] ?? null;
        const decisions = (await d.pool.query(
          `SELECT id, decision, verdict, reason_code, reason, evidence_refs, new_evidence_attempt, actor, created_at FROM analyst_decisions WHERE target_id = $1 ORDER BY id DESC LIMIT 50`, [targetId],
        )).rows;
        const suppression = await suppressionState(d.pool, targetId);
        const notices = (await d.pool.query(
          `SELECT n.id, n.route, n.state, n.reference_no, n.recipient, n.created_at, n.issued_at, n.received_at, nt.target_status, n.case_id
             FROM notice_targets nt JOIN notices n ON n.id = nt.notice_id
            WHERE nt.target_id = $1 AND ($3::boolean OR EXISTS (SELECT 1 FROM case_members m WHERE m.case_id = n.case_id AND m.user_id = $2))
            ORDER BY n.created_at DESC`, [targetId, ctx.user!.id, seesAllCases(ctx.user!)],
        )).rows;
        const enrichment = (await d.pool.query(
          `SELECT DISTINCT ON (source, subject) subject_kind, subject, source, status, data, error, method, observation_point, retrieved_at, expires_at
             FROM enrichment_results WHERE subject IN ($1, $2) ORDER BY source, subject, retrieved_at DESC`, [target.registrable_domain, target.hostname_ascii],
        )).rows;
        const monitoring = (await d.pool.query(
          `SELECT r.id, r.interval_hours, r.active, r.next_due_at, r.ends_at, r.revisits, r.reason, r.capture_variant,
                  (SELECT jsonb_agg(o ORDER BY o.id DESC) FROM (SELECT id, outcome_class, differences, created_at, job_id FROM monitoring_observations WHERE rule_id = r.id ORDER BY id DESC LIMIT 10) o) AS observations
             FROM monitoring_rules r WHERE r.target_id = $1 ORDER BY r.created_at DESC`, [targetId],
        )).rows;
        const annotations = (await d.pool.query(`SELECT id, body, actor, created_at, supersedes FROM annotations WHERE object_type = 'target' AND object_id = $1 ORDER BY id DESC LIMIT 50`, [String(targetId)])).rows;
        const caseRefs = (await d.pool.query<{ case_ref: string }>('SELECT DISTINCT case_ref FROM job_case_links WHERE job_id = ANY($1::bigint[]) ORDER BY 1', [jobIds])).rows.map((r) => r.case_ref);
        await auditCtx(d.pool, ctx, 'investigation_viewed', { jobs: jobIds.length }, { objectType: 'target', objectId: targetId, caseRef: caseRefs[0] ?? null });
        return {
          target, case_refs: caseRefs, jobs, timeline,
          best_capture: best ? { attempt_id: best.id, job_id: best.job_id, started_at: best.started_at, started_at_ist: formatIst(best.started_at), status: best.status } : null,
          images, identifiers, field_status: fieldStatus, redirects: edges, contacted_hosts: contactedHosts,
          risk, decisions, verdict: decisions[0]?.verdict ?? 'unreviewed', suppression, notices,
          action: notices[0]?.state ?? 'none', enrichment, monitoring, annotations,
          reason_codes: REASON_CODES,
          disclaimer: 'Screenshots are observations of one browser session at the recorded time. Extracted values are leads: format validity does not establish ownership, operability or criminal involvement.',
        };
      },
    },
    {
      method: 'GET', path: '/api/v1/targets/:id/related', auth: 'full',
      handler: async (ctx) => {
        const targetId = requireIntId(ctx.params.id);
        await assertTargetAccess(d.pool, ctx.user!, targetId);
        const items = await relatedTargets(d.pool, targetId, { userId: ctx.user!.id, all: seesAllCases(ctx.user!) });
        await auditCtx(d.pool, ctx, 'correlation_viewed', { results: items.length }, { objectType: 'target', objectId: targetId });
        return {
          items,
          rule: 'Grouped as a possible relationship only with two or more distinct uncommon identifiers (at least one strong). Shared CDN/IP, registrar, analytics IDs, favicons or templates alone never group sites. Frequency counts are within your case scope.',
        };
      },
    },
    {
      method: 'GET', path: '/api/v1/targets/:id/addressees', auth: 'full',
      handler: async (ctx) => {
        const targetId = requireIntId(ctx.params.id);
        await assertTargetAccess(d.pool, ctx.user!, targetId);
        const t = (await d.pool.query<{ hostname_ascii: string; registrable_domain: string }>('SELECT hostname_ascii, registrable_domain FROM targets WHERE id = $1', [targetId])).rows[0]!;
        const rows = (await d.pool.query<{ source: string; status: string; data: Record<string, unknown>; subject: string; retrieved_at: Date }>(
          `SELECT DISTINCT ON (source) source, status, data, subject, retrieved_at FROM enrichment_results
            WHERE subject = ANY($1::text[]) OR (source = 'rdap_ip' AND subject IN (SELECT jsonb_array_elements_text(data->'host_A') FROM enrichment_results WHERE subject = $2 AND source = 'dns'))
            ORDER BY source, retrieved_at DESC`, [[t.hostname_ascii, t.registrable_domain], t.hostname_ascii],
        )).rows;
        const apps = (await d.pool.query<{ v: string }>(`SELECT DISTINCT COALESCE(value_key, normalised_value) AS v FROM identifiers WHERE target_id = $1 AND field_type = 'app_store_link'`, [targetId])).rows.map((r) => r.v);
        return { addressees: suggestAddressees(rows, apps), sources: rows.map((r) => ({ source: r.source, status: r.status, subject: r.subject, retrieved_at: r.retrieved_at })),
          note: 'Suggestions from enrichment; verify each recipient before drafting. Registrar, registry, host, CDN and app distributor are different addressees with different powers.' };
      },
    },
    {
      method: 'POST', path: '/api/v1/targets/:id/enrich', auth: 'full', roles: ['analyst', 'admin'],
      handler: async (ctx) => {
        const targetId = requireIntId(ctx.params.id);
        await assertTargetAccess(d.pool, ctx.user!, targetId, 'investigator');
        await d.pool.query('UPDATE targets SET enrichment_done_at = NULL, enrichment_requested_at = NULL WHERE id = $1', [targetId]);
        await d.pool.query(`UPDATE enrichment_results SET expires_at = now() WHERE subject IN (SELECT hostname_ascii FROM targets WHERE id = $1 UNION SELECT registrable_domain FROM targets WHERE id = $1) AND expires_at > now()`, [targetId]);
        await auditCtx(d.pool, ctx, 'enrichment_refresh_requested', {}, { objectType: 'target', objectId: targetId });
        return reply(202, { queued: true, note: 'Enrichment runs asynchronously after capture, through the egress gateway.' });
      },
    },
    {
      method: 'GET', path: '/api/v1/targets/:id/lookalikes', auth: 'full',
      handler: async (ctx) => {
        const targetId = requireIntId(ctx.params.id);
        await assertTargetAccess(d.pool, ctx.user!, targetId);
        const t = (await d.pool.query<{ hostname_ascii: string }>('SELECT hostname_ascii FROM targets WHERE id = $1', [targetId])).rows[0]!;
        return { context: domainContext(t.hostname_ascii), matches: findLookalikes(t.hostname_ascii), note: 'Lookalike and brand matches are signals for review; legitimate affiliates, agents and research sites exist.' };
      },
    },
    {
      method: 'POST', path: '/api/v1/decisions', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const b = parseBody(z.object({
          target_id: z.number().int().positive(),
          decision: z.enum(['retain', 'investigate', 'false_positive', 'benign', 'inconclusive', 'recapture', 'escalate_for_approval', 'confirm_suspicious', 'likely_malicious', 'override_suppression']),
          reason_code: z.string().refine((c) => c in REASON_CODES, 'unknown reason code'),
          reason: z.string().trim().min(5).max(4000),
          evidence_refs: z.array(z.object({ kind: z.enum(['attempt', 'artifact', 'identifier', 'external']), id: z.string().max(200), note: z.string().max(500).optional() })).max(50).default([]),
          new_evidence_attempt: z.string().uuid().optional(),
          expected_last_decision_id: z.number().int().nonnegative().nullable(),
          case_id: z.string().uuid().optional(),
        }).strict(), ctx.body);
        await assertTargetAccess(d.pool, ctx.user!, b.target_id, 'investigator');
        if (b.decision === 'override_suppression' && !hasRole(ctx.user!, 'approver', 'admin')) throw forbidden('overriding a false-positive suppression requires the approver role');
        const verdict = DECISION_VERDICT[b.decision]!;
        return withTransaction(d.pool, async (client) => {
          // Serialise decisions per target and enforce the expected-version contract.
          await client.query('SELECT id FROM targets WHERE id = $1 FOR UPDATE', [b.target_id]);
          const last = (await client.query<{ id: number }>('SELECT id FROM analyst_decisions WHERE target_id = $1 ORDER BY id DESC LIMIT 1', [b.target_id])).rows[0]?.id ?? 0;
          if (last !== (b.expected_last_decision_id ?? 0)) throw conflict('version_conflict', 'another decision was recorded meanwhile; reload the target and decide again', { last_decision_id: last });
          if (b.decision === 'override_suppression') {
            const s = await suppressionState(client, b.target_id);
            if (!s.suppressed) throw conflict('not_suppressed', 'the target is not under a false-positive suppression');
            if (!b.new_evidence_attempt || !s.newer_attempts.includes(b.new_evidence_attempt)) {
              throw conflict('new_evidence_required', 'an override must cite an attempt captured after the false-positive decision', { eligible_attempts: s.newer_attempts });
            }
          }
          if (b.new_evidence_attempt) await assertAttemptAccess(client, ctx.user!, b.new_evidence_attempt);
          const risk = (await client.query<{ id: number }>('SELECT id FROM risk_assessments WHERE target_id = $1 ORDER BY id DESC LIMIT 1', [b.target_id])).rows[0];
          const ins = await client.query<{ id: number }>(
            `INSERT INTO analyst_decisions (target_id, case_id, decision, verdict, reason_code, reason, evidence_refs, risk_assessment_id, new_evidence_attempt, supersedes, actor, actor_id, request_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
            [b.target_id, b.case_id ?? null, b.decision, verdict, b.reason_code, b.reason, JSON.stringify(b.evidence_refs), risk?.id ?? null, b.new_evidence_attempt ?? null,
             last || null, ctx.user!.username, ctx.user!.id, ctx.requestId],
          );
          await auditCtx(client, ctx, 'analyst_decision_recorded', { decision: b.decision, verdict, reason_code: b.reason_code, supersedes: last || null }, { objectType: 'target', objectId: b.target_id, outcome: verdict });
          let recaptureJobId: number | null = null;
          if (b.decision === 'recapture') {
            const latest = (await client.query<{ id: number }>(`SELECT j.id FROM jobs j WHERE j.target_id = $1 AND j.parent_job_id IS NULL ORDER BY j.created_at DESC LIMIT 1`, [b.target_id])).rows[0];
            if (latest) {
              const r = await client.query<{ id: number }>(
                `INSERT INTO jobs (target_id, profile, window_key, registrable_domain, priority, urgent, required_artifacts, capture_variant, scope, allowed_interactions, retention_class, case_ref, stage)
                 SELECT target_id, profile, $2, registrable_domain, priority, false, required_artifacts, capture_variant, scope || jsonb_build_object('requeued_from_job', id, 'recapture_reason', 'analyst decision'),
                        allowed_interactions, retention_class, case_ref, CASE WHEN profile = 'data_triage' THEN 'http'::job_stage ELSE 'browser_primary'::job_stage END
                   FROM jobs WHERE id = $1 ON CONFLICT DO NOTHING RETURNING id`, [latest.id, `recapture:decision:${ins.rows[0]!.id}`],
              );
              recaptureJobId = r.rows[0]?.id ?? null;
              if (recaptureJobId) await client.query('INSERT INTO job_sources (job_id, source_record_id) SELECT $2, source_record_id FROM job_sources WHERE job_id = $1 ON CONFLICT DO NOTHING', [latest.id, recaptureJobId]);
            }
          }
          return reply(201, { decision_id: ins.rows[0]!.id, verdict, recapture_job_id: recaptureJobId });
        });
      },
    },
    {
      method: 'POST', path: '/api/v1/decisions/bulk', auth: 'full', roles: ['analyst', 'admin'],
      handler: async (ctx) => {
        // Bulk triage: per-target audit records; consequential bulk actions are not offered here.
        const b = parseBody(z.object({
          target_ids: z.array(z.number().int().positive()).min(1).max(200),
          decision: z.enum(['retain', 'investigate', 'inconclusive', 'recapture', 'false_positive', 'benign']),
          reason_code: z.string().refine((c) => c in REASON_CODES, 'unknown reason code'),
          reason: z.string().trim().min(5).max(4000),
          confirm: z.literal(true),
          preview: z.boolean().default(false),
        }).strict(), ctx.body);
        for (const t of b.target_ids) await assertTargetAccess(d.pool, ctx.user!, t, 'investigator');
        if (b.preview) return { would_record: b.target_ids.length, decision: b.decision, verdict: DECISION_VERDICT[b.decision] };
        const ids: number[] = [];
        await withTransaction(d.pool, async (client) => {
          for (const t of [...new Set(b.target_ids)].sort((x, y) => x - y)) {
            await client.query('SELECT id FROM targets WHERE id = $1 FOR UPDATE', [t]);
            const last = (await client.query<{ id: number }>('SELECT id FROM analyst_decisions WHERE target_id = $1 ORDER BY id DESC LIMIT 1', [t])).rows[0]?.id ?? null;
            const r = await client.query<{ id: number }>(
              `INSERT INTO analyst_decisions (target_id, decision, verdict, reason_code, reason, supersedes, actor, actor_id, request_id, evidence_refs)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'[{"kind":"external","id":"bulk-triage"}]') RETURNING id`,
              [t, b.decision, DECISION_VERDICT[b.decision], b.reason_code, b.reason, last, ctx.user!.username, ctx.user!.id, ctx.requestId],
            );
            ids.push(r.rows[0]!.id);
            await auditCtx(client, ctx, 'analyst_decision_recorded', { decision: b.decision, bulk: true, reason_code: b.reason_code }, { objectType: 'target', objectId: t, outcome: DECISION_VERDICT[b.decision] });
          }
        });
        return reply(201, { recorded: ids.length, decision_ids: ids });
      },
    },
    {
      method: 'GET', path: '/api/v1/review-queue', auth: 'full',
      handler: async (ctx) => {
        const limit = queryInt(ctx.url, 'limit', d.policy.web.paginated_list_limit_default, 1, d.policy.web.paginated_list_limit_max);
        const queue = ctx.url.searchParams.get('queue') ?? 'unreviewed';
        const filters: Record<string, string> = {
          unreviewed: `NOT EXISTS (SELECT 1 FROM analyst_decisions ad WHERE ad.target_id = j.target_id) AND j.state IN ('COMPLETE','PARTIAL','MANUAL_REVIEW')`,
          manual_review: `j.state = 'MANUAL_REVIEW'`,
          high_risk_unreviewed: `NOT EXISTS (SELECT 1 FROM analyst_decisions ad WHERE ad.target_id = j.target_id) AND EXISTS (SELECT 1 FROM risk_assessments r WHERE r.target_id = j.target_id AND r.band = 'high')`,
          escalated: `EXISTS (SELECT 1 FROM target_verdicts v WHERE v.target_id = j.target_id AND v.decision = 'escalate_for_approval')`,
          inconclusive: `EXISTS (SELECT 1 FROM target_verdicts v WHERE v.target_id = j.target_id AND v.verdict = 'inconclusive')`,
        };
        const f = filters[queue];
        if (!f) throw badRequest('invalid_queue', `queue must be one of ${Object.keys(filters).join(', ')}`);
        const { rows } = await d.pool.query<JobSummaryRow>(
          `${JOB_SUMMARY_SELECT} WHERE j.parent_job_id IS NULL AND ${jobVisibleSql('j', 1, 2)} AND ${f}
            ORDER BY j.urgent DESC, (SELECT max(score) FROM risk_assessments r WHERE r.target_id = j.target_id) DESC NULLS LAST, j.updated_at DESC LIMIT $3`,
          [ctx.user!.id, seesAllCases(ctx.user!), limit],
        );
        return { queue, items: rows.map((r) => presentJob(r, d.policy)) };
      },
    },
    {
      method: 'POST', path: '/api/v1/identifier-reviews', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const b = parseBody(z.object({
          target_id: z.number().int().positive(),
          field_type: z.string().regex(/^[a-z_]{2,40}$/),
          value_key: z.string().min(1).max(2000),
          state: z.enum(['unverified', 'candidate', 'corroborated', 'rejected']),
          corrected_value: z.string().max(2000).optional(),
          reason_code: z.enum(['ocr_error', 'format_invalid', 'not_displayed', 'third_party_resource', 'confirmed_by_second_source', 'confirmed_by_official_channel', 'duplicate', 'other']),
          reason: z.string().trim().min(5).max(2000),
          evidence_refs: z.array(z.object({ kind: z.string().max(40), id: z.string().max(200) })).max(20).default([]),
        }).strict(), ctx.body);
        await assertTargetAccess(d.pool, ctx.user!, b.target_id, 'investigator');
        const exists = await d.pool.query(`SELECT 1 FROM identifiers WHERE target_id = $1 AND field_type = $2 AND COALESCE(value_key, normalised_value, raw_value) = $3 LIMIT 1`, [b.target_id, b.field_type, b.value_key]);
        if (!exists.rowCount) throw badRequest('unknown_identifier', 'no such extracted value on this target');
        if (b.state === 'corroborated' && b.evidence_refs.length === 0) throw badRequest('evidence_required', 'corroboration must cite at least one evidence reference');
        const r = await d.pool.query<{ id: number }>(
          `INSERT INTO identifier_reviews (target_id, field_type, value_key, state, corrected_value, reason_code, reason, evidence_refs, actor, actor_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
          [b.target_id, b.field_type, b.value_key, b.state, b.corrected_value ?? null, b.reason_code, b.reason, JSON.stringify(b.evidence_refs), ctx.user!.username, ctx.user!.id],
        );
        await auditCtx(d.pool, ctx, 'identifier_review_recorded', { field_type: b.field_type, state: b.state, reason_code: b.reason_code, corrected: b.corrected_value !== undefined }, { objectType: 'target', objectId: b.target_id, outcome: b.state });
        return reply(201, { review_id: r.rows[0]!.id, note: 'Original evidence and extraction output are unchanged; this interpretation is recorded separately.' });
      },
    },
    {
      method: 'POST', path: '/api/v1/annotations', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const b = parseBody(z.object({
          object_type: z.enum(['target', 'attempt', 'artifact', 'identifier', 'case']),
          object_id: z.string().min(1).max(200),
          body: z.string().trim().min(1).max(10000),
          supersedes: z.number().int().positive().optional(),
        }).strict(), ctx.body);
        if (b.object_type === 'target') await assertTargetAccess(d.pool, ctx.user!, requireIntId(b.object_id), 'investigator');
        else if (b.object_type === 'attempt') await assertAttemptAccess(d.pool, ctx.user!, b.object_id, 'investigator');
        else if (b.object_type === 'case') {
          const { assertCaseAccess } = await import('../authz.js');
          await assertCaseAccess(d.pool, ctx.user!, b.object_id, 'investigator');
        } else if (b.object_type === 'artifact') {
          const a = (await d.pool.query<{ attempt_id: string }>('SELECT attempt_id FROM artifacts WHERE id = $1', [requireIntId(b.object_id)])).rows[0];
          if (!a) throw badRequest('unknown_object', 'artifact not found');
          await assertAttemptAccess(d.pool, ctx.user!, a.attempt_id, 'investigator');
        } else throw badRequest('unsupported_object', 'annotate identifiers through their target');
        const r = await d.pool.query<{ id: number }>(
          'INSERT INTO annotations (object_type, object_id, body, supersedes, actor, actor_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
          [b.object_type, b.object_id, b.body, b.supersedes ?? null, ctx.user!.username, ctx.user!.id],
        );
        await auditCtx(d.pool, ctx, 'annotation_added', { object_type: b.object_type, supersedes: b.supersedes ?? null }, { objectType: b.object_type, objectId: b.object_id });
        return reply(201, { annotation_id: r.rows[0]!.id });
      },
    },
    {
      method: 'GET', path: '/api/v1/entities', auth: 'full',
      handler: async (ctx) => {
        const type = ctx.url.searchParams.get('type');
        const value = ctx.url.searchParams.get('value')?.trim();
        const mode = ctx.url.searchParams.get('mode') ?? 'exact';
        const caseRef = ctx.url.searchParams.get('case_ref');
        if (!type || !/^[a-z_]{2,40}$/.test(type) || !value || value.length < 3 || value.length > 500) throw badRequest('invalid_query', 'type and value (3-500 characters) are required');
        if (mode !== 'exact' && mode !== 'contains') throw badRequest('invalid_query', 'mode must be exact or contains');
        // Sensitive search is case-scoped; a global (all my cases) search needs a recorded purpose.
        const purpose = ctx.req.headers['x-purpose'];
        if (!caseRef && d.policy.web.require_purpose_for_global_search && (typeof purpose !== 'string' || purpose.trim().length < 5)) {
          throw badRequest('purpose_required', 'searches across all your cases must state a purpose (X-Purpose header)');
        }
        if (caseRef) {
          const c = await caseByRef(d.pool, caseRef);
          if (!c) throw badRequest('unknown_case', 'case not found');
          const { assertCaseAccess } = await import('../authz.js');
          await assertCaseAccess(d.pool, ctx.user!, c.id);
        }
        const limit = queryInt(ctx.url, 'limit', 100, 1, 500);
        const normalised = type === 'email' || type === 'upi_vpa' ? value.toLowerCase() : value;
        const { rows } = await d.pool.query(
          `SELECT i.field_type, i.normalised_value, i.raw_value, i.method, i.validation_state, i.display_context, i.observed_at, i.attempt_id, i.job_id,
                  i.target_id, t.url, t.registrable_domain, i.source_artifact_id, i.bbox, i.locator, i.context,
                  (SELECT array_agg(DISTINCT l.case_ref) FROM job_case_links l WHERE l.job_id = i.job_id) AS case_refs
             FROM identifiers i JOIN jobs j ON j.id = i.job_id JOIN targets t ON t.id = i.target_id
            WHERE i.field_type = $3 AND ${jobVisibleSql('j', 1, 2)}
              AND (CASE WHEN $5 = 'exact' THEN COALESCE(i.value_key, i.normalised_value) = $4 OR i.normalised_value = $4 ELSE i.normalised_value ILIKE '%' || $4 || '%' END)
              AND ($6::text IS NULL OR EXISTS (SELECT 1 FROM job_case_links l WHERE l.job_id = j.id AND l.case_ref = $6))
            ORDER BY i.observed_at DESC NULLS LAST LIMIT $7`,
          [ctx.user!.id, seesAllCases(ctx.user!), type, normalised, mode, caseRef, limit],
        );
        await auditCtx(d.pool, ctx, 'protected_identifier_search', { type, mode, value_sha256: (await import('node:crypto')).createHash('sha256').update(normalised).digest('hex'), case_ref: caseRef, results: rows.length },
          { objectType: 'identifier_search', objectId: type, caseRef });
        const targets = new Set(rows.map((r) => r.target_id));
        return {
          type, mode, results: rows, distinct_targets: targets.size,
          note: 'A match shows where a value was observed in your scope. It does not establish that the same person controls these sites or owns the identifier.',
        };
      },
    },
  ];
}
