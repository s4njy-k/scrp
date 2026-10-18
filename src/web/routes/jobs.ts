/**
 * Intake, job queue views, live progress (SSE) and the provisional first
 * image (blueprint v4 §22.1 /intake /jobs, §22.2; checklist §10).
 */
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import type { Policy } from '../../config/policy.js';
import { withTransaction, type Queryable } from '../../db/pool.js';
import { importBuffer, IntakeError, type IntakeFormat } from '../../importer/importer.js';
import { assertSafeRelative } from '../../storage/artifactStore.js';
import { formatIst } from '../../evidence/time.js';
import { assertAttemptAccess, assertCaseAccess, assertJobAccess, jobCaseRefs, jobVisibleSql, seesAllCases } from '../authz.js';
import {
  badRequest, conflict, decodeCursor, encodeCursor, HttpError, notFound, queryInt, reply, requireIntId, requireUuid, type AuthedUser, type Ctx, type RouteSpec,
} from '../http.js';
import { acquisitionChip, liveStage } from '../status.js';
import { auditCtx, parseBody, type RouteDeps } from './common.js';

export const JOB_SUMMARY_SELECT = `
  SELECT j.id, j.target_id, t.url, t.hostname_unicode, j.registrable_domain, j.profile, j.capture_variant, j.state, j.stage, j.outcome,
         j.classification, j.outcome_reason, j.priority, j.urgent, j.http_attempts, j.browser_attempts, j.active_seconds_used, j.parent_job_id,
         j.created_at, j.updated_at, j.finished_at, j.next_eligible_at, j.retention_class,
         la.id AS latest_attempt_id, la.progress_stage, la.extraction_state, la.started_at AS latest_attempt_started_at,
         fi.id AS first_image_attempt_id, fi.first_image_at, fi.first_image_sha256, (fi.id IS NOT NULL AND fi.status = 'pending') AS first_image_provisional,
         tv.verdict, tv.decision AS last_decision,
         (SELECT array_agg(DISTINCT l.case_ref ORDER BY l.case_ref) FROM job_case_links l WHERE l.job_id = j.id) AS case_refs,
         (SELECT n.state FROM notice_targets nt JOIN notices n ON n.id = nt.notice_id WHERE nt.target_id = j.target_id ORDER BY n.created_at DESC LIMIT 1) AS action_state
    FROM jobs j JOIN targets t ON t.id = j.target_id
    LEFT JOIN LATERAL (SELECT a.id, a.progress_stage, a.extraction_state, a.started_at FROM attempts a WHERE a.job_id = j.id ORDER BY a.attempt_no DESC LIMIT 1) la ON true
    LEFT JOIN LATERAL (SELECT a.id, a.first_image_at, a.first_image_sha256, a.status FROM attempts a
                        WHERE a.job_id = j.id AND a.first_image_rel IS NOT NULL ORDER BY a.attempt_no DESC LIMIT 1) fi ON true
    LEFT JOIN target_verdicts tv ON tv.target_id = j.target_id`;

export interface JobSummaryRow {
  id: number; target_id: number; url: string; state: string; stage: string; outcome: string | null; classification: string | null;
  http_attempts: number; browser_attempts: number; active_seconds_used: number; progress_stage: string | null; extraction_state: string | null;
  first_image_attempt_id: string | null; first_image_at: Date | null; verdict: string | null; action_state: string | null; updated_at: Date;
  [k: string]: unknown;
}

export function presentJob(r: JobSummaryRow, policy: Policy): Record<string, unknown> {
  const l = policy.limits;
  return {
    ...r,
    acquisition: acquisitionChip(r),
    live_stage: liveStage({ state: r.state, progress_stage: r.progress_stage, extraction_state: r.extraction_state, has_first_image: Boolean(r.first_image_attempt_id) }),
    verdict: r.verdict ?? 'unreviewed',
    action: r.action_state ?? 'none',
    budget_remaining: {
      http_attempts: Math.max(0, l.http_attempts_max - r.http_attempts),
      browser_attempts: Math.max(0, l.browser_attempts_max - r.browser_attempts),
      seconds: Math.max(0, Math.round(l.active_acquisition_seconds_max - r.active_seconds_used)),
    },
    updated_at_ist: formatIst(r.updated_at),
  };
}

/** Batch-level defaults from query parameters; each record's own column overrides them. */
function batchDefaults(p: URLSearchParams): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const urgent = p.get('urgent');
  if (urgent === 'true' || urgent === 'false') out.urgent = urgent;
  const priority = p.get('priority');
  if (priority !== null && /^-?\d{1,4}$/.test(priority)) out.priority = priority;
  const variant = p.get('capture_variant');
  if (variant === 'desktop' || variant === 'mobile' || variant === 'both') out.capture_variant = variant;
  const retention = p.get('retention_class');
  if (retention && /^[a-z_]{2,40}$/.test(retention)) out.retention_class = retention;
  return out;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

const FORMAT_BY_TYPE: Record<string, IntakeFormat> = {
  'text/csv': 'csv',
  'application/csv': 'csv',
  'application/x-ndjson': 'jsonl',
  'application/jsonl': 'jsonl',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
  'text/plain': 'text',
};

/** In-process de-duplication of preview-view audit events (one per session and capture). */
const previewAudited = new Set<string>();

export async function listJobs(db: Queryable, user: AuthedUser, policy: Policy, url: URL, extraWhere: { caseRef?: string | null } = {}): Promise<{ items: Record<string, unknown>[]; next_cursor: string | null }> {
  const limit = queryInt(url, 'limit', policy.web.paginated_list_limit_default, 1, policy.web.paginated_list_limit_max);
  const cursor = decodeCursor(url.searchParams.get('cursor'));
  const params: unknown[] = [user.id, seesAllCases(user)];
  const where: string[] = [jobVisibleSql('j', 1, 2)];
  const add = (sql: (n: number) => string, v: unknown) => {
    params.push(v);
    where.push(sql(params.length));
  };
  const state = url.searchParams.get('state');
  if (state) add((n) => `j.state = ANY(string_to_array($${n}, ',')::processing_state[])`, state.toUpperCase());
  const outcome = url.searchParams.get('outcome');
  if (outcome) add((n) => `j.outcome = ANY(string_to_array($${n}, ',')::acquisition_outcome[])`, outcome.toUpperCase());
  const caseRef = extraWhere.caseRef ?? url.searchParams.get('case_ref');
  if (caseRef) add((n) => `EXISTS (SELECT 1 FROM job_case_links l WHERE l.job_id = j.id AND l.case_ref = $${n})`, caseRef);
  const q = url.searchParams.get('q')?.trim();
  if (q) add((n) => `(t.url ILIKE '%' || $${n} || '%' OR j.registrable_domain ILIKE '%' || $${n} || '%')`, q.slice(0, 200));
  if (url.searchParams.get('urgent') === 'true') where.push('j.urgent');
  const verdict = url.searchParams.get('verdict');
  if (verdict === 'unreviewed') where.push('NOT EXISTS (SELECT 1 FROM analyst_decisions d WHERE d.target_id = j.target_id)');
  else if (verdict) add((n) => `EXISTS (SELECT 1 FROM target_verdicts v WHERE v.target_id = j.target_id AND v.verdict = $${n})`, verdict);
  if (url.searchParams.get('top_level') === 'true') where.push('j.parent_job_id IS NULL');
  if (cursor && typeof cursor[0] === 'string' && typeof cursor[1] === 'number') {
    params.push(cursor[0], cursor[1]);
    where.push(`(j.updated_at, j.id) < ($${params.length - 1}::timestamptz, $${params.length}::bigint)`);
  }
  params.push(limit + 1);
  const { rows } = await db.query<JobSummaryRow>(`${JOB_SUMMARY_SELECT} WHERE ${where.join(' AND ')} ORDER BY j.updated_at DESC, j.id DESC LIMIT $${params.length}`, params);
  const page = rows.slice(0, limit);
  const last = page[page.length - 1];
  return { items: page.map((r) => presentJob(r, policy)), next_cursor: rows.length > limit && last ? encodeCursor([last.updated_at.toISOString(), last.id]) : null };
}

export function jobRoutes(d: RouteDeps): RouteSpec[] {
  const w = d.policy.web;
  let sseConnections = 0;

  return [
    {
      method: 'POST', path: '/api/v1/intake-batches', auth: 'full', roles: ['intake', 'admin'], body: 'raw', maxBodyBytes: Math.floor(w.intake_max_mib * 1024 * 1024),
      handler: async (ctx) => {
        const p = ctx.url.searchParams;
        const caseId = requireUuid(p.get('case_id') ?? undefined, 'case_id');
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, caseId, 'investigator');
        if (caseRow.status !== 'open') throw conflict('case_closed', 'the case is closed; reopen it before adding targets');
        const dryRun = p.get('dry_run') === 'true';
        const profile = p.get('profile') ?? 'browser_evidence';
        if (profile !== 'browser_evidence' && profile !== 'data_triage') throw badRequest('invalid_profile', 'profile must be browser_evidence or data_triage');
        const ct = String(ctx.req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
        const format = (p.get('format') as IntakeFormat | null) ?? FORMAT_BY_TYPE[ct];
        if (!format || !['csv', 'jsonl', 'xlsx', 'text'].includes(format)) throw badRequest('invalid_format', 'format must be csv, jsonl, xlsx or text (or send a matching Content-Type)');
        const idem = ctx.req.headers['idempotency-key'];
        if (!dryRun && (typeof idem !== 'string' || idem.length < 8 || idem.length > 200)) throw badRequest('idempotency_key_required', 'send an Idempotency-Key header (8-200 characters) so retries never create duplicate visits');
        const body = ctx.rawBody ?? Buffer.alloc(0);
        if (body.length === 0) throw badRequest('empty_intake', 'the intake body is empty');
        const bodySha = createHash('sha256').update(body).digest('hex');

        const replay = async () => {
          const prior = (await d.pool.query<{ batch_uuid: string; file_sha256: string; counts: Record<string, number> }>(
            'SELECT batch_uuid, file_sha256, counts FROM import_batches WHERE imported_by = $1 AND idempotency_key = $2', [ctx.user!.username, idem],
          )).rows[0];
          if (!prior) return null;
          if (prior.file_sha256 !== bodySha) throw conflict('idempotency_key_reused', 'this Idempotency-Key was already used for a different intake body');
          return reply(200, { batch_id: prior.batch_uuid, replayed: true, ...prior.counts });
        };
        if (!dryRun) {
          const r = await replay();
          if (r) return r;
        }
        const batchUuid = randomUUID();
        try {
          const s = await importBuffer(d.pool, d.policy, body, {
            defaultProfile: profile, windowKey: p.get('window') ?? today(), importedBy: ctx.user!.username, format,
            filename: (p.get('filename') ?? `intake.${format === 'text' ? 'txt' : format}`).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120),
            batchUuid, submittedByUserId: ctx.user!.id, idempotencyKey: dryRun ? null : (idem as string), caseId, caseRef: caseRow.case_ref,
            requestId: ctx.requestId, lawfulBasis: p.get('lawful_basis')?.slice(0, 500) ?? null, authorisationRef: p.get('authorisation_ref')?.slice(0, 200) ?? null,
            dryRun, maxRows: w.intake_max_rows, actorKind: 'user', recordDefaults: batchDefaults(p),
          });
          return reply(dryRun ? 200 : 202, {
            batch_id: dryRun ? null : batchUuid, dry_run: dryRun, lines: s.lines, accepted: s.accepted, rejected: s.rejected,
            duplicate: s.jobsMerged, jobs_created: s.jobsCreated, targets_created: s.targetsCreated, formula_cells_ignored: s.formulaCells ?? 0,
            line_results: (s.lineResults ?? []).slice(0, 1000),
            note: dryRun ? 'Preview only: nothing was queued.' : 'Accepted and durably queued. Capture runs asynchronously; follow progress on /jobs.',
          });
        } catch (err) {
          if (err instanceof IntakeError) throw badRequest(err.code, err.message);
          if ((err as { code?: string }).code === '23505' && !dryRun) {
            const r = await replay(); // a concurrent identical request won the race
            if (r) return r;
          }
          throw err;
        }
      },
    },
    {
      method: 'GET', path: '/api/v1/intake-batches/:id', auth: 'full',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const b = (await d.pool.query<{ id: number; case_id: string | null; counts: unknown; filename: string; format: string; created_at: Date; imported_by: string; lawful_basis: string | null; authorisation_ref: string | null }>(
          'SELECT id, case_id, counts, filename, format, created_at, imported_by, lawful_basis, authorisation_ref FROM import_batches WHERE batch_uuid = $1', [id],
        )).rows[0];
        if (!b || !b.case_id) throw notFound('intake batch not found');
        await assertCaseAccess(d.pool, ctx.user!, b.case_id);
        const lines = (await d.pool.query(
          `SELECT s.line_number AS line, s.original_input AS target, s.rejected, s.rejection_reason AS reason,
                  (SELECT array_agg(js.job_id) FROM job_sources js WHERE js.source_record_id = s.id) AS job_ids
             FROM source_records s WHERE s.import_batch_id = $1 ORDER BY s.line_number LIMIT 5000`, [b.id],
        )).rows;
        return { batch_id: id, ...b, id: undefined, lines };
      },
    },
    {
      method: 'GET', path: '/api/v1/jobs', auth: 'full',
      handler: async (ctx) => listJobs(d.pool, ctx.user!, d.policy, ctx.url),
    },
    {
      method: 'GET', path: '/api/v1/jobs/:id', auth: 'full',
      handler: async (ctx) => {
        const id = requireIntId(ctx.params.id);
        await assertJobAccess(d.pool, ctx.user!, id);
        const row = (await d.pool.query<JobSummaryRow>(`${JOB_SUMMARY_SELECT} WHERE j.id = $1`, [id])).rows[0]!;
        const attempts = (await d.pool.query(
          `SELECT id, attempt_no, kind, engine, adapter, capture_variant, vantage, status, outcome, classification, error, started_at, ended_at,
                  active_seconds, required_satisfied, missing_required, manifest_sha256, manifest_version, total_bytes, engine_version,
                  progress_stage, first_image_at, extraction_state, deleted_at
             FROM attempts WHERE job_id = $1 ORDER BY attempt_no`, [id],
        )).rows;
        const sources = (await d.pool.query(
          `SELECT s.id, s.original_input, s.source_ref, s.case_ref, s.priority, s.created_at, b.batch_uuid
             FROM job_sources js JOIN source_records s ON s.id = js.source_record_id JOIN import_batches b ON b.id = s.import_batch_id
            WHERE js.job_id = $1 ORDER BY s.id`, [id],
        )).rows;
        const caseRefs = await jobCaseRefs(d.pool, id);
        await auditCtx(d.pool, ctx, 'job_viewed', {}, { jobId: id, objectType: 'job', objectId: id, caseRef: caseRefs[0] ?? null });
        return { job: presentJob(row, d.policy), attempts, sources };
      },
    },
    {
      method: 'POST', path: '/api/v1/jobs/:id/control', auth: 'full', roles: ['analyst', 'admin'],
      handler: async (ctx) => {
        const id = requireIntId(ctx.params.id);
        await assertJobAccess(d.pool, ctx.user!, id, 'investigator');
        const b = parseBody(z.object({ action: z.enum(['pause', 'resume', 'cancel']), reason: z.string().trim().min(3).max(500), confirm: z.literal(true) }).strict(), ctx.body);
        const sql: Record<typeof b.action, string> = {
          // A paused job keeps its budget and history; it is simply not eligible until resumed.
          pause: `UPDATE jobs SET state = 'DEFERRED', next_eligible_at = 'infinity', outcome_reason = $2, updated_at = now() WHERE id = $1 AND state IN ('QUEUED','DEFERRED') RETURNING id`,
          resume: `UPDATE jobs SET state = 'QUEUED', next_eligible_at = now(), outcome_reason = $2, updated_at = now() WHERE id = $1 AND state = 'DEFERRED' AND next_eligible_at = 'infinity' RETURNING id`,
          cancel: `UPDATE jobs SET state = 'FAILED_FINAL', stage = 'done', outcome_reason = $2, finished_at = now(), updated_at = now() WHERE id = $1 AND state IN ('QUEUED','DEFERRED') RETURNING id`,
        };
        const reason = `${b.action === 'cancel' ? 'cancelled' : b.action === 'pause' ? 'paused' : 'resumed'} by ${ctx.user!.username}: ${b.reason}`;
        const r = await d.pool.query(sql[b.action], [id, reason]);
        if (!r.rowCount) throw conflict('invalid_state', `cannot ${b.action} this job in its current state (running jobs finish their attempt first)`);
        await auditCtx(d.pool, ctx, `job_${b.action}`, { reason: b.reason }, { jobId: id, objectType: 'job', objectId: id, outcome: 'ok' });
        return { ok: true };
      },
    },
    {
      method: 'POST', path: '/api/v1/jobs/:id/recapture', auth: 'full', roles: ['analyst', 'admin'],
      handler: async (ctx) => {
        const id = requireIntId(ctx.params.id);
        await assertJobAccess(d.pool, ctx.user!, id, 'investigator');
        const b = parseBody(z.object({ reason: z.string().trim().min(3).max(500), capture_variant: z.enum(['desktop', 'mobile']).optional(), urgent: z.boolean().default(false) }).strict(), ctx.body);
        const newId = await createRecaptureJob(d.pool, id, `recapture:${new Date().toISOString()}`, { variant: b.capture_variant ?? null, urgent: b.urgent, reason: b.reason, actor: ctx.user!.username });
        await auditCtx(d.pool, ctx, 'job_recapture_requested', { from_job: id, reason: b.reason, capture_variant: b.capture_variant ?? 'same' }, { jobId: newId, objectType: 'job', objectId: newId, outcome: 'ok' });
        return reply(202, { job_id: newId, note: 'A new job and attempt will be created; earlier evidence is unchanged.' });
      },
    },
    {
      method: 'GET', path: '/api/v1/jobs/events', auth: 'full',
      handler: async (ctx) => {
        if (sseConnections >= w.sse_max_connections) throw new HttpError(503, 'too_many_streams', 'too many live streams; use polling');
        sseConnections += 1;
        const res = ctx.res;
        res.writeHead(200, {
          ...securityHeadersFor(ctx),
          'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no',
        });
        res.write(`retry: ${Math.max(2000, w.sse_poll_ms * 2)}\n\n`);
        const last = String(ctx.req.headers['last-event-id'] ?? ctx.url.searchParams.get('since') ?? '');
        let since = /^\d{4}-\d{2}-\d{2}T/.test(last) ? last : new Date(Date.now() - 5000).toISOString();
        const caseRef = ctx.url.searchParams.get('case_ref');
        let closed = false;
        const started = Date.now();
        const close = () => {
          if (closed) return;
          closed = true;
          sseConnections -= 1;
          clearInterval(timer);
          clearInterval(ping);
          res.end();
        };
        ctx.req.on('close', close);
        const poll = async () => {
          if (closed) return;
          if (Date.now() - started > 30 * 60_000) return close(); // clients reconnect with Last-Event-ID
          try {
            const params: unknown[] = [ctx.user!.id, seesAllCases(ctx.user!), since];
            let extra = '';
            if (caseRef) {
              params.push(caseRef);
              extra = ` AND EXISTS (SELECT 1 FROM job_case_links l WHERE l.job_id = j.id AND l.case_ref = $4)`;
            }
            const { rows } = await d.pool.query<JobSummaryRow>(
              `${JOB_SUMMARY_SELECT} WHERE ${jobVisibleSql('j', 1, 2)} AND (j.updated_at > $3::timestamptz
                 OR EXISTS (SELECT 1 FROM attempts a WHERE a.job_id = j.id AND a.progress_at > $3::timestamptz))${extra}
               ORDER BY j.updated_at LIMIT 200`, params,
            );
            for (const r of rows) {
              const presented = presentJob(r, d.policy);
              res.write(`id: ${new Date().toISOString()}\nevent: job\ndata: ${JSON.stringify(presented)}\n\n`);
            }
            since = new Date(Date.now() - 1000).toISOString();
          } catch {
            res.write(`event: error\ndata: {"code":"temporarily_unavailable"}\n\n`);
          }
        };
        const timer = setInterval(() => void poll(), w.sse_poll_ms);
        const ping = setInterval(() => res.write(': keep-alive\n\n'), 15_000);
        await poll();
        return undefined;
      },
    },
    {
      method: 'GET', path: '/api/v1/attempts/:id/first-image', auth: 'full',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const { jobId } = await assertAttemptAccess(d.pool, ctx.user!, id);
        const a = (await d.pool.query<{ status: string; artifact_dir: string | null; first_image_rel: string | null; first_image_sha256: string | null; first_image_at: Date | null }>(
          'SELECT status, artifact_dir, first_image_rel, first_image_sha256, first_image_at FROM attempts WHERE id = $1', [id],
        )).rows[0]!;
        if (!a.first_image_rel || !a.first_image_sha256) throw notFound('no image yet');
        assertSafeRelative(a.first_image_rel);
        const candidates = [
          ...(a.artifact_dir ? [join(d.root, a.artifact_dir, a.first_image_rel)] : []),
          join(d.root, 'tmp', id, a.first_image_rel),
        ];
        let data: Buffer | null = null;
        for (const p of candidates) {
          data = await readFile(p).catch(() => null);
          if (data) break;
        }
        if (!data) throw notFound('image not available (moved during finalisation; retry)');
        // Serve only bytes that match the hash recorded when the image was saved.
        if (createHash('sha256').update(data).digest('hex') !== a.first_image_sha256) throw conflict('integrity_mismatch', 'stored image bytes do not match the recorded hash');
        if (data.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a') throw conflict('not_png', 'stored image is not a PNG');
        const key = `${ctx.user!.sessionId}:${id}`;
        if (!previewAudited.has(key)) {
          previewAudited.add(key);
          if (previewAudited.size > 20_000) previewAudited.clear();
          await auditCtx(d.pool, ctx, 'evidence_preview_viewed', { status: a.status === 'pending' ? 'provisional' : 'final' }, { jobId, attemptId: id, objectType: 'attempt', objectId: id });
        }
        return {
          status: 200, raw: data, contentType: 'image/png',
          headers: {
            'Content-Security-Policy': "default-src 'none'; sandbox", 'Cache-Control': 'private, no-store',
            'X-Evidence-Status': a.status === 'pending' ? 'provisional' : 'final', 'X-Evidence-SHA256': a.first_image_sha256,
            'Content-Disposition': `inline; filename="${id}-first-image.png"`,
          },
        };
      },
    },
  ];
}

function securityHeadersFor(ctx: Ctx): Record<string, string> {
  return { 'X-Request-Id': ctx.requestId, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'" };
}

/** A revisit or recapture is always a NEW job with a fresh, recorded budget; history is never rewritten. */
export async function createRecaptureJob(db: Parameters<typeof withTransaction>[0], fromJobId: number, windowKey: string,
  o: { variant: string | null; urgent: boolean; reason: string; actor: string; priority?: number; scopeExtra?: Record<string, unknown> }): Promise<number> {
  return withTransaction(db, async (client) => {
    const r = await client.query<{ id: number }>(
      `INSERT INTO jobs (target_id, profile, window_key, registrable_domain, priority, urgent, required_artifacts, capture_variant, scope,
          allowed_interactions, retention_class, case_ref, deadline, stage)
       SELECT target_id, profile, $2, registrable_domain, COALESCE($6, priority), $4, required_artifacts, COALESCE($3, capture_variant),
              scope || jsonb_build_object('requeued_from_job', id, 'recapture_reason', $5::text) || $7::jsonb, allowed_interactions, retention_class, case_ref, NULL,
              CASE WHEN profile = 'data_triage' THEN 'http'::job_stage ELSE 'browser_primary'::job_stage END
         FROM jobs WHERE id = $1
       ON CONFLICT (target_id, profile, capture_variant, window_key) WHERE parent_job_id IS NULL DO NOTHING RETURNING id`,
      [fromJobId, windowKey, o.variant, o.urgent, o.reason, o.priority ?? null, o.scopeExtra ?? {}],
    );
    if (!r.rows[0]) throw conflict('duplicate_window', 'a job for this target, profile and window already exists');
    await client.query('INSERT INTO job_sources (job_id, source_record_id) SELECT $2, source_record_id FROM job_sources WHERE job_id = $1 ON CONFLICT DO NOTHING', [fromJobId, r.rows[0].id]);
    return r.rows[0].id;
  });
}

