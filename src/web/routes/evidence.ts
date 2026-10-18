/**
 * Evidence access (blueprint v4 §22.1 /evidence/:captureId, §23.2, §27.1;
 * checklist §1, §7, §9): manifests with integrity status, hash-verified
 * artifact streaming with strict content handling, Verify Evidence, packages
 * and the scoped audit trail. Every evidence read is audited.
 */
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { createEvidencePackage } from '../../evidence/package.js';
import { runVerification } from '../../evidence/verify.js';
import { verifyChain } from '../../evidence/custody.js';
import { assertSafeRelative, sha256File } from '../../storage/artifactStore.js';
import { assertAttemptAccess, assertCaseAccess, assertJobAccess, hasRole, jobCaseRefs, seesAllCases } from '../authz.js';
import { badRequest, conflict, decodeCursor, encodeCursor, forbidden, notFound, queryInt, reply, requireIntId, requireUuid, type RouteSpec } from '../http.js';
import { auditCtx, parseBody, type RouteDeps } from './common.js';

/** Artifact types that may be displayed inline as plain text (never as HTML). */
const TEXT_INLINE = new Set(['rendered_text', 'console_log', 'network_events', 'action_log', 'attempt_metadata', 'http_response_record', 'derived_extraction']);
const PNG_MAGIC = '89504e470d0a1a0a';

interface ArtifactRow {
  id: number;
  attempt_id: string;
  artifact_type: string;
  relative_path: string | null;
  sha256: string | null;
  size_bytes: number | null;
  restricted: boolean;
  is_derivative: boolean;
  metadata: Record<string, unknown>;
  artifact_dir: string | null;
  job_id: number;
}

export function evidenceRoutes(d: RouteDeps): RouteSpec[] {
  return [
    {
      method: 'GET', path: '/api/v1/captures/:id/manifest', auth: 'full',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const { jobId } = await assertAttemptAccess(d.pool, ctx.user!, id);
        const a = (await d.pool.query<{ artifact_dir: string | null; manifest_sha256: string | null; status: string }>(
          'SELECT artifact_dir, manifest_sha256, status FROM attempts WHERE id = $1', [id],
        )).rows[0]!;
        if (!a.artifact_dir) throw notFound('this capture has no committed manifest yet');
        assertSafeRelative(a.artifact_dir);
        const etag = a.manifest_sha256 ? `"${a.manifest_sha256}"` : null;
        if (etag && ctx.req.headers['if-none-match'] === etag) return { status: 304, raw: Buffer.alloc(0), headers: { ETag: etag } };
        const text = await readFile(join(d.root, a.artifact_dir, 'manifest.json'), 'utf8').catch(() => null);
        if (text === null) throw conflict('manifest_missing', 'the manifest file is missing from the evidence store; run Verify Evidence');
        const actual = createHash('sha256').update(text).digest('hex');
        const manifest = JSON.parse(text) as { artifacts?: { restricted?: boolean; metadata?: unknown }[] };
        const ids = (await d.pool.query<{ id: number; relative_path: string | null; verification_state: string; last_verified_at: Date | null; is_derivative: boolean; artifact_type: string; sha256: string | null; metadata: Record<string, unknown> }>(
          'SELECT id, relative_path, verification_state, last_verified_at, is_derivative, artifact_type, sha256, metadata FROM artifacts WHERE attempt_id = $1 ORDER BY id', [id],
        )).rows;
        const caseRefs = await jobCaseRefs(d.pool, jobId);
        await auditCtx(d.pool, ctx, 'manifest_viewed', { integrity_ok: actual === a.manifest_sha256 }, { jobId, attemptId: id, objectType: 'attempt', objectId: id, caseRef: caseRefs[0] ?? null });
        return reply(200, {
          integrity: { ledger_sha256: a.manifest_sha256, actual_sha256: actual, matches: actual === a.manifest_sha256, checked_at: new Date().toISOString() },
          manifest,
          ledger_artifacts: ids,
          derivatives: ids.filter((r) => r.is_derivative),
        }, { ...(etag && actual === a.manifest_sha256 ? { ETag: etag, 'Cache-Control': 'private, max-age=0, must-revalidate' } : {}) });
      },
    },
    {
      method: 'GET', path: '/api/v1/artifacts/:id/content', auth: 'full',
      handler: async (ctx) => {
        const id = requireIntId(ctx.params.id);
        const art = (await d.pool.query<ArtifactRow>(
          `SELECT ar.id, ar.attempt_id, ar.artifact_type, ar.relative_path, ar.sha256, ar.size_bytes, ar.restricted, ar.is_derivative, ar.metadata,
                  a.artifact_dir, a.job_id
             FROM artifacts ar JOIN attempts a ON a.id = ar.attempt_id WHERE ar.id = $1`, [id],
        )).rows[0];
        if (!art) throw notFound('artifact not found');
        await assertJobAccess(d.pool, ctx.user!, art.job_id).catch(() => { throw notFound('artifact not found'); });
        if (!art.relative_path || !art.sha256) throw notFound('this artifact failed or was omitted; no file exists (see its manifest entry)');
        assertSafeRelative(art.relative_path);
        const isPng = art.relative_path.endsWith('.png');
        const wantsInline = ctx.url.searchParams.get('disposition') === 'inline';
        const purpose = ctx.req.headers['x-purpose'];
        // Restricted artifacts (cookies, tokens, HAR headers) need the evidence role and a stated purpose.
        if (art.restricted && (!hasRole(ctx.user!, 'evidence') || typeof purpose !== 'string' || purpose.trim().length < 5)) {
          throw forbidden('restricted artifact: requires the evidence role and an X-Purpose header', 'restricted_artifact');
        }
        // Screenshots may be viewed inline by analysts; every other download needs the evidence role.
        if (!(isPng && wantsInline) && !TEXT_INLINE.has(art.artifact_type) && !hasRole(ctx.user!, 'evidence', 'admin')) {
          throw forbidden('downloading original evidence requires the evidence role', 'evidence_role_required');
        }
        const abs = art.is_derivative && art.metadata?.root_relative === true ? join(d.root, art.relative_path)
          : art.artifact_dir ? join(d.root, art.artifact_dir, art.relative_path) : null;
        if (!abs) throw notFound('artifact file location unknown');
        const st = await stat(abs).catch(() => null);
        if (!st?.isFile()) throw conflict('artifact_missing', 'the artifact file is missing from the evidence store; run Verify Evidence');
        // Verify before serving: never hand out bytes that differ from the ledger.
        const { sha256 } = await sha256File(abs);
        const caseRefs = await jobCaseRefs(d.pool, art.job_id);
        if (sha256 !== art.sha256) {
          await d.pool.query(`UPDATE artifacts SET verification_state = 'mismatch', last_verified_at = now() WHERE id = $1`, [id]);
          await auditCtx(d.pool, ctx, 'artifact_integrity_mismatch_on_read', { expected: art.sha256, actual: sha256 }, { jobId: art.job_id, attemptId: art.attempt_id, objectType: 'artifact', objectId: id, caseRef: caseRefs[0] ?? null, outcome: 'refused' });
          throw conflict('integrity_mismatch', 'stored bytes do not match the recorded hash; the file was not served');
        }
        if (isPng) {
          const fh = await readFile(abs);
          if (fh.subarray(0, 8).toString('hex') !== PNG_MAGIC) throw conflict('not_png', 'stored file is not a PNG');
        }
        await auditCtx(d.pool, ctx, art.restricted ? 'restricted_artifact_downloaded' : 'artifact_downloaded', { type: art.artifact_type, sha256, inline: wantsInline && (isPng || TEXT_INLINE.has(art.artifact_type)) },
          { jobId: art.job_id, attemptId: art.attempt_id, objectType: 'artifact', objectId: id, caseRef: caseRefs[0] ?? null, outcome: 'served' });
        const inline = wantsInline && (isPng || TEXT_INLINE.has(art.artifact_type));
        const ext = art.relative_path.split('.').pop()!.replace(/[^a-z0-9]/g, '');
        const contentType = isPng ? 'image/png' : inline ? 'text/plain; charset=utf-8' : 'application/octet-stream';
        return {
          status: 200,
          raw: createReadStream(abs),
          contentType,
          headers: {
            'Content-Length': String(st.size),
            // Captured content never executes with the UI's privileges.
            'Content-Security-Policy': "default-src 'none'; sandbox",
            'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="artifact-${id}.${inline || isPng ? ext : `${ext}.bin`}"`,
            'Cache-Control': 'private, no-store',
            'X-Evidence-SHA256': sha256,
          },
        };
      },
    },
    {
      method: 'POST', path: '/api/v1/captures/:id/verify', auth: 'full', roles: ['analyst', 'evidence', 'admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const { jobId } = await assertAttemptAccess(d.pool, ctx.user!, id);
        const caseRefs = await jobCaseRefs(d.pool, jobId);
        const r = await runVerification(d.pool, d.root, 'attempt', id, ctx.user!.username, { actorKind: 'user', requestId: ctx.requestId, caseRef: caseRefs[0] ?? null });
        return { run_id: r.run_id, result: r.result, counts: r.counts, report_sha256: r.report_sha256, finished_at_ist: r.finished_at_ist, attempts: r.attempts, statement: r.statement };
      },
    },
    {
      method: 'POST', path: '/api/v1/cases/:id/verify', auth: 'full', roles: ['analyst', 'evidence', 'admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, id);
        const r = await runVerification(d.pool, d.root, 'case', caseRow.case_ref, ctx.user!.username, { actorKind: 'user', requestId: ctx.requestId, caseRef: caseRow.case_ref });
        return { run_id: r.run_id, result: r.result, counts: r.counts, report_sha256: r.report_sha256, finished_at_ist: r.finished_at_ist,
          failures: r.attempts.flatMap((a) => a.artifacts.filter((c) => c.status !== 'ok').map((c) => ({ attempt: a.attempt_id, path: c.path, status: c.status }))), statement: r.statement };
      },
    },
    {
      method: 'GET', path: '/api/v1/verification-runs/:id/report', auth: 'full',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const run = (await d.pool.query<{ scope: string; object_id: string; report_path: string | null; report_sha256: string | null }>(
          'SELECT scope, object_id, report_path, report_sha256 FROM verification_runs WHERE id = $1', [id],
        )).rows[0];
        if (!run?.report_path) throw notFound('report not found');
        if (run.scope === 'attempt') {
          for (const a of run.object_id.split(',')) await assertAttemptAccess(d.pool, ctx.user!, a).catch(() => { throw notFound('report not found'); });
        } else if (run.scope === 'job') await assertJobAccess(d.pool, ctx.user!, Number(run.object_id)).catch(() => { throw notFound('report not found'); });
        else if (run.scope === 'case') {
          const c = (await d.pool.query<{ id: string }>('SELECT id FROM cases WHERE case_ref = $1', [run.object_id])).rows[0];
          if (!c) throw notFound('report not found');
          await assertCaseAccess(d.pool, ctx.user!, c.id);
        } else if (!seesAllCases(ctx.user!)) throw notFound('report not found');
        assertSafeRelative(run.report_path);
        const data = await readFile(join(d.root, run.report_path));
        await auditCtx(d.pool, ctx, 'verification_report_downloaded', { run_id: id }, { objectType: 'verification_run', objectId: id });
        return { status: 200, raw: data, contentType: 'application/json', headers: { 'Content-Disposition': `attachment; filename="verification-${id}.json"`, 'X-Evidence-SHA256': run.report_sha256 ?? '' } };
      },
    },
    {
      method: 'POST', path: '/api/v1/packages', auth: 'full', roles: ['evidence', 'admin'],
      handler: async (ctx) => {
        const b = parseBody(z.object({
          case_id: z.string().uuid(),
          job_id: z.number().int().positive().optional(),
          attempt_ids: z.array(z.string().uuid()).min(1).max(200).optional(),
          purpose: z.string().trim().min(5).max(500),
          include_restricted: z.boolean().default(false),
        }).strict(), ctx.body);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, b.case_id, 'investigator');
        if (b.job_id) {
          await assertJobAccess(d.pool, ctx.user!, b.job_id);
          // The package is filed under this case, so its contents must belong to it: otherwise evidence
          // from another case could be relabelled and reach members of this case only.
          const linked = await d.pool.query('SELECT 1 FROM job_case_links WHERE job_id = $1 AND case_ref = $2', [b.job_id, caseRow.case_ref]);
          if (!linked.rowCount) throw badRequest('evidence_not_in_case', `job ${b.job_id} is not linked to case ${caseRow.case_ref}`);
        }
        for (const a of b.attempt_ids ?? []) {
          await assertAttemptAccess(d.pool, ctx.user!, a);
          const linked = await d.pool.query('SELECT 1 FROM attempts a JOIN job_case_links l ON l.job_id = a.job_id WHERE a.id = $1 AND l.case_ref = $2', [a, caseRow.case_ref]);
          if (!linked.rowCount) throw badRequest('evidence_not_in_case', `attempt ${a} is not linked to case ${caseRow.case_ref}`);
        }
        const kind = b.attempt_ids ? 'attempts' : b.job_id ? 'job' : 'case';
        const id = b.attempt_ids ? b.attempt_ids.join(',') : b.job_id ? String(b.job_id) : caseRow.case_ref;
        try {
          const p = await createEvidencePackage(d.pool, d.root, { kind, id, purpose: b.purpose, actor: ctx.user!.username, includeRestricted: b.include_restricted, actorKind: 'user', requestId: ctx.requestId, caseRef: caseRow.case_ref });
          return reply(201, p);
        } catch (err) {
          const m = (err as Error).message;
          if (/verification failed|no committed attempts|exceeds the/.test(m)) throw conflict('package_refused', m);
          throw err;
        }
      },
    },
    {
      method: 'GET', path: '/api/v1/packages/:id/archive', auth: 'full', roles: ['evidence', 'admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const p = (await d.pool.query<{ case_ref: string | null; scope: { archive?: string; archive_sha256?: string }; index_sha256: string }>(
          'SELECT case_ref, scope, index_sha256 FROM evidence_packages WHERE id = $1', [id],
        )).rows[0];
        if (!p?.scope.archive) throw notFound('package not found');
        const c = p.case_ref ? (await d.pool.query<{ id: string }>('SELECT id FROM cases WHERE case_ref = $1', [p.case_ref])).rows[0] : null;
        if (c) await assertCaseAccess(d.pool, ctx.user!, c.id);
        else if (!seesAllCases(ctx.user!)) throw notFound('package not found');
        assertSafeRelative(p.scope.archive);
        const abs = join(d.root, p.scope.archive);
        const { sha256 } = await sha256File(abs);
        if (p.scope.archive_sha256 && sha256 !== p.scope.archive_sha256) throw conflict('integrity_mismatch', 'package archive does not match its recorded hash');
        const st = await stat(abs);
        await auditCtx(d.pool, ctx, 'evidence_package_downloaded', { package_id: id, archive_sha256: sha256, index_sha256: p.index_sha256 }, { objectType: 'evidence_package', objectId: id, caseRef: p.case_ref, outcome: 'served' });
        return { status: 200, raw: createReadStream(abs), contentType: 'application/x-tar', headers: { 'Content-Length': String(st.size), 'Content-Disposition': `attachment; filename="evidence-package-${id}.tar"`, 'X-Evidence-SHA256': sha256, 'X-Package-Index-SHA256': p.index_sha256 } };
      },
    },
    {
      method: 'GET', path: '/api/v1/audit-events', auth: 'full',
      handler: async (ctx) => {
        const limit = queryInt(ctx.url, 'limit', 100, 1, 500);
        const cursor = decodeCursor(ctx.url.searchParams.get('cursor'));
        const objectType = ctx.url.searchParams.get('object_type');
        const objectId = ctx.url.searchParams.get('object_id');
        const caseId = ctx.url.searchParams.get('case_id');
        let caseRef: string | null = null;
        if (caseId) caseRef = (await assertCaseAccess(d.pool, ctx.user!, requireUuid(caseId, 'case_id'))).caseRow.case_ref;
        const global = hasRole(ctx.user!, 'auditor', 'admin');
        if (!global && !caseRef) throw forbidden('auditors may list all events; others must give case_id', 'case_scope_required');
        const params: unknown[] = [];
        const where: string[] = [];
        const add = (sql: (n: number) => string, v: unknown) => {
          params.push(v);
          where.push(sql(params.length));
        };
        if (caseRef) add((n) => `(e.case_ref = $${n} OR e.job_id IN (SELECT job_id FROM job_case_links WHERE case_ref = $${n}))`, caseRef);
        if (objectType) add((n) => `e.object_type = $${n}`, objectType);
        if (objectId) add((n) => `e.object_id = $${n}`, objectId);
        if (cursor && typeof cursor[0] === 'number') add((n) => `e.id < $${n}`, cursor[0]);
        params.push(limit + 1);
        const { rows } = await d.pool.query<{ id: number }>(
          `SELECT e.id, e.at, e.actor, e.actor_kind, e.event_type, e.job_id, e.attempt_id, e.case_ref, e.object_type, e.object_id, e.outcome, e.request_id,
                  e.details, e.chain_pos, e.event_hash
             FROM audit_events e ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY e.id DESC LIMIT $${params.length}`, params,
        );
        await auditCtx(d.pool, ctx, 'audit_log_viewed', { case_ref: caseRef, object_type: objectType, object_id: objectId }, { objectType: 'audit_log', objectId: caseRef ?? 'global', caseRef });
        const page = rows.slice(0, limit);
        return { items: page, next_cursor: rows.length > limit ? encodeCursor([page[page.length - 1]!.id]) : null };
      },
    },
    {
      method: 'GET', path: '/api/v1/custody/verify', auth: 'full', roles: ['auditor', 'admin'],
      handler: async (ctx) => {
        const r = await verifyChain(d.pool);
        await auditCtx(d.pool, ctx, 'custody_chain_verified', { ok: r.ok, sealed: r.sealed_events, unsealed: r.unsealed_events }, { objectType: 'custody_chain', objectId: r.head?.chain_pos ?? 0, outcome: r.ok ? 'pass' : 'fail' });
        return { ...r, statement: 'The chain is tamper-evident relative to externally held signed checkpoints; it is not WORM storage. Compare with an exported checkpoint using `cli.js custody verify --checkpoint <file>`.' };
      },
    },
    {
      method: 'GET', path: '/api/v1/captures/:id/artifacts', auth: 'full',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        await assertAttemptAccess(d.pool, ctx.user!, id);
        if (ctx.url.searchParams.has('type') && !/^[a-z_]{2,40}$/.test(ctx.url.searchParams.get('type')!)) throw badRequest('invalid_type', 'bad artifact type');
        return {
          items: (await d.pool.query(
            `SELECT id, artifact_type, relative_path, size_bytes, sha256, observed_start, observed_end, creation_method, completeness, limitations,
                    restricted, is_derivative, derived_from, error, metadata, verification_state, last_verified_at
               FROM artifacts WHERE attempt_id = $1 AND ($2::text IS NULL OR artifact_type = $2) ORDER BY id`, [id, ctx.url.searchParams.get('type')],
          )).rows,
        };
      },
    },
  ];
}
