/**
 * Legally routed actions, report drafts, Section 63 worksheets and uploads
 * (blueprint v4 §22.1 /reports, §24.3, §26; checklist §1, §6, §11).
 * Nothing here dispatches anything. Every transition is attributed, audited and
 * recorded in an append-only event table; approval is maker-checker.
 */
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { withTransaction, type Queryable } from '../../db/pool.js';
import { blockingFailures, checkEligibility, LEGAL_ROUTES, SECTION_69A_GROUNDS, type RouteId } from '../../actions/legalRoutes.js';
import { approvalSnapshot, renderReport, snapshotText, type ReportTarget } from '../../actions/report.js';
import {
  applyWorksheetEdits, buildFactSheet, fieldsFor, initialWorksheet, SCHEDULE_SOURCE, SCHEDULE_TEMPLATE_ID, worksheetGaps, type WorksheetValue,
} from '../../actions/certificate.js';
import { createEvidencePackage } from '../../evidence/package.js';
import { runVerification } from '../../evidence/verify.js';
import { formatIst } from '../../evidence/time.js';
import { suppressionState } from '../../investigation/decisions.js';
import { assertSafeRelative, sha256File } from '../../storage/artifactStore.js';
import { assertAttemptAccess, assertCaseAccess, hasRole, seesAllCases } from '../authz.js';
import { badRequest, conflict, forbidden, notFound, reply, requireUuid, type AuthedUser, type Ctx, type RouteSpec } from '../http.js';
import { auditCtx, expectedVersion, parseBody, type RouteDeps } from './common.js';

const ROUTE_IDS = Object.keys(LEGAL_ROUTES) as [RouteId, ...RouteId[]];
const RECIPIENT = z.object({
  name: z.string().trim().min(1).max(300),
  kind: z.enum(['government_nodal', 'intermediary', 'registrar', 'registry', 'hosting_provider', 'cdn', 'app_distributor', 'record_holder', 'bank_or_psp', 'investigating_officer']),
  contact: z.string().trim().max(300).optional(),
  jurisdiction: z.string().trim().max(200).optional(),
}).strict();
const TEXT = (max: number) => z.string().trim().max(max).optional();
const NOTICE_FIELDS = {
  reference_no: TEXT(120), language: z.enum(['en', 'hi', 'en_hi']).optional(), legal_basis: TEXT(5000), authority_ref: TEXT(500), issuing_authority: TEXT(300),
  signatory_name: TEXT(200), signatory_designation: TEXT(200), jurisdiction: TEXT(300), facts_summary: TEXT(10000), requested_action: TEXT(3000),
  necessity_note: TEXT(3000), proportionality_note: TEXT(3000), lawful_deadline: TEXT(300), internal_followup_at: z.string().datetime({ offset: true }).optional(),
  route_fields: z.record(z.string().regex(/^[a-z0-9_]{2,60}$/), z.union([z.string().max(5000), z.boolean(), z.number(), z.array(z.string().max(500)).max(50)])).optional(),
};
const TARGETS = z.array(z.object({
  target_id: z.number().int().positive(),
  evidence_attempt_ids: z.array(z.string().uuid()).max(10).optional(),
  legal_ground: z.string().trim().max(1000).optional(),
}).strict()).min(1).max(200);

interface NoticeRow {
  id: string; case_id: string; route: RouteId; state: string; reference_no: string | null; language: 'en' | 'hi' | 'en_hi'; recipient: Record<string, string>;
  legal_basis: string | null; authority_ref: string | null; issuing_authority: string | null; signatory_name: string | null; signatory_designation: string | null;
  jurisdiction: string | null; facts_summary: string | null; requested_action: string | null; necessity_note: string | null; proportionality_note: string | null;
  lawful_deadline: string | null; internal_followup_at: Date | null; route_fields: Record<string, unknown>; created_by: string; created_by_id: string | null;
  approved_by: string | null; approved_by_id: string | null; approved_at: Date | null; approved_snapshot_sha256: string | null; version: number;
  generated_package_id: string | null; report_path: string | null; report_sha256: string | null; issued_at: Date | null; received_at: Date | null;
}

async function noticeTargets(db: Queryable, noticeId: string) {
  const rows = (await db.query<{ target_id: number; url: string; registrable_domain: string; evidence_attempt_ids: string[]; legal_ground: string | null; target_status: string; verdict: string | null; has_app_link: boolean }>(
    `SELECT nt.target_id, t.url, t.registrable_domain, nt.evidence_attempt_ids, nt.legal_ground, nt.target_status, v.verdict,
            EXISTS (SELECT 1 FROM identifiers i WHERE i.target_id = t.id AND i.field_type IN ('app_store_link', 'apk_link')) AS has_app_link
       FROM notice_targets nt JOIN targets t ON t.id = nt.target_id LEFT JOIN target_verdicts v ON v.target_id = t.id
      WHERE nt.notice_id = $1 ORDER BY nt.target_id`, [noticeId],
  )).rows;
  const out = [];
  for (const r of rows) {
    const s = await suppressionState(db, r.target_id);
    const ev = (await db.query<{ ok: boolean }>(
      `SELECT bool_and(a.status IN ('committed', 'recovered') AND a.artifact_dir IS NOT NULL AND a.deleted_at IS NULL
                       AND NOT EXISTS (SELECT 1 FROM artifacts ar WHERE ar.attempt_id = a.id AND ar.verification_state IN ('mismatch', 'missing'))) AS ok
         FROM attempts a WHERE a.id = ANY($1::uuid[])`, [r.evidence_attempt_ids],
    )).rows[0];
    out.push({ ...r, suppressed: s.suppressed, evidence_attempts: r.evidence_attempt_ids, evidence_ok: Boolean(ev?.ok) && r.evidence_attempt_ids.length > 0 });
  }
  return out;
}

async function eligibility(db: Queryable, n: NoticeRow, actor: AuthedUser | null, stage: 'submit' | 'approve' | 'generate') {
  const targets = await noticeTargets(db, n.id);
  return checkEligibility({
    route: n.route, fields: n as unknown as Record<string, unknown>, routeFields: n.route_fields, recipientKind: n.recipient?.kind ?? null,
    targets: targets.map((t) => ({ target_id: t.target_id, url: t.url, verdict: t.verdict, suppressed: t.suppressed, evidence_attempts: t.evidence_attempts, evidence_ok: t.evidence_ok, has_app_link: t.has_app_link })),
    creatorId: n.created_by_id, actorId: actor?.id ?? null, stage,
  });
}

async function reportTargets(db: Queryable, root: string, noticeId: string): Promise<ReportTarget[]> {
  const out: ReportTarget[] = [];
  for (const t of await noticeTargets(db, noticeId)) {
    const evidence: ReportTarget['evidence'] = [];
    for (const aid of t.evidence_attempts) {
      const a = (await db.query<{ id: string; started_at: Date; outcome: string | null; manifest_sha256: string | null; artifact_dir: string | null; vantage: string }>(
        'SELECT id, started_at, outcome, manifest_sha256, artifact_dir, vantage FROM attempts WHERE id = $1', [aid],
      )).rows[0];
      if (!a) continue;
      let finalUrl: string | null = null;
      if (a.artifact_dir) {
        try {
          assertSafeRelative(a.artifact_dir);
          finalUrl = (JSON.parse(await readFile(join(root, a.artifact_dir, 'manifest.json'), 'utf8')) as { finalUrl: string | null }).finalUrl;
        } catch { finalUrl = null; }
      }
      const shot = (await db.query<{ sha256: string }>(`SELECT sha256 FROM artifacts WHERE attempt_id = $1 AND artifact_type IN ('screenshot_settled', 'screenshot_early') AND sha256 IS NOT NULL ORDER BY artifact_type DESC LIMIT 1`, [aid])).rows[0];
      evidence.push({ attempt_id: a.id, observed_at_utc: a.started_at.toISOString(), outcome: a.outcome, final_url: finalUrl, manifest_sha256: a.manifest_sha256, screenshot_sha256: shot?.sha256 ?? null, vantage: a.vantage });
    }
    const ids = (await db.query<{ field_type: string; value: string; method: string }>(
      `SELECT DISTINCT field_type, COALESCE(value_key, normalised_value) AS value, method FROM identifiers
        WHERE attempt_id = ANY($1::uuid[]) AND NOT signal_only AND validation_state <> 'format_invalid' AND display_context <> 'resource_string'
          AND field_type IN ('upi_vpa','upi_uri','phone','whatsapp','telegram','email','bank_account','ifsc','crypto_btc','crypto_eth','crypto_tron','app_store_link','apk_link')
        ORDER BY field_type LIMIT 30`, [t.evidence_attempts],
    )).rows;
    out.push({ url: t.url, registrable_domain: t.registrable_domain, legal_ground: t.legal_ground, evidence, identifiers: ids });
  }
  return out;
}

function reportInputFrom(n: NoticeRow, caseRef: string, targets: ReportTarget[], pkg: { id: string; index_sha256: string } | null, generatedAt: string) {
  return {
    notice: {
      id: n.id, route: n.route, reference_no: n.reference_no, language: n.language, recipient: n.recipient, legal_basis: n.legal_basis, authority_ref: n.authority_ref,
      issuing_authority: n.issuing_authority, signatory_name: n.signatory_name, signatory_designation: n.signatory_designation, jurisdiction: n.jurisdiction,
      facts_summary: n.facts_summary, requested_action: n.requested_action, lawful_deadline: n.lawful_deadline, route_fields: n.route_fields,
      approved_by: n.approved_by, approved_at: n.approved_at?.toISOString() ?? null, created_by: n.created_by,
    },
    caseRef, targets, generatedAt, evidencePackage: pkg,
    // Identifiers are masked unless the recipient is an investigating officer or a competent authority channel.
    maskIdentifiers: !['investigating_officer', 'government_nodal'].includes(n.recipient?.kind ?? ''),
  };
}

const TRANSITIONS: Record<string, { from: string[]; to: string | null; roles: ('analyst' | 'approver' | 'report' | 'admin' | 'evidence')[]; notCreator?: boolean; eligible?: 'submit' | 'approve' }> = {
  submit: { from: ['draft'], to: 'analyst_review', roles: ['analyst', 'approver', 'admin'], eligible: 'submit' },
  review_ok: { from: ['analyst_review'], to: 'legal_check', roles: ['analyst', 'approver', 'admin'], notCreator: true, eligible: 'submit' },
  return_to_draft: { from: ['analyst_review', 'legal_check', 'approved'], to: 'draft', roles: ['analyst', 'approver', 'admin'] },
  approve: { from: ['legal_check'], to: 'approved', roles: ['approver'], notCreator: true, eligible: 'approve' },
  generate: { from: ['approved'], to: 'generated', roles: ['approver', 'report'] },
  record_issued: { from: ['generated'], to: 'issued', roles: ['approver', 'report'] },
  record_acknowledged: { from: ['issued'], to: 'acknowledged', roles: ['approver', 'report', 'analyst'] },
  record_outcome: { from: ['issued', 'acknowledged'], to: null, roles: ['approver', 'report', 'analyst'] },
  close: { from: ['complied', 'partially_complied', 'rejected', 'no_response'], to: null, roles: ['approver', 'admin'] },
  withdraw: { from: ['draft', 'analyst_review', 'legal_check', 'approved', 'generated'], to: 'withdrawn', roles: ['analyst', 'approver', 'admin'] },
  dispute: { from: ['issued', 'acknowledged', 'complied', 'partially_complied'], to: 'disputed', roles: ['approver', 'admin'] },
};

const UPLOAD_TYPES: Record<string, { ext: string; magic: (b: Buffer) => boolean }> = {
  'application/pdf': { ext: 'pdf', magic: (b) => b.subarray(0, 5).toString('latin1') === '%PDF-' },
  'image/png': { ext: 'png', magic: (b) => b.subarray(0, 8).toString('hex') === '89504e470d0a1a0a' },
  'image/jpeg': { ext: 'jpg', magic: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  'text/plain': { ext: 'txt', magic: (b) => { try { new TextDecoder('utf-8', { fatal: true }).decode(b); return true; } catch { return false; } } },
};

export function actionRoutes(d: RouteDeps): RouteSpec[] {
  const loadNotice = async (ctx: Ctx, id: string, min: 'viewer' | 'investigator' = 'viewer') => {
    const n = (await d.pool.query<NoticeRow>('SELECT * FROM notices WHERE id = $1', [id])).rows[0];
    if (!n) throw notFound('notice not found');
    const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, n.case_id, min).catch(() => { throw notFound('notice not found'); });
    return { n, caseRow };
  };
  const event = async (db: Queryable, ctx: Ctx, n: { id: string; case_id: string }, caseRef: string, from: string | null, to: string, note: string | null, details: Record<string, unknown> = {}) => {
    await db.query('INSERT INTO notice_events (notice_id, from_state, to_state, actor, actor_id, note, details) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [n.id, from, to, ctx.user!.username, ctx.user!.id, note, details]);
    await auditCtx(db, ctx, 'notice_transition', { from, to, note, ...details }, { objectType: 'notice', objectId: n.id, caseRef, outcome: to });
  };
  const setTargets = async (db: Queryable, ctx: Ctx, noticeId: string, caseRef: string, targets: z.infer<typeof TARGETS>) => {
    await db.query('DELETE FROM notice_targets WHERE notice_id = $1', [noticeId]);
    for (const t of targets) {
      // The target must belong to this case; evidence must be a committed capture of that target.
      const linked = await db.query(`SELECT 1 FROM jobs j JOIN job_case_links l ON l.job_id = j.id WHERE j.target_id = $1 AND l.case_ref = $2 LIMIT 1`, [t.target_id, caseRef]);
      if (!linked.rowCount) throw badRequest('target_not_in_case', `target ${t.target_id} is not linked to case ${caseRef}`);
      let attempts = t.evidence_attempt_ids ?? [];
      if (attempts.length === 0) {
        attempts = (await db.query<{ id: string }>(
          `SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE j.target_id = $1 AND a.status IN ('committed', 'recovered') AND a.artifact_dir IS NOT NULL
             AND a.kind = 'browser' ORDER BY a.started_at DESC LIMIT 1`, [t.target_id],
        )).rows.map((r) => r.id);
      }
      for (const a of attempts) {
        const ok = await db.query('SELECT 1 FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE a.id = $1 AND j.target_id = $2', [a, t.target_id]);
        if (!ok.rowCount) throw badRequest('evidence_not_for_target', `attempt ${a} is not a capture of target ${t.target_id}`);
        await assertAttemptAccess(db, ctx.user!, a);
      }
      await db.query('INSERT INTO notice_targets (notice_id, target_id, evidence_attempt_ids, legal_ground) VALUES ($1,$2,$3,$4)', [noticeId, t.target_id, attempts, t.legal_ground ?? null]);
    }
  };

  return [
    {
      method: 'GET', path: '/api/v1/legal-routes', auth: 'full',
      handler: async () => ({
        routes: Object.values(LEGAL_ROUTES), section_69a_grounds: SECTION_69A_GROUNDS,
        disclaimer: 'Engineering guardrails, not legal advice. Verify the statute, rules, authority and channel in force at issuance with competent legal reviewers.',
      }),
    },
    {
      method: 'POST', path: '/api/v1/notices', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const b = parseBody(z.object({ case_id: z.string().uuid(), route: z.enum(ROUTE_IDS), recipient: RECIPIENT, targets: TARGETS, ...NOTICE_FIELDS }).strict(), ctx.body);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, b.case_id, 'investigator');
        if (caseRow.status !== 'open') throw conflict('case_closed', 'the case is closed');
        const id = randomUUID();
        await withTransaction(d.pool, async (client) => {
          await client.query(
            `INSERT INTO notices (id, case_id, route, reference_no, language, recipient, legal_basis, authority_ref, issuing_authority, signatory_name, signatory_designation,
                jurisdiction, facts_summary, requested_action, necessity_note, proportionality_note, lawful_deadline, internal_followup_at, route_fields, created_by, created_by_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
            [id, b.case_id, b.route, b.reference_no ?? null, b.language ?? 'en', b.recipient, b.legal_basis ?? null, b.authority_ref ?? null, b.issuing_authority ?? null,
             b.signatory_name ?? null, b.signatory_designation ?? null, b.jurisdiction ?? null, b.facts_summary ?? null, b.requested_action ?? null, b.necessity_note ?? null,
             b.proportionality_note ?? null, b.lawful_deadline ?? null, b.internal_followup_at ?? null, b.route_fields ?? {}, ctx.user!.username, ctx.user!.id],
          );
          await setTargets(client, ctx, id, caseRow.case_ref, b.targets);
          await event(client, ctx, { id, case_id: b.case_id }, caseRow.case_ref, null, 'draft', 'draft created', { route: b.route, targets: b.targets.length });
        });
        return reply(201, { id, state: 'draft' });
      },
    },
    {
      method: 'GET', path: '/api/v1/notices', auth: 'full',
      handler: async (ctx) => {
        const caseId = ctx.url.searchParams.get('case_id');
        const state = ctx.url.searchParams.get('state');
        const params: unknown[] = [ctx.user!.id, seesAllCases(ctx.user!)];
        let extra = '';
        if (caseId) { params.push(requireUuid(caseId, 'case_id')); extra += ` AND n.case_id = $${params.length}`; }
        if (state) { params.push(state); extra += ` AND n.state = $${params.length}`; }
        const { rows } = await d.pool.query(
          `SELECT n.id, n.case_id, c.case_ref, n.route, n.state, n.reference_no, n.recipient, n.created_by, n.created_at, n.approved_by, n.approved_at,
                  n.issued_at, n.received_at, n.internal_followup_at, (SELECT count(*)::int FROM notice_targets nt WHERE nt.notice_id = n.id) AS target_count
             FROM notices n JOIN cases c ON c.id = n.case_id
            WHERE ($2::boolean OR EXISTS (SELECT 1 FROM case_members m WHERE m.case_id = n.case_id AND m.user_id = $1))${extra}
            ORDER BY n.created_at DESC LIMIT 200`, params,
        );
        return { items: rows.map((r) => ({ ...r, internal_followup_note: 'internal follow-up target, not a legal deadline' })) };
      },
    },
    {
      method: 'GET', path: '/api/v1/notices/:id', auth: 'full',
      handler: async (ctx) => {
        const { n, caseRow } = await loadNotice(ctx, requireUuid(ctx.params.id));
        const targets = await noticeTargets(d.pool, n.id);
        const events = (await d.pool.query('SELECT from_state, to_state, actor, note, details, at FROM notice_events WHERE notice_id = $1 ORDER BY id', [n.id])).rows;
        const reports = (await d.pool.query('SELECT id, snapshot_sha256, files, index_sha256, evidence_package_id, generated_by, generated_at FROM notice_reports WHERE notice_id = $1 ORDER BY generated_at DESC', [n.id])).rows;
        const checks = await eligibility(d.pool, n, ctx.user, n.state === 'legal_check' ? 'approve' : 'submit');
        return { notice: n, case_ref: caseRow.case_ref, route: LEGAL_ROUTES[n.route], targets, events, reports, eligibility: checks, blocking: blockingFailures(checks), transitions: Object.entries(TRANSITIONS).filter(([, t]) => t.from.includes(n.state)).map(([k]) => k) };
      },
    },
    {
      method: 'PATCH', path: '/api/v1/notices/:id', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const { n, caseRow } = await loadNotice(ctx, requireUuid(ctx.params.id), 'investigator');
        const b = parseBody(z.object({ expected_version: z.number().int().positive().optional(), recipient: RECIPIENT.optional(), targets: TARGETS.optional(), ...NOTICE_FIELDS }).strict(), ctx.body);
        if (n.state !== 'draft') throw conflict('not_editable', 'only drafts can be edited; return the notice to draft first (this records who and why)');
        const version = expectedVersion(ctx, b);
        if (version === null) throw conflict('version_required', 'send expected_version');
        await withTransaction(d.pool, async (client) => {
          const cols = ['reference_no', 'language', 'legal_basis', 'authority_ref', 'issuing_authority', 'signatory_name', 'signatory_designation', 'jurisdiction', 'facts_summary',
            'requested_action', 'necessity_note', 'proportionality_note', 'lawful_deadline', 'internal_followup_at', 'route_fields', 'recipient'] as const;
          const sets: string[] = [];
          const params: unknown[] = [n.id, version];
          for (const c of cols) {
            if ((b as Record<string, unknown>)[c] !== undefined) { params.push((b as Record<string, unknown>)[c]); sets.push(`${c} = $${params.length}`); }
          }
          const r = await client.query(`UPDATE notices SET ${[...sets, 'version = version + 1'].join(', ')} WHERE id = $1 AND version = $2 AND state = 'draft'`, params);
          if (!r.rowCount) throw conflict('version_conflict', 'the notice changed meanwhile; reload');
          if (b.targets) await setTargets(client, ctx, n.id, caseRow.case_ref, b.targets);
          await auditCtx(client, ctx, 'notice_edited', { fields: cols.filter((c) => (b as Record<string, unknown>)[c] !== undefined), targets_replaced: Boolean(b.targets) }, { objectType: 'notice', objectId: n.id, caseRef: caseRow.case_ref });
        });
        return { version: version + 1 };
      },
    },
    {
      method: 'POST', path: '/api/v1/notices/:id/transition', auth: 'full', roles: ['analyst', 'approver', 'report', 'admin'],
      handler: async (ctx) => transition(ctx, requireUuid(ctx.params.id)),
    },
    {
      // Spec path (blueprint v4 §23.2): checker approval.
      method: 'POST', path: '/api/v1/actions/:id/approve', auth: 'full', roles: ['approver'],
      handler: async (ctx) => {
        ctx.body = { ...(ctx.body as object), action: 'approve' };
        return transition(ctx, requireUuid(ctx.params.id));
      },
    },
    {
      method: 'POST', path: '/api/v1/reports/:type/preview', auth: 'full', roles: ['analyst', 'approver', 'report', 'admin'],
      handler: async (ctx) => {
        if (ctx.params.type !== 'notice') throw badRequest('unknown_report_type', 'report type must be notice');
        const b = parseBody(z.object({ notice_id: z.string().uuid(), format: z.enum(['markdown', 'html', 'json']).default('markdown') }).strict(), ctx.body);
        const { n, caseRow } = await loadNotice(ctx, b.notice_id);
        const r = renderReport(reportInputFrom(n, caseRow.case_ref, await reportTargets(d.pool, d.root, n.id), null, new Date().toISOString()));
        await auditCtx(d.pool, ctx, 'notice_previewed', { format: b.format }, { objectType: 'notice', objectId: n.id, caseRef: caseRow.case_ref });
        return { preview_only: true, dispatch: 'none', format: b.format, content: b.format === 'json' ? r.json : b.format === 'html' ? r.html : r.markdown, eligibility: await eligibility(d.pool, n, ctx.user, 'submit') };
      },
    },
    {
      method: 'POST', path: '/api/v1/reports/:id/generate', auth: 'full', roles: ['approver', 'report'],
      handler: async (ctx) => {
        ctx.body = { action: 'generate' };
        return transition(ctx, requireUuid(ctx.params.id));
      },
    },
    {
      method: 'GET', path: '/api/v1/notices/:id/reports/:reportId/:file', auth: 'full',
      handler: async (ctx) => {
        const { n, caseRow } = await loadNotice(ctx, requireUuid(ctx.params.id));
        const rep = (await d.pool.query<{ relative_dir: string; files: { path: string; sha256: string }[] }>('SELECT relative_dir, files FROM notice_reports WHERE id = $1 AND notice_id = $2', [requireUuid(ctx.params.reportId, 'reportId'), n.id])).rows[0];
        if (!rep) throw notFound('report not found');
        const f = rep.files.find((x) => x.path === ctx.params.file);
        if (!f) throw notFound('file not found');
        assertSafeRelative(`${rep.relative_dir}/${f.path}`);
        const abs = join(d.root, rep.relative_dir, f.path);
        if ((await sha256File(abs)).sha256 !== f.sha256) throw conflict('integrity_mismatch', 'report file does not match its recorded hash');
        await auditCtx(d.pool, ctx, 'notice_report_downloaded', { file: f.path }, { objectType: 'notice', objectId: n.id, caseRef: caseRow.case_ref });
        return { status: 200, raw: await readFile(abs), contentType: 'application/octet-stream', headers: { 'Content-Disposition': `attachment; filename="notice-${n.id}-${f.path}"`, 'X-Evidence-SHA256': f.sha256, 'Content-Security-Policy': "default-src 'none'; sandbox" } };
      },
    },

    // ---- Uploads (signed certificates, dispatch and receipt proofs) ----
    {
      method: 'POST', path: '/api/v1/cases/:id/uploads', auth: 'full', roles: ['analyst', 'approver', 'evidence', 'report', 'admin'], body: 'raw', maxBodyBytes: Math.floor(d.policy.web.upload_max_mib * 1024 * 1024),
      handler: async (ctx) => {
        const caseId = requireUuid(ctx.params.id);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, caseId, 'investigator');
        const purpose = ctx.url.searchParams.get('purpose') ?? '';
        if (!['signed_certificate', 'dispatch_proof', 'receipt_proof', 'provider_acknowledgement', 'legal_authority', 'other'].includes(purpose)) throw badRequest('invalid_purpose', 'unknown upload purpose');
        const ct = String(ctx.req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
        const kind = UPLOAD_TYPES[ct];
        const body = ctx.rawBody ?? Buffer.alloc(0);
        if (!kind) throw badRequest('unsupported_type', `allowed types: ${Object.keys(UPLOAD_TYPES).join(', ')}`);
        if (body.length === 0 || !kind.magic(body)) throw badRequest('content_mismatch', 'file content does not match its declared type');
        const id = randomUUID();
        const now = new Date();
        const rel = `uploads/${now.getUTCFullYear()}/${String(now.getUTCMonth() + 1).padStart(2, '0')}/${id}.${kind.ext}`;
        await mkdir(join(d.root, rel, '..'), { recursive: true });
        await writeFile(join(d.root, rel), body, { mode: 0o440, flag: 'wx' });
        const sha = createHash('sha256').update(body).digest('hex');
        const filename = (ctx.url.searchParams.get('filename') ?? `upload.${kind.ext}`).replace(/[^\p{L}\p{N}._ -]/gu, '_').slice(0, 200);
        await d.pool.query(`INSERT INTO uploads (id, case_id, purpose, filename, content_type, relative_path, sha256, size_bytes, uploaded_by, note) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [id, caseId, purpose, filename, ct, rel, sha, body.length, ctx.user!.username, ctx.url.searchParams.get('note')?.slice(0, 1000) ?? null]);
        await auditCtx(d.pool, ctx, 'document_uploaded', { purpose, sha256: sha, size: body.length, content_type: ct }, { objectType: 'upload', objectId: id, caseRef: caseRow.case_ref, outcome: 'stored' });
        return reply(201, { id, sha256: sha, size_bytes: body.length });
      },
    },
    {
      method: 'GET', path: '/api/v1/uploads/:id/content', auth: 'full', roles: ['analyst', 'approver', 'evidence', 'report', 'admin'],
      handler: async (ctx) => {
        const u = (await d.pool.query<{ case_id: string; relative_path: string; sha256: string; filename: string }>('SELECT case_id, relative_path, sha256, filename FROM uploads WHERE id = $1', [requireUuid(ctx.params.id)])).rows[0];
        if (!u) throw notFound('upload not found');
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, u.case_id).catch(() => { throw notFound('upload not found'); });
        assertSafeRelative(u.relative_path);
        const abs = join(d.root, u.relative_path);
        if ((await sha256File(abs)).sha256 !== u.sha256) throw conflict('integrity_mismatch', 'upload does not match its recorded hash');
        await auditCtx(d.pool, ctx, 'document_downloaded', { sha256: u.sha256 }, { objectType: 'upload', objectId: ctx.params.id!, caseRef: caseRow.case_ref });
        const st = await stat(abs);
        return { status: 200, raw: createReadStream(abs), contentType: 'application/octet-stream', headers: { 'Content-Length': String(st.size), 'Content-Disposition': `attachment; filename="${ctx.params.id}-${u.filename.replace(/"/g, '')}"`, 'X-Evidence-SHA256': u.sha256, 'Content-Security-Policy': "default-src 'none'; sandbox" } };
      },
    },

    // ---- Templates and Section 63 worksheets ----
    {
      method: 'GET', path: '/api/v1/templates', auth: 'full',
      handler: async () => ({
        templates: [{
          id: SCHEDULE_TEMPLATE_ID, version: d.policy.governance.section63_template_source_version, source: SCHEDULE_SOURCE,
          verifications: (await d.pool.query('SELECT template_version, source_reference, verified_by, verified_at, note FROM template_verifications WHERE template_id = $1 ORDER BY id DESC', [SCHEDULE_TEMPLATE_ID])).rows,
          part_a: fieldsFor('A'), part_b: fieldsFor('B'),
        }],
      }),
    },
    {
      method: 'POST', path: '/api/v1/templates/:id/verify', auth: 'full', roles: ['approver', 'admin'],
      handler: async (ctx) => {
        if (ctx.params.id !== SCHEDULE_TEMPLATE_ID) throw notFound('unknown template');
        const b = parseBody(z.object({ source_reference: z.string().trim().min(10).max(1000), note: z.string().trim().max(2000).optional(), confirm_checked_against_official_text: z.literal(true) }).strict(), ctx.body);
        await d.pool.query('INSERT INTO template_verifications (template_id, template_version, source_reference, verified_by, note) VALUES ($1,$2,$3,$4,$5)',
          [SCHEDULE_TEMPLATE_ID, d.policy.governance.section63_template_source_version, b.source_reference, ctx.user!.username, b.note ?? null]);
        await auditCtx(d.pool, ctx, 'template_verified', { template: SCHEDULE_TEMPLATE_ID, version: d.policy.governance.section63_template_source_version, source_reference: b.source_reference }, { objectType: 'template', objectId: SCHEDULE_TEMPLATE_ID });
        return reply(201, { ok: true });
      },
    },
    {
      method: 'POST', path: '/api/v1/certificates', auth: 'full', roles: ['analyst', 'evidence', 'approver'],
      handler: async (ctx) => {
        const b = parseBody(z.object({ case_id: z.string().uuid(), attempt_ids: z.array(z.string().uuid()).min(1).max(50), part: z.enum(['A', 'B', 'A_and_B']) }).strict(), ctx.body);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, b.case_id, 'investigator');
        for (const a of b.attempt_ids) {
          await assertAttemptAccess(d.pool, ctx.user!, a);
          const linked = await d.pool.query('SELECT 1 FROM attempts a JOIN job_case_links l ON l.job_id = a.job_id WHERE a.id = $1 AND l.case_ref = $2', [a, caseRow.case_ref]);
          if (!linked.rowCount) throw badRequest('attempt_not_in_case', `attempt ${a} is not linked to this case`);
        }
        const v = await runVerification(d.pool, d.root, 'attempt', b.attempt_ids.join(','), ctx.user!.username, { actorKind: 'user', requestId: ctx.requestId, caseRef: caseRow.case_ref });
        if (v.result !== 'pass') throw conflict('verification_failed', `evidence verification failed (run ${v.run_id}); a certificate worksheet cannot be prepared over unverified records`);
        const id = randomUUID();
        const fs = await buildFactSheet(d.pool, d.root, id, caseRow.case_ref, b.attempt_ids);
        const ws = initialWorksheet(b.part, fs.hashReportSha256, fs.fileCount);
        await withTransaction(d.pool, async (client) => {
          await client.query(
            `INSERT INTO certificates (id, case_id, attempt_ids, part, template_source_version, fact_sheet_path, fact_sheet_sha256, hash_report_path, hash_report_sha256, worksheet, prepared_by, prepared_by_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
            [id, b.case_id, b.attempt_ids, b.part, d.policy.governance.section63_template_source_version, fs.factSheetPath, fs.factSheetSha256, fs.hashReportPath, fs.hashReportSha256, ws, ctx.user!.username, ctx.user!.id],
          );
          await client.query(`INSERT INTO certificate_events (certificate_id, from_state, to_state, actor, note) VALUES ($1, NULL, 'draft', $2, 'worksheet prepared')`, [id, ctx.user!.username]);
          // Evidence cited by a certificate is protected from routine expiry.
          await client.query(`UPDATE attempts SET retention_class = 'case_evidence', expires_at = NULL WHERE id = ANY($1::uuid[])`, [b.attempt_ids]);
          await auditCtx(client, ctx, 'certificate_prepared', { part: b.part, fact_sheet_sha256: fs.factSheetSha256, hash_report_sha256: fs.hashReportSha256, verification_run: v.run_id, attempts: b.attempt_ids.length },
            { objectType: 'certificate', objectId: id, caseRef: caseRow.case_ref, outcome: 'draft' });
        });
        return reply(201, { id, state: 'draft', fact_sheet_sha256: fs.factSheetSha256, hash_report_sha256: fs.hashReportSha256, verification_run: v.run_id });
      },
    },
    {
      method: 'GET', path: '/api/v1/certificates', auth: 'full',
      handler: async (ctx) => {
        const caseId = ctx.url.searchParams.get('case_id');
        const params: unknown[] = [ctx.user!.id, seesAllCases(ctx.user!)];
        let extra = '';
        if (caseId) { params.push(requireUuid(caseId, 'case_id')); extra = ` AND x.case_id = $${params.length}`; }
        const { rows } = await d.pool.query(
          `SELECT x.id, x.case_id, c.case_ref, x.part, x.state, cardinality(x.attempt_ids) AS attempt_count, x.prepared_by, x.created_at, x.completed_at, x.signed_recorded_at
             FROM certificates x JOIN cases c ON c.id = x.case_id
            WHERE ($2::boolean OR EXISTS (SELECT 1 FROM case_members m WHERE m.case_id = x.case_id AND m.user_id = $1))${extra}
            ORDER BY x.created_at DESC LIMIT 200`, params,
        );
        return { items: rows };
      },
    },
    {
      method: 'GET', path: '/api/v1/certificates/:id', auth: 'full',
      handler: async (ctx) => {
        const c = (await d.pool.query<{ case_id: string; part: 'A' | 'B' | 'A_and_B'; worksheet: Record<string, WorksheetValue>; template_source_version: string }>('SELECT * FROM certificates WHERE id = $1', [requireUuid(ctx.params.id)])).rows[0];
        if (!c) throw notFound('certificate not found');
        await assertCaseAccess(d.pool, ctx.user!, c.case_id).catch(() => { throw notFound('certificate not found'); });
        const verified = (await d.pool.query('SELECT 1 FROM template_verifications WHERE template_id = $1 AND template_version = $2', [SCHEDULE_TEMPLATE_ID, c.template_source_version])).rowCount;
        const events = (await d.pool.query('SELECT from_state, to_state, actor, note, at FROM certificate_events WHERE certificate_id = $1 ORDER BY id', [ctx.params.id])).rows;
        return { certificate: c, fields: fieldsFor(c.part), gaps: worksheetGaps(c.part, c.worksheet), template_verified: Boolean(verified), template_source: SCHEDULE_SOURCE, events,
          notice: 'The platform never signs. Unknown statutory particulars must be marked unknown by a person, not invented. Platform documents are supporting material, not a determination of admissibility; who may sign Part B is governed by the Act and current case law.' };
      },
    },
    {
      method: 'PATCH', path: '/api/v1/certificates/:id/worksheet', auth: 'full', roles: ['analyst', 'evidence', 'approver'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const b = parseBody(z.object({ expected_version: z.number().int().positive(), edits: z.record(z.string(), z.object({ value: z.union([z.string(), z.array(z.string()), z.boolean(), z.null()]), marked_unknown: z.boolean().optional() }).strict()) }).strict(), ctx.body);
        const c = (await d.pool.query<{ case_id: string; part: 'A' | 'B' | 'A_and_B'; worksheet: Record<string, WorksheetValue>; state: string; version: number }>('SELECT case_id, part, worksheet, state, version FROM certificates WHERE id = $1', [id])).rows[0];
        if (!c) throw notFound('certificate not found');
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, c.case_id, 'investigator');
        if (c.state !== 'draft') throw conflict('not_editable', 'only draft worksheets can be edited');
        let next: Record<string, WorksheetValue>;
        try {
          next = applyWorksheetEdits(c.part, c.worksheet, b.edits, ctx.user!.username);
        } catch (err) {
          throw badRequest('invalid_worksheet_edit', (err as Error).message);
        }
        const r = await d.pool.query('UPDATE certificates SET worksheet = $3, version = version + 1 WHERE id = $1 AND version = $2', [id, b.expected_version, next]);
        if (!r.rowCount) throw conflict('version_conflict', 'the worksheet changed meanwhile; reload');
        await auditCtx(d.pool, ctx, 'certificate_worksheet_edited', { fields: Object.keys(b.edits) }, { objectType: 'certificate', objectId: id, caseRef: caseRow.case_ref });
        return { version: b.expected_version + 1, gaps: worksheetGaps(c.part, next) };
      },
    },
    {
      method: 'POST', path: '/api/v1/certificates/:id/transition', auth: 'full', roles: ['analyst', 'evidence', 'approver'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const b = parseBody(z.object({
          action: z.enum(['complete', 'reopen', 'record_signed', 'record_submission', 'withdraw']),
          upload_id: z.string().uuid().optional(),
          submission: z.object({ authority: z.string().trim().min(2).max(300), reference: z.string().trim().min(1).max(200), submitted_at: z.string().datetime({ offset: true }), note: z.string().max(1000).optional() }).strict().optional(),
          note: z.string().trim().max(1000).optional(),
        }).strict(), ctx.body);
        return withTransaction(d.pool, async (client) => {
          const c = (await client.query<{ case_id: string; part: 'A' | 'B' | 'A_and_B'; worksheet: Record<string, WorksheetValue>; state: string; template_source_version: string; submissions: unknown[] }>(
            'SELECT case_id, part, worksheet, state, template_source_version, submissions FROM certificates WHERE id = $1 FOR UPDATE', [id],
          )).rows[0];
          if (!c) throw notFound('certificate not found');
          const { caseRow } = await assertCaseAccess(client, ctx.user!, c.case_id, 'investigator');
          const ev = async (to: string) => {
            await client.query('INSERT INTO certificate_events (certificate_id, from_state, to_state, actor, note) VALUES ($1,$2,$3,$4,$5)', [id, c.state, to, ctx.user!.username, b.note ?? null]);
            await auditCtx(client, ctx, 'certificate_transition', { action: b.action, from: c.state, to }, { objectType: 'certificate', objectId: id, caseRef: caseRow.case_ref, outcome: to });
          };
          if (b.action === 'complete') {
            if (c.state !== 'draft') throw conflict('invalid_state', 'only drafts can be completed');
            const verified = await client.query('SELECT 1 FROM template_verifications WHERE template_id = $1 AND template_version = $2', [SCHEDULE_TEMPLATE_ID, c.template_source_version]);
            if (!verified.rowCount) throw conflict('template_not_verified', 'an approver must first record that the Schedule template was checked against the official text');
            const gaps = worksheetGaps(c.part, c.worksheet);
            if (gaps.length) throw conflict('worksheet_incomplete', 'every field must be entered or explicitly marked unknown by a person', { gaps });
            await client.query(`UPDATE certificates SET state = 'completed', completed_by = $2, completed_at = now(), version = version + 1 WHERE id = $1`, [id, ctx.user!.username]);
            await ev('completed');
            return { state: 'completed' };
          }
          if (b.action === 'reopen') {
            if (c.state !== 'completed') throw conflict('invalid_state', 'only completed worksheets can be reopened');
            await client.query(`UPDATE certificates SET state = 'draft', version = version + 1 WHERE id = $1`, [id]);
            await ev('draft');
            return { state: 'draft' };
          }
          if (b.action === 'record_signed') {
            if (c.state !== 'completed') throw conflict('invalid_state', 'complete the worksheet before recording a signed certificate');
            if (!b.upload_id) throw badRequest('upload_required', 'upload the signed certificate (purpose signed_certificate) and cite it');
            const u = (await client.query<{ purpose: string; case_id: string; sha256: string }>('SELECT purpose, case_id, sha256 FROM uploads WHERE id = $1', [b.upload_id])).rows[0];
            if (!u || u.case_id !== c.case_id || u.purpose !== 'signed_certificate') throw badRequest('invalid_upload', 'the upload must be a signed_certificate in the same case');
            await client.query(`UPDATE certificates SET state = 'signed', signed_upload_id = $2, signed_recorded_by = $3, signed_recorded_at = now(), version = version + 1 WHERE id = $1`, [id, b.upload_id, ctx.user!.username]);
            await ev('signed');
            return { state: 'signed', signed_document_sha256: u.sha256, note: 'Recorded the signed document supplied by the signatories; the platform did not sign.' };
          }
          if (b.action === 'record_submission') {
            if (c.state !== 'signed' && c.state !== 'attached_to_submission') throw conflict('invalid_state', 'record a signed certificate first');
            if (!b.submission) throw badRequest('submission_required', 'give the authority, reference and submission time');
            const subs = [...(c.submissions ?? []), { ...b.submission, recorded_by: ctx.user!.username, recorded_at: new Date().toISOString(), submitted_at_ist: formatIst(b.submission.submitted_at) }];
            await client.query(`UPDATE certificates SET state = 'attached_to_submission', submissions = $2, version = version + 1 WHERE id = $1`, [id, JSON.stringify(subs)]);
            await ev('attached_to_submission');
            return { state: 'attached_to_submission', submissions: subs.length };
          }
          if (c.state === 'attached_to_submission') throw conflict('invalid_state', 'a submitted certificate cannot be withdrawn here; record a new submission note instead');
          await client.query(`UPDATE certificates SET state = 'withdrawn', version = version + 1 WHERE id = $1`, [id]);
          await ev('withdrawn');
          return { state: 'withdrawn' };
        });
      },
    },
    {
      method: 'GET', path: '/api/v1/certificates/:id/files/:kind', auth: 'full',
      handler: async (ctx) => {
        const c = (await d.pool.query<{ case_id: string; part: 'A' | 'B' | 'A_and_B'; worksheet: Record<string, WorksheetValue>; fact_sheet_path: string; fact_sheet_sha256: string; hash_report_path: string; hash_report_sha256: string; state: string }>(
          'SELECT case_id, part, worksheet, fact_sheet_path, fact_sheet_sha256, hash_report_path, hash_report_sha256, state FROM certificates WHERE id = $1', [requireUuid(ctx.params.id)],
        )).rows[0];
        if (!c) throw notFound('certificate not found');
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, c.case_id).catch(() => { throw notFound('certificate not found'); });
        let data: Buffer;
        let name: string;
        let sha: string;
        if (ctx.params.kind === 'fact-sheet' || ctx.params.kind === 'hash-report') {
          const p = ctx.params.kind === 'fact-sheet' ? c.fact_sheet_path : c.hash_report_path;
          sha = ctx.params.kind === 'fact-sheet' ? c.fact_sheet_sha256 : c.hash_report_sha256;
          assertSafeRelative(p);
          data = await readFile(join(d.root, p));
          if (createHash('sha256').update(data).digest('hex') !== sha) throw conflict('integrity_mismatch', 'file does not match its recorded hash');
          name = p.split('/').pop()!;
        } else if (ctx.params.kind === 'worksheet') {
          const lines = [`# DRAFT WORKSHEET — Certificate under section 63(4)(c), Bharatiya Sakshya Adhiniyam, 2023 (${c.part === 'A_and_B' ? 'Part A and Part B' : `Part ${c.part}`})`, '',
            `State: ${c.state}. This worksheet is not a certificate. Transcribe verified particulars onto the prescribed form, to be signed by the responsible persons.`, `Source: ${SCHEDULE_SOURCE}`, ''];
          for (const f of fieldsFor(c.part)) {
            const v = c.worksheet[f.key];
            const shown = v?.marked_unknown ? '[marked unknown / not applicable]' : v?.value === null || v?.value === undefined ? '[blank]' : Array.isArray(v.value) ? v.value.join(', ') : String(v.value);
            lines.push(`- **${f.label}**: ${shown}${v?.source === 'system_proposed' ? ' (system proposal — confirm)' : ''}`);
          }
          data = Buffer.from(`${lines.join('\n')}\n`);
          sha = createHash('sha256').update(data).digest('hex');
          name = 'worksheet.md';
        } else throw notFound('unknown file');
        await auditCtx(d.pool, ctx, 'certificate_file_downloaded', { kind: ctx.params.kind, sha256: sha }, { objectType: 'certificate', objectId: ctx.params.id!, caseRef: caseRow.case_ref });
        return { status: 200, raw: data, contentType: 'application/octet-stream', headers: { 'Content-Disposition': `attachment; filename="certificate-${ctx.params.id}-${name}"`, 'X-Evidence-SHA256': sha } };
      },
    },
  ];

  async function transition(ctx: Ctx, id: string): Promise<unknown> {
    const b = parseBody(z.object({
      action: z.enum(Object.keys(TRANSITIONS) as [string, ...string[]]),
      note: z.string().trim().max(2000).optional(),
      issued_at: z.string().datetime({ offset: true }).optional(),
      issue_channel: z.string().trim().max(300).optional(),
      dispatch_upload_id: z.string().uuid().optional(),
      received_at: z.string().datetime({ offset: true }).optional(),
      receipt_upload_id: z.string().uuid().optional(),
      outcome: z.enum(['complied', 'partially_complied', 'rejected', 'no_response']).optional(),
      target_statuses: z.array(z.object({ target_id: z.number().int().positive(), status: z.enum(['acted_upon', 'not_acted', 'disputed', 'withdrawn', 'verified_removed', 'still_live']), note: z.string().max(1000).optional() }).strict()).max(200).optional(),
      close_as: z.enum(['verified_closed', 'escalated']).optional(),
    }).strict(), ctx.body);
    const t = TRANSITIONS[b.action]!;
    const { n, caseRow } = await loadNotice(ctx, id, 'investigator');
    if (!t.roles.some((r) => hasRole(ctx.user!, r))) throw forbidden(`'${b.action}' requires one of: ${t.roles.join(', ')}`);
    if (!t.from.includes(n.state)) throw conflict('invalid_transition', `cannot ${b.action} a notice in state ${n.state}`);
    if (t.notCreator && n.created_by_id === ctx.user!.id) throw forbidden('maker-checker: the author cannot review or approve their own notice', 'maker_checker');
    if (b.action === 'withdraw' || b.action === 'return_to_draft' || b.action === 'dispute') {
      if (!b.note || b.note.length < 5) throw badRequest('reason_required', 'give a reason for this change');
    }

    return withTransaction(d.pool, async (client) => {
      const locked = (await client.query<NoticeRow>('SELECT * FROM notices WHERE id = $1 FOR UPDATE', [id])).rows[0]!;
      if (locked.state !== n.state) throw conflict('version_conflict', 'the notice changed meanwhile; reload');
      let to = t.to;
      const extra: Record<string, unknown> = {};
      if (t.eligible) {
        const checks = await eligibility(client, locked, ctx.user, t.eligible);
        await client.query('UPDATE notices SET last_eligibility = $2 WHERE id = $1', [id, JSON.stringify(checks)]);
        const blocking = blockingFailures(checks);
        if (blocking.length) throw conflict('not_eligible', 'eligibility checks failed', { failures: blocking.map((c) => ({ code: c.code, message: c.message })) });
      }
      if (b.action === 'approve') {
        const snapshot = approvalSnapshot({ notice: reportInputFrom(locked, caseRow.case_ref, [], null, '').notice, targets: await reportTargets(client, d.root, id) });
        const sha = createHash('sha256').update(snapshotText(snapshot)).digest('hex');
        await client.query('UPDATE notices SET approved_by = $2, approved_by_id = $3, approved_at = now(), approved_snapshot_sha256 = $4 WHERE id = $1', [id, ctx.user!.username, ctx.user!.id, sha]);
        extra.approved_snapshot_sha256 = sha;
      }
      if (b.action === 'return_to_draft') {
        await client.query('UPDATE notices SET approved_by = NULL, approved_by_id = NULL, approved_at = NULL, approved_snapshot_sha256 = NULL WHERE id = $1', [id]);
      }
      if (b.action === 'generate') {
        const targets = await reportTargets(client, d.root, id);
        const snap = approvalSnapshot({ notice: reportInputFrom(locked, caseRow.case_ref, [], null, '').notice, targets });
        const sha = createHash('sha256').update(snapshotText(snap)).digest('hex');
        if (sha !== locked.approved_snapshot_sha256) throw conflict('snapshot_changed', 'content differs from what the checker approved; return to draft and re-approve');
        const attemptIds = [...new Set(targets.flatMap((x) => x.evidence.map((e) => e.attempt_id)))];
        const pkg = await createEvidencePackage(d.pool, d.root, { kind: 'attempts', id: attemptIds.join(','), purpose: `evidence enclosure for notice ${id}`, actor: ctx.user!.username, actorKind: 'user', requestId: ctx.requestId, caseRef: caseRow.case_ref });
        const generatedAt = new Date().toISOString();
        const r = renderReport(reportInputFrom(locked, caseRow.case_ref, targets, { id: pkg.package_id, index_sha256: pkg.index_sha256 }, generatedAt));
        const reportId = randomUUID();
        const dir = `reports/notices/${id}/${reportId}`;
        await mkdir(join(d.root, dir), { recursive: true });
        const files = [
          { path: 'notice.md', data: r.markdown, format: 'markdown' },
          { path: 'notice.html', data: r.html, format: 'html' },
          { path: 'notice.json', data: `${JSON.stringify(r.json, null, 2)}\n`, format: 'json' },
          { path: 'targets.csv', data: r.csv, format: 'csv' },
        ].map((f) => ({ ...f, sha256: createHash('sha256').update(f.data).digest('hex'), size_bytes: Buffer.byteLength(f.data) }));
        for (const f of files) await writeFile(join(d.root, dir, f.path), f.data, { mode: 0o440, flag: 'wx' });
        const index = { format: 'cyber-web-collector/notice-report@1', notice_id: id, report_id: reportId, approved_snapshot_sha256: sha, evidence_package: { id: pkg.package_id, index_sha256: pkg.index_sha256 }, files: files.map(({ data: _d, ...rest }) => rest), generated_at_utc: generatedAt };
        const indexText = `${JSON.stringify(index, null, 2)}\n`;
        await writeFile(join(d.root, dir, 'report-index.json'), indexText, { mode: 0o440, flag: 'wx' });
        const indexSha = createHash('sha256').update(indexText).digest('hex');
        const fileRows = [...files.map(({ data: _d, ...rest }) => rest), { path: 'report-index.json', sha256: indexSha, size_bytes: Buffer.byteLength(indexText), format: 'json' }];
        await client.query(`INSERT INTO notice_reports (id, notice_id, snapshot_sha256, relative_dir, files, index_sha256, evidence_package_id, generated_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [reportId, id, sha, dir, JSON.stringify(fileRows), indexSha, pkg.package_id, ctx.user!.username]);
        await client.query('UPDATE notices SET generated_package_id = $2, report_path = $3, report_sha256 = $4 WHERE id = $1', [id, pkg.package_id, `${dir}/report-index.json`, indexSha]);
        // Evidence cited by an action is protected from routine expiry.
        await client.query(`UPDATE attempts SET retention_class = 'notice_issued', expires_at = NULL WHERE id = ANY($1::uuid[])`, [attemptIds]);
        Object.assign(extra, { report_id: reportId, report_index_sha256: indexSha, evidence_package_id: pkg.package_id });
      }
      if (b.action === 'record_issued') {
        if (!b.issued_at || !b.issue_channel || !b.dispatch_upload_id) throw badRequest('dispatch_proof_required', 'record issued_at, issue_channel and a dispatch proof upload; issuance is done by an authorised person outside this system');
        await requireUpload(client, b.dispatch_upload_id, locked.case_id, ['dispatch_proof']);
        await client.query('UPDATE notices SET issued_at = $2, issued_by = $3, issue_channel = $4, dispatch_upload_id = $5 WHERE id = $1', [id, b.issued_at, ctx.user!.username, b.issue_channel, b.dispatch_upload_id]);
      }
      if (b.action === 'record_acknowledged') {
        if (!b.received_at || !b.receipt_upload_id) throw badRequest('receipt_proof_required', 'a legally meaningful timer starts only from documented receipt: give received_at and a receipt/acknowledgement upload');
        await requireUpload(client, b.receipt_upload_id, locked.case_id, ['receipt_proof', 'provider_acknowledgement']);
        await client.query('UPDATE notices SET received_at = $2, receipt_upload_id = $3 WHERE id = $1', [id, b.received_at, b.receipt_upload_id]);
      }
      if (b.action === 'record_outcome') {
        if (!b.outcome) throw badRequest('outcome_required', 'give the outcome (complied, partially_complied, rejected, no_response)');
        to = b.outcome;
        for (const s of b.target_statuses ?? []) {
          await client.query('UPDATE notice_targets SET target_status = $3, status_note = $4, updated_at = now() WHERE notice_id = $1 AND target_id = $2', [id, s.target_id, s.status, s.note ?? null]);
        }
        await client.query('UPDATE notices SET outcome_note = $2 WHERE id = $1', [id, b.note ?? null]);
        extra.note = 'Issued or acknowledged is not the same as complied: verify with a fresh capture (monitoring) before closing.';
      }
      if (b.action === 'close') {
        if (!b.close_as) throw badRequest('close_as_required', 'close as verified_closed or escalated');
        if (b.close_as === 'verified_closed') {
          const fresh = await client.query(
            `SELECT 1 FROM notice_targets nt JOIN jobs j ON j.target_id = nt.target_id JOIN attempts a ON a.job_id = j.id
              WHERE nt.notice_id = $1 AND a.started_at > COALESCE($2::timestamptz, now() - interval '100 years') AND a.status IN ('committed', 'recovered') LIMIT 1`,
            [id, locked.issued_at],
          );
          if (!fresh.rowCount) throw conflict('verification_capture_required', 'closing as verified needs at least one fresh capture after issuance (schedule a monitoring revisit)');
        }
        to = b.close_as;
      }
      await client.query('UPDATE notices SET state = $2, version = version + 1 WHERE id = $1', [id, to]);
      await event(client, ctx, locked, caseRow.case_ref, locked.state, to!, b.note ?? null, extra);
      return { state: to, ...extra };
    });
  }

  async function requireUpload(db: Queryable, uploadId: string, caseId: string, purposes: string[]): Promise<void> {
    const u = (await db.query<{ case_id: string; purpose: string }>('SELECT case_id, purpose FROM uploads WHERE id = $1', [uploadId])).rows[0];
    if (!u || u.case_id !== caseId || !purposes.includes(u.purpose)) throw badRequest('invalid_upload', `the upload must belong to this case and have purpose ${purposes.join(' or ')}`);
  }
}
