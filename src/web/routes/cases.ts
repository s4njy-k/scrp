/**
 * Cases, membership and legal holds (checklist §6 "link targets to an
 * authorised case ... with case-level access controls and masked display";
 * §1 legal holds; blueprint v4 §22.1 /cases/:caseId).
 */
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { withTransaction } from '../../db/pool.js';
import { assertCaseAccess, hasRole, maskRef, seesAllCases } from '../authz.js';
import { conflict, decodeCursor, encodeCursor, forbidden, notFound, queryInt, reply, requireUuid, type RouteSpec } from '../http.js';
import { auditCtx, expectedVersion, parseBody, type RouteDeps } from './common.js';

const CATEGORY = z.enum(['financial_fraud', 'phishing', 'impersonation', 'investment_scam', 'loan_app', 'job_task_scam', 'sextortion', 'other']);
const REF = z.string().trim().min(1).max(120).regex(/^[A-Za-z0-9/_.:-]+$/, 'letters, digits and / _ . : - only');

export function caseRoutes(d: RouteDeps): RouteSpec[] {
  return [
    {
      method: 'GET', path: '/api/v1/cases', auth: 'full',
      handler: async (ctx) => {
        const limit = queryInt(ctx.url, 'limit', d.policy.web.paginated_list_limit_default, 1, d.policy.web.paginated_list_limit_max);
        const cursor = decodeCursor(ctx.url.searchParams.get('cursor'));
        const status = ctx.url.searchParams.get('status');
        const q = ctx.url.searchParams.get('q')?.trim().slice(0, 100) || null;
        const { rows } = await d.pool.query(
          `SELECT c.id, c.case_ref, c.title, c.category, c.sensitivity, c.status, c.owner_unit, c.opened_at, c.version,
                  m.case_role AS my_role,
                  (SELECT count(DISTINCT l.job_id)::int FROM job_case_links l WHERE l.case_ref = c.case_ref) AS job_count,
                  EXISTS (SELECT 1 FROM case_holds h WHERE h.case_ref = c.case_ref AND h.released_at IS NULL) AS on_hold
             FROM cases c LEFT JOIN case_members m ON m.case_id = c.id AND m.user_id = $1
            WHERE ($2::boolean OR m.user_id IS NOT NULL)
              AND ($3::text IS NULL OR c.status = $3)
              AND ($4::text IS NULL OR c.case_ref ILIKE '%' || $4 || '%' OR c.title ILIKE '%' || $4 || '%')
              AND ($5::timestamptz IS NULL OR (c.opened_at, c.id) < ($5::timestamptz, $6::uuid))
            ORDER BY c.opened_at DESC, c.id DESC LIMIT $7`,
          [ctx.user!.id, seesAllCases(ctx.user!), status, q, cursor?.[0] ?? null, cursor?.[1] ?? null, limit + 1],
        );
        const page = rows.slice(0, limit);
        const last = page[page.length - 1] as { opened_at: Date; id: string } | undefined;
        return { items: page, next_cursor: rows.length > limit && last ? encodeCursor([last.opened_at.toISOString(), last.id]) : null };
      },
    },
    {
      method: 'POST', path: '/api/v1/cases', auth: 'full', roles: ['admin', 'analyst', 'intake'],
      handler: async (ctx) => {
        const b = parseBody(z.object({
          case_ref: REF,
          title: z.string().trim().min(1).max(300),
          category: CATEGORY.default('other'),
          sensitivity: z.enum(['restricted', 'confidential', 'secret']).default('restricted'),
          owner_unit: z.string().trim().max(200).optional(),
          description: z.string().max(5000).optional(),
          ncrp_refs: z.array(REF).max(50).default([]),
          fir_refs: z.array(REF).max(50).default([]),
        }).strict(), ctx.body);
        const id = randomUUID();
        try {
          await withTransaction(d.pool, async (client) => {
            await client.query(
              `INSERT INTO cases (id, case_ref, title, category, sensitivity, owner_unit, description, ncrp_refs, fir_refs, opened_by)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
              [id, b.case_ref, b.title, b.category, b.sensitivity, b.owner_unit ?? null, b.description ?? null, b.ncrp_refs, b.fir_refs, ctx.user!.id],
            );
            await client.query(`INSERT INTO case_members (case_id, user_id, case_role, added_by) VALUES ($1,$2,'owner',$2)`, [id, ctx.user!.id]);
            await auditCtx(client, ctx, 'case_opened', { case_ref: b.case_ref, category: b.category, sensitivity: b.sensitivity, ncrp_ref_count: b.ncrp_refs.length, fir_ref_count: b.fir_refs.length },
              { objectType: 'case', objectId: id, caseRef: b.case_ref, outcome: 'ok' });
          });
        } catch (err) {
          if ((err as { code?: string }).code === '23505') throw conflict('case_ref_taken', 'a case with this reference already exists');
          throw err;
        }
        return reply(201, { id, case_ref: b.case_ref });
      },
    },
    {
      method: 'GET', path: '/api/v1/cases/:id', auth: 'full',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const { role } = await assertCaseAccess(d.pool, ctx.user!, id);
        const c = (await d.pool.query(
          `SELECT id, case_ref, title, category, sensitivity, owner_unit, status, description, ncrp_refs, fir_refs, opened_at, closed_at, version,
                  (SELECT username FROM users WHERE id = opened_by) AS opened_by
             FROM cases WHERE id = $1`, [id],
        )).rows[0] as Record<string, unknown> & { case_ref: string; ncrp_refs: string[]; fir_refs: string[] };
        // Restricted references are shown in full to case members only; administrators outside the case see masks.
        const member = role !== 'admin';
        const members = (await d.pool.query(
          `SELECT u.id AS user_id, u.username, u.display_name, m.case_role, m.added_at FROM case_members m JOIN users u ON u.id = m.user_id WHERE m.case_id = $1 ORDER BY m.case_role, u.username`, [id],
        )).rows;
        const counts = (await d.pool.query(
          `SELECT j.state, count(*)::int AS n FROM jobs j WHERE j.id IN (SELECT job_id FROM job_case_links WHERE case_ref = $1) GROUP BY j.state`, [c.case_ref],
        )).rows;
        const holds = (await d.pool.query('SELECT case_ref, reason, placed_by, placed_at, released_by, released_at FROM case_holds WHERE case_ref = $1', [c.case_ref])).rows;
        await auditCtx(d.pool, ctx, 'case_viewed', { as: role }, { objectType: 'case', objectId: id, caseRef: c.case_ref });
        return {
          ...c,
          ncrp_refs: member ? c.ncrp_refs : c.ncrp_refs.map(maskRef),
          fir_refs: member ? c.fir_refs : c.fir_refs.map(maskRef),
          refs_masked: !member,
          my_role: role,
          members,
          job_states: Object.fromEntries(counts.map((r) => [r.state, r.n])),
          holds,
        };
      },
    },
    {
      method: 'PATCH', path: '/api/v1/cases/:id', auth: 'full',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        await assertCaseAccess(d.pool, ctx.user!, id, 'owner');
        const b = parseBody(z.object({
          expected_version: z.number().int().positive().optional(),
          title: z.string().trim().min(1).max(300).optional(),
          description: z.string().max(5000).optional(),
          status: z.enum(['open', 'closed']).optional(),
          ncrp_refs: z.array(REF).max(50).optional(),
          fir_refs: z.array(REF).max(50).optional(),
          reason: z.string().trim().min(3).max(500),
        }).strict(), ctx.body);
        const version = expectedVersion(ctx, b);
        if (version === null) throw conflict('version_required', 'send expected_version (or If-Match) for concurrent-safe updates');
        const r = await d.pool.query<{ version: number; case_ref: string }>(
          `UPDATE cases SET title = COALESCE($3, title), description = COALESCE($4, description), status = COALESCE($5, status),
              ncrp_refs = COALESCE($6, ncrp_refs), fir_refs = COALESCE($7, fir_refs), version = version + 1,
              closed_at = CASE WHEN $5 = 'closed' THEN COALESCE(closed_at, now()) WHEN $5 = 'open' THEN NULL ELSE closed_at END,
              closed_by = CASE WHEN $5 = 'closed' THEN $8::uuid WHEN $5 = 'open' THEN NULL ELSE closed_by END
            WHERE id = $1 AND version = $2 RETURNING version, case_ref`,
          [id, version, b.title ?? null, b.description ?? null, b.status ?? null, b.ncrp_refs ?? null, b.fir_refs ?? null, ctx.user!.id],
        );
        if (!r.rows[0]) throw conflict('version_conflict', 'the case was changed by someone else; reload and retry');
        await auditCtx(d.pool, ctx, 'case_updated', { changes: { title: b.title, status: b.status, description_changed: b.description !== undefined, ncrp_refs_changed: b.ncrp_refs !== undefined, fir_refs_changed: b.fir_refs !== undefined }, reason: b.reason },
          { objectType: 'case', objectId: id, caseRef: r.rows[0].case_ref, outcome: 'ok' });
        return { version: r.rows[0].version };
      },
    },
    {
      method: 'POST', path: '/api/v1/cases/:id/members', auth: 'full',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, id, 'owner');
        const b = parseBody(z.object({ username: z.string().min(3).max(64), case_role: z.enum(['owner', 'investigator', 'viewer']), reason: z.string().trim().min(3).max(500) }).strict(), ctx.body);
        const u = (await d.pool.query<{ id: string }>('SELECT id FROM users WHERE username = $1 AND disabled_at IS NULL', [b.username.toLowerCase()])).rows[0];
        if (!u) throw notFound('user not found');
        await d.pool.query(
          `INSERT INTO case_members (case_id, user_id, case_role, added_by) VALUES ($1,$2,$3,$4)
           ON CONFLICT (case_id, user_id) DO UPDATE SET case_role = EXCLUDED.case_role, added_by = EXCLUDED.added_by, added_at = now()`,
          [id, u.id, b.case_role, ctx.user!.id],
        );
        await auditCtx(d.pool, ctx, 'case_member_set', { username: b.username, case_role: b.case_role, reason: b.reason }, { objectType: 'case', objectId: id, caseRef: caseRow.case_ref, outcome: 'ok' });
        return { ok: true };
      },
    },
    {
      method: 'DELETE', path: '/api/v1/cases/:id/members/:userId', auth: 'full', body: 'none',
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const userId = requireUuid(ctx.params.userId, 'userId');
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, id, 'owner');
        return withTransaction(d.pool, async (client) => {
          const owners = await client.query<{ user_id: string }>(`SELECT user_id FROM case_members WHERE case_id = $1 AND case_role = 'owner' FOR UPDATE`, [id]);
          if (owners.rows.length === 1 && owners.rows[0]!.user_id === userId) throw conflict('last_owner', 'a case must keep at least one owner');
          const r = await client.query('DELETE FROM case_members WHERE case_id = $1 AND user_id = $2', [id, userId]);
          if (!r.rowCount) throw notFound('membership not found');
          await auditCtx(client, ctx, 'case_member_removed', { user_id: userId }, { objectType: 'case', objectId: id, caseRef: caseRow.case_ref, outcome: 'ok' });
          return reply(204);
        });
      },
    },
    {
      method: 'POST', path: '/api/v1/cases/:id/hold', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, id, 'investigator');
        const b = parseBody(z.object({ reason: z.string().trim().min(5).max(1000), authority_ref: z.string().trim().max(200).optional() }).strict(), ctx.body);
        await d.pool.query(
          `INSERT INTO case_holds (case_ref, reason, placed_by) VALUES ($1,$2,$3)
           ON CONFLICT (case_ref) DO UPDATE SET reason = EXCLUDED.reason, placed_by = EXCLUDED.placed_by, placed_at = now(), released_at = NULL, released_by = NULL`,
          [caseRow.case_ref, b.authority_ref ? `${b.reason} [authority: ${b.authority_ref}]` : b.reason, ctx.user!.username],
        );
        await auditCtx(d.pool, ctx, 'case_hold_placed', { reason: b.reason, authority_ref: b.authority_ref ?? null }, { objectType: 'case', objectId: id, caseRef: caseRow.case_ref, outcome: 'ok' });
        return { on_hold: true };
      },
    },
    {
      method: 'POST', path: '/api/v1/cases/:id/hold/release', auth: 'full', roles: ['approver', 'admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, id, 'viewer');
        if (!hasRole(ctx.user!, 'approver', 'admin')) throw forbidden();
        const b = parseBody(z.object({ reason: z.string().trim().min(5).max(1000) }).strict(), ctx.body);
        const r = await d.pool.query(`UPDATE case_holds SET released_at = now(), released_by = $2 WHERE case_ref = $1 AND released_at IS NULL`, [caseRow.case_ref, ctx.user!.username]);
        if (!r.rowCount) throw notFound('no active hold');
        await auditCtx(d.pool, ctx, 'case_hold_released', { reason: b.reason }, { objectType: 'case', objectId: id, caseRef: caseRow.case_ref, outcome: 'ok' });
        return { on_hold: false };
      },
    },
  ];
}
