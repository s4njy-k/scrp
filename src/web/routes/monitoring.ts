/**
 * Monitoring rules, revisit observations and reappearance alerts
 * (blueprint v4 §22.1 /monitor; checklist §8).
 */
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { assertCaseAccess, assertTargetAccess, seesAllCases } from '../authz.js';
import { badRequest, conflict, notFound, reply, requireUuid, type RouteSpec } from '../http.js';
import { auditCtx, parseBody, type RouteDeps } from './common.js';

export function monitoringRoutes(d: RouteDeps): RouteSpec[] {
  const m = d.policy.monitoring;
  return [
    {
      method: 'POST', path: '/api/v1/monitoring/rules', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const b = parseBody(z.object({
          target_id: z.number().int().positive(),
          case_id: z.string().uuid(),
          interval_hours: z.number().positive().default(m.default_interval_hours),
          duration_days: z.number().int().positive().max(m.max_rule_duration_days).default(Math.min(30, m.max_rule_duration_days)),
          capture_variant: z.enum(['desktop', 'mobile']).default('desktop'),
          notice_id: z.string().uuid().optional(),
          reason: z.string().trim().min(5).max(1000),
        }).strict(), ctx.body);
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, b.case_id, 'investigator');
        await assertTargetAccess(d.pool, ctx.user!, b.target_id, 'investigator');
        if (b.interval_hours < m.min_interval_hours) throw badRequest('interval_too_short', `revisits are proportionate: at least every ${m.min_interval_hours} h`);
        const linked = await d.pool.query('SELECT 1 FROM jobs j JOIN job_case_links l ON l.job_id = j.id WHERE j.target_id = $1 AND l.case_ref = $2 LIMIT 1', [b.target_id, caseRow.case_ref]);
        if (!linked.rowCount) throw badRequest('target_not_in_case', 'the target is not linked to this case');
        const baseline = (await d.pool.query<{ id: string }>(
          `SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE j.target_id = $1 AND a.status IN ('committed','recovered') AND a.artifact_dir IS NOT NULL ORDER BY a.started_at DESC LIMIT 1`, [b.target_id],
        )).rows[0];
        const id = randomUUID();
        try {
          await d.pool.query(
            `INSERT INTO monitoring_rules (id, target_id, case_id, notice_id, baseline_attempt, interval_hours, max_per_day, capture_variant, reason, created_by, ends_at, next_due_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now() + make_interval(days => $11), now() + make_interval(secs => $6::numeric * 3600))`,
            [id, b.target_id, b.case_id, b.notice_id ?? null, baseline?.id ?? null, b.interval_hours, Math.min(m.max_auto_revisits_per_target_per_day, Math.max(1, Math.floor(24 / b.interval_hours))),
             b.capture_variant, b.reason, ctx.user!.username, b.duration_days],
          );
        } catch (err) {
          if ((err as { code?: string }).code === '23505') throw conflict('rule_exists', 'an active monitoring rule already exists for this target and profile in this case');
          throw err;
        }
        await auditCtx(d.pool, ctx, 'monitoring_rule_created', { target_id: b.target_id, interval_hours: b.interval_hours, duration_days: b.duration_days, reason: b.reason },
          { objectType: 'monitoring_rule', objectId: id, caseRef: caseRow.case_ref, outcome: 'active' });
        return reply(201, { id, baseline_attempt: baseline?.id ?? null, note: 'Each revisit creates a new capture; earlier evidence is unchanged. Revisits pause under disk pressure.' });
      },
    },
    {
      method: 'GET', path: '/api/v1/monitoring/rules', auth: 'full',
      handler: async (ctx) => {
        const caseId = ctx.url.searchParams.get('case_id');
        const params: unknown[] = [ctx.user!.id, seesAllCases(ctx.user!)];
        let extra = '';
        if (caseId) { params.push(requireUuid(caseId, 'case_id')); extra = ` AND r.case_id = $${params.length}`; }
        const { rows } = await d.pool.query(
          `SELECT r.*, t.url, c.case_ref,
                  (SELECT jsonb_build_object('outcome_class', o.outcome_class, 'created_at', o.created_at, 'differences', o.differences, 'attempt_id', o.attempt_id)
                     FROM monitoring_observations o WHERE o.rule_id = r.id ORDER BY o.id DESC LIMIT 1) AS latest_observation,
                  (SELECT count(*)::int FROM monitoring_observations o WHERE o.rule_id = r.id) AS observations
             FROM monitoring_rules r JOIN targets t ON t.id = r.target_id JOIN cases c ON c.id = r.case_id
            WHERE ($2::boolean OR EXISTS (SELECT 1 FROM case_members cm WHERE cm.case_id = r.case_id AND cm.user_id = $1))${extra}
            ORDER BY r.active DESC, r.next_due_at LIMIT 500`, params,
        );
        return { items: rows };
      },
    },
    {
      method: 'POST', path: '/api/v1/monitoring/rules/:id/stop', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const r = (await d.pool.query<{ case_id: string }>('SELECT case_id FROM monitoring_rules WHERE id = $1', [id])).rows[0];
        if (!r) throw notFound('rule not found');
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, r.case_id, 'investigator');
        const b = parseBody(z.object({ reason: z.string().trim().min(5).max(1000) }).strict(), ctx.body);
        const u = await d.pool.query(`UPDATE monitoring_rules SET active = false, stopped_by = $2, stopped_at = now() WHERE id = $1 AND active`, [id, ctx.user!.username]);
        if (!u.rowCount) throw conflict('not_active', 'rule is not active');
        await auditCtx(d.pool, ctx, 'monitoring_rule_stopped', { reason: b.reason }, { objectType: 'monitoring_rule', objectId: id, caseRef: caseRow.case_ref });
        return { active: false };
      },
    },
    {
      method: 'POST', path: '/api/v1/monitoring/rules/:id/observations', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const id = requireUuid(ctx.params.id);
        const r = (await d.pool.query<{ case_id: string; last_job_id: number | null }>('SELECT case_id, last_job_id FROM monitoring_rules WHERE id = $1', [id])).rows[0];
        if (!r) throw notFound('rule not found');
        const { caseRow } = await assertCaseAccess(d.pool, ctx.user!, r.case_id, 'investigator');
        const b = parseBody(z.object({
          outcome_class: z.enum(['reported_removal', 'provider_confirmed_suspension']),
          note: z.string().trim().min(5).max(2000),
          upload_id: z.string().uuid().optional(),
        }).strict(), ctx.body);
        // Provider confirmation must rest on a recorded acknowledgement, never on an inference.
        if (b.outcome_class === 'provider_confirmed_suspension') {
          if (!b.upload_id) throw badRequest('proof_required', 'provider-confirmed suspension needs the provider acknowledgement upload');
          const u = (await d.pool.query<{ case_id: string; purpose: string }>('SELECT case_id, purpose FROM uploads WHERE id = $1', [b.upload_id])).rows[0];
          if (!u || u.case_id !== r.case_id || !['provider_acknowledgement', 'receipt_proof'].includes(u.purpose)) throw badRequest('invalid_upload', 'upload must be a provider acknowledgement in this case');
        }
        if (!r.last_job_id) throw conflict('no_revisit', 'record manual observations against an existing revisit job');
        const o = await d.pool.query<{ id: number }>(
          `INSERT INTO monitoring_observations (rule_id, job_id, outcome_class, differences, analyst_note) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
          [id, r.last_job_id, b.outcome_class, JSON.stringify({ recorded_by: ctx.user!.username, upload_id: b.upload_id ?? null }), b.note],
        );
        await auditCtx(d.pool, ctx, 'monitoring_observation_recorded', { outcome: b.outcome_class, manual: true, upload_id: b.upload_id ?? null }, { objectType: 'monitoring_rule', objectId: id, caseRef: caseRow.case_ref, outcome: b.outcome_class });
        return reply(201, { observation_id: o.rows[0]!.id });
      },
    },
    {
      method: 'GET', path: '/api/v1/monitoring/alerts', auth: 'full',
      handler: async (ctx) => {
        const visible = (alias: string) => `($2::boolean OR EXISTS (SELECT 1 FROM jobs j JOIN job_case_links l ON l.job_id = j.id JOIN cases c ON c.case_ref = l.case_ref
            JOIN case_members cm ON cm.case_id = c.id WHERE j.target_id = ${alias} AND cm.user_id = $1))`;
        const { rows } = await d.pool.query(
          `SELECT a.*, ts.url AS source_url, tn.url AS new_url FROM reappearance_alerts a JOIN targets ts ON ts.id = a.source_target_id JOIN targets tn ON tn.id = a.new_target_id
            WHERE ${visible('a.source_target_id')} AND ${visible('a.new_target_id')} ORDER BY a.acknowledged_at NULLS FIRST, a.created_at DESC LIMIT 200`,
          [ctx.user!.id, seesAllCases(ctx.user!)],
        );
        return { items: rows, note: 'A reappearance alert shows shared unusual identifiers on a new domain. It is a lead for review, not attribution.' };
      },
    },
    {
      method: 'POST', path: '/api/v1/monitoring/alerts/:id/acknowledge', auth: 'full', roles: ['analyst', 'approver', 'admin'],
      handler: async (ctx) => {
        const id = Number(ctx.params.id);
        const a = (await d.pool.query<{ new_target_id: number }>('SELECT new_target_id FROM reappearance_alerts WHERE id = $1', [id])).rows[0];
        if (!a) throw notFound('alert not found');
        await assertTargetAccess(d.pool, ctx.user!, a.new_target_id, 'investigator');
        await d.pool.query('UPDATE reappearance_alerts SET acknowledged_by = $2, acknowledged_at = now() WHERE id = $1', [id, ctx.user!.username]);
        await auditCtx(d.pool, ctx, 'reappearance_alert_acknowledged', {}, { objectType: 'reappearance_alert', objectId: id });
        return { ok: true };
      },
    },
  ];
}
