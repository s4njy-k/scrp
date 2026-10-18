/**
 * Post-action monitoring and takedown verification (blueprint v4 §22.4
 * "Follow-up", §28.1 "Monitoring revisit"; checklist §8).
 *
 *  - Revisits are NEW jobs and attempts under an authorised, bounded rule;
 *    earlier observations are never modified.
 *  - They run at low priority behind first captures and pause under disk
 *    pressure (admission control).
 *  - Each revisit is compared with the baseline and classified into distinct
 *    outcomes; provider-confirmed suspension and reported removal are only ever
 *    recorded by an analyst with proof.
 *  - Reappearance on a new domain via corroborated unusual identifiers raises
 *    an alert with evidence, not an attribution verdict.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { getDomain } from 'tldts';
import type { Policy } from '../config/policy.js';
import { audit, withTransaction, type Pool, type Queryable } from '../db/pool.js';
import { readAdmission } from '../queue/queue.js';
import { assertSafeRelative } from '../storage/artifactStore.js';
import { differenceHash, hammingDistance, textSimilarity } from './compare.js';
import { logger } from '../observability/logger.js';

export const REVISIT_STRONG_FIELDS = ['upi_vpa', 'upi_uri', 'whatsapp', 'telegram', 'phone', 'email', 'bank_account', 'crypto_btc', 'crypto_eth', 'crypto_tron'];

/** Create due revisit jobs. Skips entirely while admission is paused or low-priority work is paused. */
export async function scheduleDueRevisits(pool: Pool, policy: Policy): Promise<{ created: number; skipped_reason: string | null }> {
  if (!policy.monitoring.actioned_target_revisit_enabled) return { created: 0, skipped_reason: 'monitoring disabled by policy' };
  const admission = await readAdmission(pool);
  if (admission.paused || admission.low_priority_paused) return { created: 0, skipped_reason: `admission paused: ${admission.reasons.join('; ')}` };
  await pool.query(`UPDATE monitoring_rules SET active = false, stopped_by = 'monitor:expired', stopped_at = now() WHERE active AND ends_at <= now()`);
  const { rows } = await pool.query<{ id: string; target_id: number; interval_hours: string; max_per_day: number; capture_variant: string; case_ref: string }>(
    `SELECT r.id, r.target_id, r.interval_hours, r.max_per_day, r.capture_variant, c.case_ref
       FROM monitoring_rules r JOIN cases c ON c.id = r.case_id WHERE r.active AND r.next_due_at <= now() ORDER BY r.next_due_at LIMIT 50`,
  );
  let created = 0;
  for (const r of rows) {
    await withTransaction(pool, async (client) => {
      const locked = await client.query('SELECT 1 FROM monitoring_rules WHERE id = $1 AND active AND next_due_at <= now() FOR UPDATE SKIP LOCKED', [r.id]);
      if (!locked.rowCount) return;
      // Per rule, and per target across every case's rules: several cases must not multiply visits to the site.
      const today = (await client.query<{ rule: number; target: number }>(
        `SELECT count(*) FILTER (WHERE scope->>'monitoring_rule_id' = $1)::int AS rule, count(*)::int AS target
           FROM jobs WHERE target_id = $2 AND scope ? 'monitoring_rule_id' AND created_at > now() - interval '24 hours'`, [r.id, r.target_id],
      )).rows[0]!;
      if (today.rule >= r.max_per_day || today.target >= policy.monitoring.max_auto_revisits_per_target_per_day) {
        await client.query(`UPDATE monitoring_rules SET next_due_at = now() + interval '1 hour' WHERE id = $1`, [r.id]);
        return;
      }
      // The same target can be in several cases: copy settings from a job of the rule's own case, and
      // link the revisit (case_ref and sources) to that case only.
      const base = (await client.query<{ id: number }>(
        `SELECT j.id FROM jobs j WHERE j.target_id = $1 AND j.parent_job_id IS NULL
            AND EXISTS (SELECT 1 FROM job_case_links l WHERE l.job_id = j.id AND l.case_ref = $2)
          ORDER BY j.created_at DESC LIMIT 1`, [r.target_id, r.case_ref],
      )).rows[0];
      if (!base) return;
      const ins = await client.query<{ id: number }>(
        `INSERT INTO jobs (target_id, profile, window_key, registrable_domain, priority, urgent, required_artifacts, capture_variant, scope, allowed_interactions, retention_class, case_ref, stage)
         SELECT target_id, profile, $2, registrable_domain, $3, false, required_artifacts, $4,
                jsonb_build_object('monitoring_rule_id', $5::text, 'requeued_from_job', id, 'child_pages_max', 0), allowed_interactions, retention_class, $6::text,
                CASE WHEN profile = 'data_triage' THEN 'http'::job_stage ELSE 'browser_primary'::job_stage END
           FROM jobs WHERE id = $1
         ON CONFLICT (target_id, profile, capture_variant, window_key) WHERE parent_job_id IS NULL DO NOTHING RETURNING id`,
        [base.id, `monitor:${r.id}:${new Date().toISOString()}`, policy.monitoring.revisit_priority, r.capture_variant, r.id, r.case_ref],
      );
      const jobId = ins.rows[0]?.id;
      if (!jobId) return;
      await client.query(
        `INSERT INTO job_sources (job_id, source_record_id)
         SELECT $2, js.source_record_id FROM job_sources js JOIN source_records s ON s.id = js.source_record_id
          WHERE js.job_id = $1 AND s.case_ref = $3 ON CONFLICT DO NOTHING`, [base.id, jobId, r.case_ref]);
      await client.query(
        `UPDATE monitoring_rules SET next_due_at = now() + make_interval(secs => $2::numeric * 3600), revisits = revisits + 1, last_job_id = $3 WHERE id = $1`,
        [r.id, r.interval_hours, jobId],
      );
      await audit(client, 'monitor', 'monitoring_revisit_scheduled', { rule_id: r.id }, { jobId, objectType: 'monitoring_rule', objectId: r.id });
      created += 1;
    });
  }
  return { created, skipped_reason: null };
}

interface AttemptFacts {
  id: string;
  outcome: string | null;
  classification: string | null;
  artifact_dir: string | null;
  final_url: string | null;
  identifiers: Set<string>;
  text: string | null;
  dhash: bigint | null;
}

async function attemptFacts(db: Queryable, root: string, attemptId: string, maxMp: number): Promise<AttemptFacts | null> {
  const a = (await db.query<{ id: string; outcome: string | null; classification: string | null; artifact_dir: string | null }>(
    'SELECT id, outcome, classification, artifact_dir FROM attempts WHERE id = $1', [attemptId],
  )).rows[0];
  if (!a) return null;
  const ids = (await db.query<{ k: string }>(
    `SELECT DISTINCT field_type || ':' || COALESCE(value_key, normalised_value) AS k FROM identifiers
      WHERE attempt_id = $1 AND field_type = ANY($2::text[]) AND display_context <> 'resource_string' AND validation_state <> 'format_invalid'`,
    [attemptId, REVISIT_STRONG_FIELDS],
  )).rows.map((r) => r.k);
  let finalUrl: string | null = null;
  let text: string | null = null;
  let dhash: bigint | null = null;
  if (a.artifact_dir) {
    try {
      assertSafeRelative(a.artifact_dir);
      const dir = join(root, a.artifact_dir);
      const m = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')) as { finalUrl: string | null; artifacts: { type: string; path: string | null }[] };
      finalUrl = m.finalUrl;
      const t = m.artifacts.find((x) => x.type === 'rendered_text' && x.path);
      if (t?.path) text = await readFile(join(dir, t.path), 'utf8');
      const shot = m.artifacts.find((x) => x.type === 'screenshot_settled' && x.path) ?? m.artifacts.find((x) => x.type === 'screenshot_early' && x.path);
      if (shot?.path) dhash = differenceHash(await readFile(join(dir, shot.path)), maxMp);
    } catch { /* comparison degrades gracefully; the observation states what was compared */ }
  }
  return { ...a, final_url: finalUrl, identifiers: new Set(ids), text, dhash };
}

export type MonitoringOutcome =
  | 'still_live' | 'observed_changed_content' | 'temporarily_unreachable' | 'challenged' | 'blocked_at_tested_vantage'
  | 'dns_not_resolving' | 'parked_or_suspended_page' | 'redirected_elsewhere' | 'inconclusive';

/** Classify a revisit against its baseline into one distinct outcome with explicit differences. */
export function classifyRevisit(base: AttemptFacts | null, now: AttemptFacts, targetDomain: string): { outcome: MonitoringOutcome; differences: Record<string, unknown> } {
  const c = (now.classification ?? '').split(':')[0];
  const diff: Record<string, unknown> = { outcome_before: base?.outcome ?? null, outcome_now: now.outcome, classification_now: now.classification };
  if (now.outcome === 'DNS_FAILURE') return { outcome: 'dns_not_resolving', differences: { ...diff, note: 'name did not resolve from the collector vantage (may be temporary or vantage-specific)' } };
  if (c === 'parked_domain' || c === 'hosting_suspended') return { outcome: 'parked_or_suspended_page', differences: { ...diff, note: 'placeholder page observed; provider confirmation is recorded separately by an analyst' } };
  if (c === 'isp_block_notice' || now.outcome === 'ACCESS_BLOCKED') return { outcome: 'blocked_at_tested_vantage', differences: { ...diff, note: 'blocked or denied at this vantage only; not proof of global unavailability' } };
  if (now.outcome === 'CHALLENGE_PAGE_CAPTURED') return { outcome: 'challenged', differences: diff };
  if (['ORIGIN_UNAVAILABLE', 'TLS_FAILURE', 'INFRASTRUCTURE_DEFERRED'].includes(now.outcome ?? '') || !now.outcome) return { outcome: 'temporarily_unreachable', differences: diff };
  if (now.outcome === 'NOT_FOUND') return { outcome: 'observed_changed_content', differences: { ...diff, note: 'exact path now returns not-found' } };
  const finalDomain = now.final_url ? (getDomain(new URL(now.final_url).hostname) ?? new URL(now.final_url).hostname) : null;
  if (finalDomain && finalDomain !== targetDomain) return { outcome: 'redirected_elsewhere', differences: { ...diff, final_url: now.final_url, final_domain: finalDomain } };
  if (!base) return { outcome: 'inconclusive', differences: { ...diff, note: 'no baseline capture to compare with' } };
  const added = [...now.identifiers].filter((x) => !base.identifiers.has(x));
  const removed = [...base.identifiers].filter((x) => !now.identifiers.has(x));
  const similarity = base.text !== null && now.text !== null ? Number(textSimilarity(base.text, now.text).toFixed(3)) : null;
  const imageDistance = base.dhash !== null && now.dhash !== null ? hammingDistance(base.dhash, now.dhash) : null;
  Object.assign(diff, { identifiers_added: added, identifiers_removed: removed, text_similarity: similarity, screenshot_dhash_distance: imageDistance });
  const sameLeads = added.length === 0 && removed.length === 0;
  const similarText = similarity === null || similarity >= 0.6;
  const similarImage = imageDistance === null || imageDistance <= 12;
  if (sameLeads && similarText && similarImage) return { outcome: 'still_live', differences: diff };
  // A changed payment/contact destination is a substantive finding, never normalised away.
  return { outcome: 'observed_changed_content', differences: { ...diff, ...(added.length || removed.length ? { note: 'displayed payment/contact identifiers changed' } : {}) } };
}

/** Record observations for finished revisit jobs that have none yet. */
export async function evaluatePendingRevisits(pool: Pool, policy: Policy, root: string): Promise<number> {
  const { rows } = await pool.query<{ job_id: number; rule_id: string; baseline_attempt: string | null; registrable_domain: string }>(
    `SELECT j.id AS job_id, r.id AS rule_id, r.baseline_attempt, j.registrable_domain
       FROM jobs j JOIN monitoring_rules r ON r.id::text = j.scope->>'monitoring_rule_id'
      WHERE j.state IN ('COMPLETE','PARTIAL','FAILED_FINAL','MANUAL_REVIEW')
        AND NOT EXISTS (SELECT 1 FROM monitoring_observations o WHERE o.job_id = j.id)
        AND NOT EXISTS (SELECT 1 FROM attempts a WHERE a.job_id = j.id AND a.extraction_state IN ('pending','running'))
      ORDER BY j.finished_at NULLS LAST LIMIT 50`,
  );
  let n = 0;
  for (const r of rows) {
    const latest = (await pool.query<{ id: string }>(`SELECT id FROM attempts WHERE job_id = $1 ORDER BY attempt_no DESC LIMIT 1`, [r.job_id])).rows[0];
    const now = latest ? await attemptFacts(pool, root, latest.id, policy.bounds.max_image_decode_megapixels) : null;
    const base = r.baseline_attempt ? await attemptFacts(pool, root, r.baseline_attempt, policy.bounds.max_image_decode_megapixels) : null;
    const result = now ? classifyRevisit(base, now, r.registrable_domain) : { outcome: 'temporarily_unreachable' as MonitoringOutcome, differences: { note: 'no attempt was recorded for the revisit job' } };
    await pool.query(
      `INSERT INTO monitoring_observations (rule_id, job_id, attempt_id, baseline_attempt, outcome_class, differences) VALUES ($1,$2,$3,$4,$5,$6)`,
      [r.rule_id, r.job_id, latest?.id ?? null, r.baseline_attempt, result.outcome, JSON.stringify(result.differences)],
    );
    await audit(pool, 'monitor', 'monitoring_observation_recorded', { rule_id: r.rule_id, outcome: result.outcome }, { jobId: r.job_id, attemptId: latest?.id ?? null, objectType: 'monitoring_rule', objectId: r.rule_id, outcome: result.outcome });
    n += 1;
  }
  return n;
}

/**
 * After extraction of a new capture: does it share unusual identifiers with an
 * actioned or judged-malicious target on a different registrable domain?
 */
export async function detectReappearance(pool: Pool, policy: Policy, attemptId: string): Promise<number> {
  if (!policy.monitoring.notify_on_resurrection) return 0;
  const { rows } = await pool.query<{ source_target_id: number; new_target_id: number; shared: string[] }>(
    `SELECT o.target_id AS source_target_id, i.target_id AS new_target_id, array_agg(DISTINCT i.field_type || ':' || COALESCE(i.value_key, i.normalised_value)) AS shared
       FROM identifiers i
       JOIN identifiers o ON o.field_type = i.field_type AND COALESCE(o.value_key, o.normalised_value) = COALESCE(i.value_key, i.normalised_value) AND o.target_id <> i.target_id
       JOIN targets ti ON ti.id = i.target_id JOIN targets tox ON tox.id = o.target_id
      WHERE i.attempt_id = $1 AND i.field_type = ANY($2::text[]) AND i.display_context <> 'resource_string' AND i.validation_state <> 'format_invalid'
        AND ti.registrable_domain <> tox.registrable_domain
        AND (EXISTS (SELECT 1 FROM notice_targets nt JOIN notices n ON n.id = nt.notice_id WHERE nt.target_id = o.target_id AND n.state NOT IN ('draft','withdrawn'))
             OR EXISTS (SELECT 1 FROM target_verdicts v WHERE v.target_id = o.target_id AND v.verdict = 'likely_malicious'))
      GROUP BY 1, 2`,
    [attemptId, REVISIT_STRONG_FIELDS],
  );
  let n = 0;
  for (const r of rows) {
    const strength = r.shared.length >= 2 ? 'strong_possible' : 'possible';
    const ins = await pool.query(
      `INSERT INTO reappearance_alerts (source_target_id, new_target_id, shared, strength) VALUES ($1,$2,$3,$4)
       ON CONFLICT (source_target_id, new_target_id) DO UPDATE SET shared = EXCLUDED.shared, strength = EXCLUDED.strength RETURNING id`,
      [r.source_target_id, r.new_target_id, JSON.stringify(r.shared), strength],
    );
    if (ins.rowCount) n += 1;
    await audit(pool, 'monitor', 'reappearance_alert', { source_target_id: r.source_target_id, new_target_id: r.new_target_id, shared: r.shared, strength }, { objectType: 'target', objectId: r.new_target_id });
  }
  if (n) logger.info({ attempt: attemptId, alerts: n }, 'reappearance alerts raised (evidence, not attribution)');
  return n;
}
