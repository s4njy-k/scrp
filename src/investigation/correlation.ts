/**
 * Explainable correlation over the relational ledger (blueprint v4 §23.1
 * "relational graph", §25.3; checklist §5). No graph database: edges are
 * computed from typed identifiers with provenance, weighted by specificity and
 * rarity, and grouped only on MULTIPLE corroborating uncommon identifiers.
 * Output is always "possible relationship"; confirmed common control is an
 * analyst decision, never computed.
 */
import type { Queryable } from '../db/pool.js';

/** Specificity of a shared value as evidence of a common operator. */
const FIELD_WEIGHT: Record<string, { weight: number; strength: 'strong' | 'medium' | 'weak'; edge: string }> = {
  upi_vpa: { weight: 5, strength: 'strong', edge: 'paid_to_candidate' },
  upi_uri: { weight: 5, strength: 'strong', edge: 'paid_to_candidate' },
  bank_account: { weight: 5, strength: 'strong', edge: 'paid_to_candidate' },
  crypto_btc: { weight: 5, strength: 'strong', edge: 'paid_to_candidate' },
  crypto_eth: { weight: 4, strength: 'strong', edge: 'paid_to_candidate' },
  crypto_tron: { weight: 5, strength: 'strong', edge: 'paid_to_candidate' },
  whatsapp: { weight: 4, strength: 'strong', edge: 'contact_displayed' },
  telegram: { weight: 4, strength: 'strong', edge: 'contact_displayed' },
  phone: { weight: 3, strength: 'medium', edge: 'contact_displayed' },
  email: { weight: 3, strength: 'medium', edge: 'contact_displayed' },
  gstin: { weight: 2, strength: 'medium', edge: 'claimed_identity' },
  chat_widget_id: { weight: 2, strength: 'medium', edge: 'shared_widget' },
  apk_link: { weight: 2, strength: 'medium', edge: 'distributes_app' },
  payment_gateway_id: { weight: 3, strength: 'medium', edge: 'gateway_merchant_candidate' },
  app_store_link: { weight: 1, strength: 'weak', edge: 'distributes_app' },
  analytics_id: { weight: 1, strength: 'weak', edge: 'shared_analytics_id' },
  adsense_id: { weight: 1, strength: 'weak', edge: 'shared_analytics_id' },
  dom_template_hash: { weight: 0.5, strength: 'weak', edge: 'shared_template' },
};

/** A value seen on more than this many targets is treated as common (shared service, template default, aggregator). */
export const COMMON_VALUE_TARGETS = 50;

export interface RelatedTarget {
  target_id: number;
  url: string;
  registrable_domain: string;
  verdict: string;
  score: number;
  relationship: 'possible_relationship' | 'weak_signal_only';
  edges: { field_type: string; value: string; edge: string; strength: string; weight: number; targets_with_value: number; first_seen: string | null; last_seen: string | null }[];
  explanation: string;
  contradictions: string[];
}

export async function relatedTargets(db: Queryable, targetId: number, scope: { userId: string; all: boolean }, limit = 50): Promise<RelatedTarget[]> {
  const fields = Object.keys(FIELD_WEIGHT);
  const { rows } = await db.query<{ target_id: number; url: string; registrable_domain: string; field_type: string; value: string; first_seen: Date | null; last_seen: Date | null; targets_with_value: number; verdict: string | null }>(
    `WITH mine AS (
       SELECT DISTINCT i.field_type, COALESCE(i.value_key, i.normalised_value) AS value FROM identifiers i
        WHERE i.target_id = $1 AND i.field_type = ANY($2::text[]) AND i.validation_state <> 'format_invalid'
          AND (i.display_context <> 'resource_string' OR i.field_type IN ('analytics_id','adsense_id','chat_widget_id','dom_template_hash','apk_link','payment_gateway_id'))),
     visible AS (
       SELECT j.id FROM jobs j WHERE $4::boolean OR EXISTS (SELECT 1 FROM job_case_links l JOIN cases c ON c.case_ref = l.case_ref JOIN case_members m ON m.case_id = c.id WHERE l.job_id = j.id AND m.user_id = $3::uuid)),
     freq AS (
       SELECT i.field_type, COALESCE(i.value_key, i.normalised_value) AS value, count(DISTINCT i.target_id)::int AS n
         FROM identifiers i JOIN mine USING (field_type) JOIN visible vv ON vv.id = i.job_id
        WHERE COALESCE(i.value_key, i.normalised_value) = mine.value GROUP BY 1, 2)
     SELECT o.target_id, t.url, t.registrable_domain, o.field_type, COALESCE(o.value_key, o.normalised_value) AS value,
            min(o.observed_at) AS first_seen, max(o.observed_at) AS last_seen, f.n AS targets_with_value, v.verdict
       FROM identifiers o JOIN mine m ON m.field_type = o.field_type AND m.value = COALESCE(o.value_key, o.normalised_value)
       JOIN visible vj ON vj.id = o.job_id JOIN targets t ON t.id = o.target_id
       JOIN freq f ON f.field_type = o.field_type AND f.value = m.value
       LEFT JOIN target_verdicts v ON v.target_id = o.target_id
      WHERE o.target_id <> $1 AND t.registrable_domain <> (SELECT registrable_domain FROM targets WHERE id = $1)
      GROUP BY o.target_id, t.url, t.registrable_domain, o.field_type, COALESCE(o.value_key, o.normalised_value), f.n, v.verdict
      LIMIT 5000`,
    [targetId, fields, scope.userId, scope.all],
  );
  const byTarget = new Map<number, RelatedTarget>();
  for (const r of rows) {
    const fw = FIELD_WEIGHT[r.field_type]!;
    // Rarity: values shared by many sites carry little weight (common services, aggregators, kits).
    const rarity = r.targets_with_value > COMMON_VALUE_TARGETS ? 0.1 : r.targets_with_value > 10 ? 0.5 : 1;
    const weight = Number((fw.weight * rarity).toFixed(2));
    const t = byTarget.get(r.target_id) ?? { target_id: r.target_id, url: r.url, registrable_domain: r.registrable_domain, verdict: r.verdict ?? 'unreviewed', score: 0, relationship: 'weak_signal_only' as const, edges: [], explanation: '', contradictions: [] };
    t.edges.push({ field_type: r.field_type, value: r.value, edge: fw.edge, strength: rarity < 1 ? 'weak' : fw.strength, weight, targets_with_value: r.targets_with_value,
      first_seen: r.first_seen?.toISOString() ?? null, last_seen: r.last_seen?.toISOString() ?? null });
    byTarget.set(r.target_id, t);
  }
  const out: RelatedTarget[] = [];
  for (const t of byTarget.values()) {
    const strong = t.edges.filter((e) => e.strength === 'strong');
    const medium = t.edges.filter((e) => e.strength === 'medium');
    t.score = Number(t.edges.reduce((s, e) => s + e.weight, 0).toFixed(2));
    // Grouping rule: at least two distinct uncommon identifiers, at least one of them strong.
    const corroborated = strong.length >= 2 || (strong.length >= 1 && medium.length >= 1);
    t.relationship = corroborated ? 'possible_relationship' : 'weak_signal_only';
    t.explanation = corroborated
      ? `Shares ${strong.length} strong and ${medium.length} medium-specificity identifier(s): ${[...strong, ...medium].slice(0, 4).map((e) => `${e.field_type} ${e.value}`).join('; ')}. Possible relationship only; common control is not established.`
      : `Only ${t.edges.length} low-specificity or single shared value(s) (${t.edges.slice(0, 3).map((e) => e.field_type).join(', ')}). Not sufficient to group.`;
    if (t.verdict === 'false_positive' || t.verdict === 'benign') t.contradictions.push(`The related site is marked ${t.verdict} by an analyst.`);
    if (t.edges.some((e) => e.targets_with_value > COMMON_VALUE_TARGETS)) t.contradictions.push('At least one shared value appears on many sites (common service or template), reducing its weight.');
    out.push(t);
  }
  return out.sort((a, b) => (a.relationship === b.relationship ? b.score - a.score : a.relationship === 'possible_relationship' ? -1 : 1)).slice(0, limit);
}
