/**
 * Analyst decisions and false-positive suppression (checklist §5 "mandatory
 * false positive / benign / uncertain / needs review outcome with reason code
 * ... suppression of repeated auto-escalation and an authorised override on
 * new evidence"; blueprint v4 §25.2).
 */
import type { Queryable } from '../db/pool.js';

export const DECISION_VERDICT: Record<string, string> = {
  retain: 'suspicious',
  investigate: 'suspicious',
  confirm_suspicious: 'suspicious',
  likely_malicious: 'likely_malicious',
  false_positive: 'false_positive',
  benign: 'benign',
  inconclusive: 'inconclusive',
  recapture: 'inconclusive',
  escalate_for_approval: 'likely_malicious',
  override_suppression: 'suspicious',
};

/** Reason codes: decisions with consequences must say why (checklist §7). */
export const REASON_CODES: Record<string, string> = {
  payment_redirection: 'Displays payment destination (UPI/bank/crypto) in a deceptive context',
  brand_impersonation: 'Impersonates a bank, government body or brand without authorisation evidence',
  complaint_corroborated: 'Corroborated by a linked complaint/case record',
  coordinated_contacts: 'Contact identifiers reused across corroborated fraudulent sites',
  deceptive_claims: 'Deceptive claims (KYC/refund/lottery/investment returns)',
  phishing_form: 'Credential or payment-card collection form',
  malware_distribution: 'Distributes or links to a suspicious application/download',
  legitimate_official: 'Official or authorised site of the organisation',
  authorised_affiliate: 'Authorised affiliate, agent or provider',
  parked_or_expired: 'Parked, expired or registrar placeholder page',
  security_research: 'Commentary, criticism, journalism or security research',
  shared_infrastructure_only: 'Only shared hosting/CDN/analytics signals; no corroborated link',
  crawler_error: 'Capture error or misleading crawler output',
  insufficient_evidence: 'Not enough evidence to decide',
  content_changed: 'Content changed since the earlier observation',
  needs_recapture: 'Needs a fresh capture (profile, vantage or timing)',
  new_evidence: 'New evidence justifies revisiting an earlier decision',
  other: 'Other (explain in the reason text)',
};

export interface SuppressionState {
  suppressed: boolean;
  decision_id: number | null;
  decided_at: Date | null;
  verdict: string | null;
  /** Attempts committed after the suppressing decision: the only basis for an override. */
  newer_attempts: string[];
  overridden_by: number | null;
}

/**
 * A target whose latest standing verdict is false_positive or benign is
 * suppressed: no external action may be created for it. An override must be
 * an explicit 'override_suppression' decision citing an attempt that started
 * after the suppressing decision.
 */
export async function suppressionState(db: Queryable, targetId: number): Promise<SuppressionState> {
  const fp = (await db.query<{ id: number; created_at: Date; verdict: string }>(
    `SELECT id, created_at, verdict FROM analyst_decisions WHERE target_id = $1 AND decision IN ('false_positive', 'benign') ORDER BY id DESC LIMIT 1`, [targetId],
  )).rows[0];
  if (!fp) return { suppressed: false, decision_id: null, decided_at: null, verdict: null, newer_attempts: [], overridden_by: null };
  const override = (await db.query<{ id: number }>(
    `SELECT d.id FROM analyst_decisions d JOIN attempts a ON a.id = d.new_evidence_attempt
      WHERE d.target_id = $1 AND d.decision = 'override_suppression' AND d.id > $2 AND a.started_at > $3 ORDER BY d.id DESC LIMIT 1`,
    [targetId, fp.id, fp.created_at],
  )).rows[0];
  const newer = (await db.query<{ id: string }>(
    `SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id
      WHERE j.target_id = $1 AND a.started_at > $2 AND a.status IN ('committed', 'recovered') ORDER BY a.started_at DESC LIMIT 20`,
    [targetId, fp.created_at],
  )).rows.map((r) => r.id);
  return { suppressed: !override, decision_id: fp.id, decided_at: fp.created_at, verdict: fp.verdict, newer_attempts: newer, overridden_by: override?.id ?? null };
}
