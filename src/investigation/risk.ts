/**
 * Explainable, versioned risk assessment (blueprint v4 §25.2; checklist §5).
 *
 * The score is a TRIAGE AID for ordering analyst review, never a legal finding
 * and never sufficient for any external action. Capture quality, suspicion and
 * action eligibility are kept separate. Every signal carries a human-readable
 * label, its weight and the evidence it rests on; neutral infrastructure
 * signals (shared hosting/CDN, analytics IDs, registrar) are shown with zero
 * weight because they are weak evidence of common operators. A benign-context
 * checklist reduces the score and is shown alongside.
 */
import type { Queryable } from '../db/pool.js';
import { domainContext, findLookalikes, loadBrands, type BrandDictionary } from './brands.js';

export interface RiskSignal {
  code: string;
  label: string;
  weight: number;
  direction: 'raises' | 'lowers' | 'context';
  evidence: string[];
}

export interface RiskResult {
  policyVersion: string;
  score: number;
  band: 'insufficient_evidence' | 'low' | 'medium' | 'high';
  signals: RiskSignal[];
  benignContext: { code: string; label: string }[];
  conflicts: { code: string; label: string }[];
  captureQuality: 'content_captured' | 'partial' | 'not_target_content' | 'no_capture';
}

export interface RiskInput {
  hostname: string;
  outcome: string | null;
  classification: string | null;
  requiredSatisfied: boolean | null;
  identifiers: { field_type: string; normalised_value: string | null; validation_state: string; display_context: string; method: string; conflicts: unknown[] }[];
  /** Strong identifiers shared with targets an analyst judged suspicious/likely malicious (not FP/benign). */
  sharedWithJudged: { field_type: string; value: string; targets: number }[];
  registeredDaysAgo: number | null;
  priorFalsePositive: boolean;
}

const W = {
  payment_destination_displayed: 20,
  qr_payment_code: 10,
  deceptive_claims: 15,
  brand_on_unofficial_domain: 20,
  lookalike_domain: 20,
  sensitive_form: 15,
  apk_download: 10,
  messaging_only_contact: 5,
  coordinated_with_judged_site: 20,
  recently_registered: 5,
  official_domain: -45,
  government_domain: -30,
  affiliate_domain: -25,
  parked_page: -20,
};

export function assessRisk(i: RiskInput, policyVersion: string, dict: BrandDictionary = loadBrands()): RiskResult {
  const signals: RiskSignal[] = [];
  const benign: { code: string; label: string }[] = [];
  const conflicts: { code: string; label: string }[] = [];
  const has = (f: string, pred: (x: RiskInput['identifiers'][number]) => boolean = () => true) => i.identifiers.filter((x) => x.field_type === f && pred(x));
  const displayed = (x: { display_context: string }) => x.display_context === 'displayed';

  const c = (i.classification ?? '').split(':')[0];
  const captureQuality: RiskResult['captureQuality'] = !i.outcome ? 'no_capture'
    : c === 'parked_domain' || c === 'hosting_suspended' || ['CHALLENGE_PAGE_CAPTURED', 'ACCESS_BLOCKED', 'AUTH_REQUIRED', 'DNS_FAILURE', 'TLS_FAILURE', 'NOT_FOUND', 'ORIGIN_UNAVAILABLE', 'INFRASTRUCTURE_DEFERRED'].includes(i.outcome) ? 'not_target_content'
      : i.outcome === 'CONTENT_CAPTURED' && i.requiredSatisfied ? 'content_captured' : 'partial';

  const pay = [...has('upi_vpa', displayed), ...has('upi_uri', displayed), ...has('bank_account', displayed), ...has('crypto_btc', displayed), ...has('crypto_eth', displayed), ...has('crypto_tron', displayed)];
  if (pay.length) signals.push({ code: 'payment_destination_displayed', label: 'Payment destination shown to visitors', weight: W.payment_destination_displayed, direction: 'raises', evidence: pay.slice(0, 5).map((p) => `${p.field_type}:${p.normalised_value}`) });
  const qr = has('upi_uri', (x) => x.method === 'qr');
  if (qr.length) signals.push({ code: 'qr_payment_code', label: 'Payment QR code decoded from the page', weight: W.qr_payment_code, direction: 'raises', evidence: qr.slice(0, 3).map((q) => String(q.normalised_value)) });
  const claims = has('fraud_claim_text');
  if (claims.length) signals.push({ code: 'deceptive_claims', label: 'Language typical of fraud lures (KYC, refund, prize, guaranteed returns)', weight: W.deceptive_claims, direction: 'raises', evidence: [...new Set(claims.map((x) => String(x.normalised_value)))].slice(0, 5) });
  const forms = has('sensitive_form');
  if (forms.length) signals.push({ code: 'sensitive_form', label: 'Asks for passwords, card details, OTP or UPI PIN', weight: W.sensitive_form, direction: 'raises', evidence: [...new Set(forms.map((x) => String(x.normalised_value)))] });
  const apk = has('apk_link');
  if (apk.length) signals.push({ code: 'apk_download', label: 'Links to an Android APK download', weight: W.apk_download, direction: 'raises', evidence: apk.slice(0, 3).map((x) => String(x.normalised_value)) });
  const messaging = [...has('whatsapp'), ...has('telegram')];
  if (messaging.length && !has('email').length && !has('phone', displayed).length) {
    signals.push({ code: 'messaging_only_contact', label: 'Contact only through WhatsApp/Telegram', weight: W.messaging_only_contact, direction: 'raises', evidence: messaging.slice(0, 3).map((x) => String(x.normalised_value)) });
  }
  if (i.sharedWithJudged.length) {
    signals.push({ code: 'coordinated_with_judged_site', label: 'Shares a specific identifier with sites an analyst judged suspicious', weight: W.coordinated_with_judged_site, direction: 'raises',
      evidence: i.sharedWithJudged.slice(0, 5).map((x) => `${x.field_type}:${x.value} (${x.targets} other site${x.targets === 1 ? '' : 's'})`) });
  }

  const ctx = domainContext(i.hostname, dict);
  const brands = [...new Set(has('brand_claim').map((x) => String(x.normalised_value)))];
  if (ctx.official) {
    signals.push({ code: 'official_domain', label: `Official domain of ${ctx.official.brandName}`, weight: W.official_domain, direction: 'lowers', evidence: [ctx.registrableDomain] });
    benign.push({ code: 'legitimate_official', label: `Listed official domain of ${ctx.official.brandName} (a compromised official site still needs review)` });
  } else if (ctx.affiliate) {
    signals.push({ code: 'affiliate_domain', label: `Listed affiliate of ${ctx.affiliate.brandName}`, weight: W.affiliate_domain, direction: 'lowers', evidence: [ctx.registrableDomain] });
    benign.push({ code: 'authorised_affiliate', label: `Listed affiliate of ${ctx.affiliate.brandName}` });
  } else {
    const claimed = brands;
    if (claimed.length) {
      signals.push({ code: 'brand_on_unofficial_domain', label: 'Claims or mentions a protected brand on a domain not listed as official', weight: W.brand_on_unofficial_domain, direction: 'raises', evidence: claimed.slice(0, 5) });
      conflicts.push({ code: 'mention_vs_impersonation', label: 'A brand mention can be news, comparison, criticism or an authorised agent: confirm impersonation from the page itself' });
    }
    const look = findLookalikes(i.hostname, dict);
    if (look.length) signals.push({ code: 'lookalike_domain', label: 'Domain resembles a protected brand domain', weight: W.lookalike_domain, direction: 'raises', evidence: look.map((l) => `${l.kind}: ${l.candidateLabel} ~ ${l.comparedTo} (${l.brandName})`) });
  }
  if (ctx.governmentTld) {
    signals.push({ code: 'government_domain', label: 'Government namespace (gov.in / nic.in)', weight: W.government_domain, direction: 'lowers', evidence: [ctx.registrableDomain] });
    benign.push({ code: 'government_domain', label: 'Government namespace: treat as official unless compromise is evidenced' });
  }
  if (ctx.userContentPlatform) {
    signals.push({ code: 'user_content_platform', label: 'Hosted on a platform where anyone can publish', weight: 0, direction: 'context', evidence: [ctx.registrableDomain] });
    conflicts.push({ code: 'platform_hosting', label: 'The platform operator is not the content owner; route notices to the platform abuse channel' });
  }
  if (c === 'parked_domain' || c === 'hosting_suspended') {
    signals.push({ code: 'parked_page', label: c === 'parked_domain' ? 'Registrar/parking placeholder page observed' : 'Hosting suspension page observed', weight: W.parked_page, direction: 'lowers', evidence: [c] });
    benign.push({ code: 'parked_or_expired', label: 'Parked, expired or suspended placeholder: current content is not the reported site' });
  }
  if (i.registeredDaysAgo !== null && i.registeredDaysAgo <= 30) {
    signals.push({ code: 'recently_registered', label: `Domain registered ${i.registeredDaysAgo} day(s) ago (weak signal on its own)`, weight: W.recently_registered, direction: 'raises', evidence: [`rdap registration ${i.registeredDaysAgo}d`] });
  }
  for (const f of ['analytics_id', 'adsense_id', 'chat_widget_id', 'dom_template_hash']) {
    const xs = has(f);
    if (xs.length) signals.push({ code: `signal_${f}`, label: `${f.replace(/_/g, ' ')} present (low specificity; not scored)`, weight: 0, direction: 'context', evidence: xs.slice(0, 3).map((x) => String(x.normalised_value)) });
  }
  const conflicted = i.identifiers.filter((x) => Array.isArray(x.conflicts) && x.conflicts.length > 0);
  if (conflicted.length) conflicts.push({ code: 'identifier_conflict', label: 'A decoded QR destination differs from the displayed text; both are preserved for review' });
  if (i.priorFalsePositive) conflicts.push({ code: 'prior_false_positive', label: 'An analyst previously marked this target false positive/benign; automated escalation stays suppressed' });

  let score = Math.max(0, Math.min(100, signals.reduce((s, x) => s + x.weight, 0)));
  if (captureQuality === 'no_capture' || captureQuality === 'not_target_content') score = Math.min(score, 25);
  const band: RiskResult['band'] = captureQuality === 'no_capture' || (captureQuality === 'not_target_content' && signals.every((x) => x.direction !== 'raises'))
    ? 'insufficient_evidence' : score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';
  return { policyVersion, score, band, signals, benignContext: benign, conflicts, captureQuality };
}

/** Gather inputs from the ledger, assess, and append an immutable assessment row. */
export async function recordRiskAssessment(db: Queryable, policyVersion: string, attemptId: string, actor = 'risk-rules'): Promise<RiskResult & { id: number }> {
  const a = (await db.query<{ job_id: number; target_id: number; outcome: string | null; classification: string | null; required_satisfied: boolean | null; hostname: string; registrable_domain: string }>(
    `SELECT a.job_id, j.target_id, a.outcome, a.classification, a.required_satisfied, t.hostname_ascii AS hostname, t.registrable_domain
       FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN targets t ON t.id = j.target_id WHERE a.id = $1`, [attemptId],
  )).rows[0];
  if (!a) throw new Error(`attempt ${attemptId} not found`);
  const ids = (await db.query<RiskInput['identifiers'][number]>(
    'SELECT field_type, normalised_value, validation_state, display_context, method, conflicts FROM identifiers WHERE attempt_id = $1', [attemptId],
  )).rows;
  const shared = (await db.query<{ field_type: string; value: string; targets: number }>(
    `SELECT i.field_type, COALESCE(i.value_key, i.normalised_value) AS value, count(DISTINCT o.target_id)::int AS targets
       FROM identifiers i JOIN identifiers o ON o.field_type = i.field_type AND COALESCE(o.value_key, o.normalised_value) = COALESCE(i.value_key, i.normalised_value) AND o.target_id <> $2
       JOIN target_verdicts v ON v.target_id = o.target_id AND v.verdict IN ('suspicious', 'likely_malicious')
      WHERE i.attempt_id = $1 AND i.field_type IN ('upi_vpa','upi_uri','phone','whatsapp','telegram','bank_account','crypto_btc','crypto_eth','crypto_tron')
        AND i.display_context <> 'resource_string' AND i.validation_state <> 'format_invalid'
      GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10`, [attemptId, a.target_id],
  )).rows;
  const rdap = (await db.query<{ data: { events?: { action: string; date: string }[] } }>(
    `SELECT data FROM enrichment_results WHERE subject = $1 AND source = 'rdap_domain' AND status = 'ok' ORDER BY retrieved_at DESC LIMIT 1`, [a.registrable_domain],
  )).rows[0];
  const reg = rdap?.data.events?.find((e) => e.action === 'registration')?.date;
  const fp = await db.query(`SELECT 1 FROM target_verdicts WHERE target_id = $1 AND verdict IN ('false_positive', 'benign')`, [a.target_id]);
  const r = assessRisk({
    hostname: a.hostname, outcome: a.outcome, classification: a.classification, requiredSatisfied: a.required_satisfied, identifiers: ids,
    sharedWithJudged: shared, registeredDaysAgo: reg ? Math.floor((Date.now() - Date.parse(reg)) / 86_400_000) : null, priorFalsePositive: Boolean(fp.rowCount),
  }, policyVersion);
  const ins = await db.query<{ id: number }>(
    `INSERT INTO risk_assessments (target_id, job_id, attempt_id, policy_version, score, band, signals, benign_context, conflicts, capture_quality, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
    [a.target_id, a.job_id, attemptId, r.policyVersion, r.score, r.band, JSON.stringify(r.signals), JSON.stringify(r.benignContext), JSON.stringify(r.conflicts), r.captureQuality, actor],
  );
  return { ...r, id: ins.rows[0]!.id };
}
