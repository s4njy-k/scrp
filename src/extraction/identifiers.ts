/**
 * Conservative identifier extraction (blueprint §11). Ordered approach:
 * DOM text/attributes and observed JSON first; QR and OCR are separate
 * methods with their own provenance. Every value keeps raw and normalised
 * forms, method, source, surrounding context and validation state.
 */
import { btcAddressValid, ethAddressState, ifscValid, normalisePhone, tronAddressValid, UPI_HANDLES } from './validators.js';

export type FieldType =
  | 'email' | 'phone' | 'whatsapp' | 'telegram' | 'social_profile' | 'upi_vpa' | 'upi_uri' | 'qr_payload'
  | 'bank_account' | 'ifsc' | 'crypto_btc' | 'crypto_eth' | 'crypto_tron' | 'form_action' | 'api_endpoint'
  | 'analytics_id' | 'business_identity' | 'gstin' | 'cin' | 'fraud_claim_text';

export const ALL_FIELDS: FieldType[] = [
  'email', 'phone', 'whatsapp', 'telegram', 'social_profile', 'upi_vpa', 'upi_uri', 'qr_payload', 'bank_account', 'ifsc',
  'crypto_btc', 'crypto_eth', 'crypto_tron', 'form_action', 'api_endpoint', 'analytics_id', 'business_identity', 'gstin', 'cin', 'fraud_claim_text',
];

export type Validation = 'format_valid' | 'format_invalid' | 'uncertain' | 'unvalidated';
export type Method = 'dom' | 'attribute' | 'json' | 'http_body' | 'network' | 'qr' | 'ocr';

export interface Identifier {
  fieldType: FieldType;
  rawValue: string;
  normalisedValue: string | null;
  method: Method;
  sourceUrl: string | null;
  frameUrl: string | null;
  locator: string | null;
  bbox: Record<string, number> | null;
  context: string;
  artifactSha256: string | null;
  validation: Validation;
  displayContext: 'displayed' | 'resource_string' | 'unknown';
  note?: string;
}

export interface TextSource {
  text: string;
  method: Method;
  displayContext: Identifier['displayContext'];
  sourceUrl: string | null;
  frameUrl?: string | null;
  artifactSha256: string | null;
  locator?: string | null;
  bbox?: Record<string, number> | null;
  /** OCR text: never promote ambiguous values to confirmed identifiers. */
  fromOcr?: boolean;
}

function contextAround(text: string, index: number, length: number, radius = 80): string {
  return text.slice(Math.max(0, index - radius), Math.min(text.length, index + length + radius)).replace(/\s+/g, ' ').trim();
}

const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b/g;
const VPA_RE = /\b[A-Za-z0-9][A-Za-z0-9._-]{1,255}@[A-Za-z][A-Za-z0-9]{1,63}\b(?!\.[A-Za-z])/g;
const PHONE_RE = /(?<![\w/.-])(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,5}\)?[\s-]?)?\d{3,5}[\s-]?\d{4,6}(?![\w/-])/g;
const UPI_URI_RE = /upi:\/\/pay\?[^\s"'<>]+/gi;
const IFSC_RE = /\b[A-Z]{4}0[A-Z0-9]{6}\b/g;
const ACCOUNT_RE = /(?:a\/?c|acc(?:ount)?|khata)[\s.:#-]*(?:no\.?|number|num)?[\s.:#-]*(\d[\d\s-]{7,22}\d)/gi;
const BTC_RE = /\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const ETH_RE = /\b0x[a-fA-F0-9]{40}\b/g;
const TRON_RE = /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g;
const WHATSAPP_RE = /(?:https?:\/\/)?(?:wa\.me\/(\+?\d{6,15})|api\.whatsapp\.com\/send\/?\?[^\s"'<>]*phone=(\+?\d{6,15})|chat\.whatsapp\.com\/([A-Za-z0-9]{10,40})|whatsapp:\/\/send\?[^\s"'<>]*phone=(\+?\d{6,15}))/gi;
const TELEGRAM_RE = /(?:https?:\/\/)?(?:t\.me|telegram\.me|telegram\.dog)\/(\+?[A-Za-z0-9_]{4,64})|tg:\/\/resolve\?domain=([A-Za-z0-9_]{4,64})/gi;
const SOCIAL_RE = /https?:\/\/(?:www\.|m\.)?(facebook\.com|fb\.com|instagram\.com|twitter\.com|x\.com|youtube\.com|linkedin\.com|tiktok\.com|threads\.net)\/[A-Za-z0-9_.@\-/]{2,100}/gi;
const GA_RE = /\b(G-[A-Z0-9]{6,12}|UA-\d{4,10}-\d{1,4}|GTM-[A-Z0-9]{4,9}|AW-\d{6,12})\b/g;
const FBPIXEL_RE = /fbq\(\s*['"]init['"]\s*,\s*['"](\d{12,17})['"]/g;
const GSTIN_RE = /\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/g;
const CIN_RE = /\b[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b/g;
const CLAIM_RE = /\b(kyc (update|pending|expired)|refund (process|initiated)|lottery|you have won|prize money|guaranteed (returns|profit)|double your (money|investment)|customer care (number|helpline)|account (will be )?(blocked|suspended)|electricity (connection|bill) (will be )?(disconnected|cut)|task[- ]based (job|earning)|work from home earn|investment plan|crypto (trading|mining) profit|loan approved|processing fee)\b/gi;

function push(out: Identifier[], src: TextSource, fieldType: FieldType, raw: string, normalised: string | null, validation: Validation, index: number, note?: string): void {
  let v = validation;
  if (src.fromOcr && v === 'format_valid' && !note?.includes('checksum')) v = 'uncertain';
  out.push({
    fieldType, rawValue: raw.slice(0, 2000), normalisedValue: normalised, method: src.method, sourceUrl: src.sourceUrl,
    frameUrl: src.frameUrl ?? null, locator: src.locator ?? null, bbox: src.bbox ?? null,
    context: contextAround(src.text, index, raw.length), artifactSha256: src.artifactSha256, validation: v,
    displayContext: src.displayContext, ...(note ? { note } : {}),
  });
}

export function parseUpiUri(uri: string): Record<string, string> {
  try {
    const q = uri.replace(/^upi:\/\/pay\?/i, '');
    const params = new URLSearchParams(q.replace(/&amp;/g, '&'));
    const out: Record<string, string> = {};
    for (const [k, v] of params) if (['pa', 'pn', 'am', 'cu', 'tn', 'mc', 'tr', 'tid', 'url', 'mode', 'purpose'].includes(k)) out[k] = v.slice(0, 500);
    return out;
  } catch {
    return {};
  }
}

export function extractFromText(src: TextSource): Identifier[] {
  const out: Identifier[] = [];
  const text = src.text.slice(0, 5_000_000);
  const emails = new Set<string>();

  for (const m of text.matchAll(EMAIL_RE)) {
    const raw = m[0];
    if (/\.(png|jpe?g|gif|svg|webp|css|js)$/i.test(raw)) continue; // asset names like logo@2x.png
    emails.add(raw.toLowerCase());
    push(out, src, 'email', raw, raw.toLowerCase(), 'format_valid', m.index);
  }
  for (const m of text.matchAll(UPI_URI_RE)) {
    const params = parseUpiUri(m[0]);
    push(out, src, 'upi_uri', m[0], params.pa ? `upi://pay?pa=${params.pa.toLowerCase()}` : null, params.pa ? 'format_valid' : 'format_invalid', m.index, JSON.stringify(params));
    if (params.pa) push(out, src, 'upi_vpa', params.pa, params.pa.toLowerCase(), validateVpa(params.pa), m.index, 'from upi:// URI pa parameter');
  }
  for (const m of text.matchAll(VPA_RE)) {
    const raw = m[0];
    if (emails.has(raw.toLowerCase())) continue;
    const handle = raw.split('@')[1]!.toLowerCase();
    if (/^\d+x$/.test(handle) || /\.(png|jpe?g|svg|webp)$/i.test(raw)) continue;
    push(out, src, 'upi_vpa', raw, raw.toLowerCase(), validateVpa(raw), m.index);
  }
  for (const m of text.matchAll(PHONE_RE)) {
    const raw = m[0].trim();
    const digits = raw.replace(/\D/g, '');
    if (digits.length < 8 || digits.length > 15) continue;
    if (/^(19|20)\d{2}[\s-]?\d{2}[\s-]?\d{2}/.test(raw)) continue; // dates
    const p = normalisePhone(raw);
    if (p.state === 'format_invalid') continue;
    // Bare digit runs in resource strings are too noisy to report.
    if (src.displayContext === 'resource_string' && !raw.startsWith('+')) continue;
    push(out, src, 'phone', raw, p.normalised, p.state, m.index);
  }
  for (const m of text.matchAll(WHATSAPP_RE)) {
    const id = m[1] ?? m[2] ?? m[4] ?? (m[3] ? `group:${m[3]}` : null);
    const phone = id && !id.startsWith('group:') ? normalisePhone(id) : null;
    push(out, src, 'whatsapp', m[0], phone?.normalised ?? id, phone ? phone.state : 'unvalidated', m.index);
  }
  for (const m of text.matchAll(TELEGRAM_RE)) {
    const id = (m[1] ?? m[2] ?? '').toLowerCase();
    if (['share', 'joinchat', 'addstickers', 'iv'].includes(id)) continue;
    push(out, src, 'telegram', m[0], id ? `t.me/${id}` : null, 'unvalidated', m.index);
  }
  for (const m of text.matchAll(SOCIAL_RE)) {
    push(out, src, 'social_profile', m[0], m[0].toLowerCase().replace(/^https?:\/\/(www\.|m\.)?/, '').replace(/\/$/, ''), 'unvalidated', m.index);
  }
  for (const m of text.matchAll(IFSC_RE)) {
    push(out, src, 'ifsc', m[0], m[0], ifscValid(m[0]) ? 'format_valid' : 'format_invalid', m.index);
  }
  for (const m of text.matchAll(ACCOUNT_RE)) {
    const digits = m[1]!.replace(/\D/g, '');
    if (digits.length < 9 || digits.length > 18) continue;
    // Displayed account numbers stay 'unvalidated': no public checksum exists; OCR digits are uncertain.
    push(out, src, 'bank_account', m[1]!, digits, src.fromOcr ? 'uncertain' : 'unvalidated', m.index, 'keyword-anchored; pairing with a nearby IFSC is contextual, not verified');
  }
  for (const m of text.matchAll(BTC_RE)) {
    const ok = btcAddressValid(m[0]);
    if (!ok && src.displayContext === 'resource_string') continue;
    push(out, src, 'crypto_btc', m[0], m[0], ok ? 'format_valid' : 'format_invalid', m.index, ok ? 'checksum verified' : undefined);
  }
  for (const m of text.matchAll(ETH_RE)) {
    if (src.displayContext === 'resource_string') continue; // hashes/addresses in bundles are noise
    push(out, src, 'crypto_eth', m[0], m[0].toLowerCase(), ethAddressState(m[0]), m.index);
  }
  for (const m of text.matchAll(TRON_RE)) {
    const ok = tronAddressValid(m[0]);
    if (!ok) continue;
    push(out, src, 'crypto_tron', m[0], m[0], 'format_valid', m.index, 'checksum verified');
  }
  for (const m of text.matchAll(GA_RE)) push(out, src, 'analytics_id', m[0], m[0], 'unvalidated', m.index);
  for (const m of text.matchAll(FBPIXEL_RE)) push(out, src, 'analytics_id', m[0], `fbpixel:${m[1]}`, 'unvalidated', m.index);
  for (const m of text.matchAll(GSTIN_RE)) push(out, src, 'gstin', m[0], m[0], 'format_valid', m.index, 'format only; registration not verified');
  for (const m of text.matchAll(CIN_RE)) push(out, src, 'cin', m[0], m[0], 'format_valid', m.index, 'format only; registration not verified');
  if (src.displayContext !== 'resource_string') {
    for (const m of text.matchAll(CLAIM_RE)) push(out, src, 'fraud_claim_text', m[0], m[0].toLowerCase(), 'unvalidated', m.index, 'keyword signal only; not an assessment');
  }
  return out;
}

function validateVpa(vpa: string): Validation {
  const [user, handle] = vpa.split('@');
  if (!user || !handle || user.length < 2) return 'format_invalid';
  return UPI_HANDLES.has(handle.toLowerCase()) ? 'format_valid' : 'uncertain';
}

/** Attributes in raw/rendered HTML: tel:, mailto:, form actions, business identity meta. */
export function extractFromHtmlAttributes(html: string, baseUrl: string | null, src: Omit<TextSource, 'text' | 'method'>): { identifiers: Identifier[]; links: string[]; formActions: string[] } {
  const identifiers: Identifier[] = [];
  const links: string[] = [];
  const formActions: string[] = [];
  const s: TextSource = { ...src, text: html, method: 'attribute' };
  const abs = (v: string) => {
    try {
      return new URL(v.replace(/&amp;/g, '&'), baseUrl ?? undefined).href;
    } catch {
      return null;
    }
  };
  for (const m of html.matchAll(/href\s*=\s*["']\s*tel:([^"']{4,40})["']/gi)) {
    const p = normalisePhone(decodeURIComponent(m[1]!));
    push(identifiers, s, 'phone', `tel:${m[1]}`, p.normalised, p.state, m.index);
  }
  for (const m of html.matchAll(/href\s*=\s*["']\s*mailto:([^"'?]{3,200})/gi)) {
    const e = decodeURIComponent(m[1]!).trim();
    push(identifiers, s, 'email', `mailto:${e}`, e.toLowerCase(), /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(e) ? 'format_valid' : 'format_invalid', m.index);
  }
  for (const m of html.matchAll(/<form\b[^>]*\baction\s*=\s*["']([^"']*)["']/gi)) {
    const a = m[1]!.trim();
    if (!a || /^javascript:/i.test(a)) continue;
    const u = abs(a);
    if (u) {
      formActions.push(u);
      push(identifiers, s, 'form_action', a, u, 'unvalidated', m.index);
    }
  }
  const LINK_FIELDS = new Set<FieldType>(['whatsapp', 'telegram', 'social_profile', 'upi_uri', 'upi_vpa']);
  for (const m of html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"'#][^"']*)["']/gi)) {
    const raw = m[1]!.replace(/&amp;/g, '&');
    const u = abs(raw);
    if (u && /^https?:/i.test(u) && links.length < 2000) links.push(u);
    // Messaging/social/UPI destinations often appear only in link targets, not visible text.
    if (/wa\.me|whatsapp|t\.me|telegram|tg:|upi:|facebook|instagram|twitter|x\.com|youtube|linkedin|tiktok|threads/i.test(raw)) {
      for (const id of extractFromText({ ...s, text: raw })) {
        if (LINK_FIELDS.has(id.fieldType)) identifiers.push({ ...id, context: contextAround(html, m.index, m[0].length) });
      }
    }
  }
  const og = /<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']{1,200})["']/i.exec(html);
  if (og) push(identifiers, s, 'business_identity', og[1]!, og[1]!.trim(), 'unvalidated', og.index, 'og:site_name (claimed)');
  const title = /<title[^>]*>([^<]{1,300})<\/title>/i.exec(html);
  if (title) push(identifiers, s, 'business_identity', title[1]!.trim(), title[1]!.trim(), 'unvalidated', title.index, 'document title (claimed)');
  return { identifiers, links, formActions };
}

/** Collapse exact duplicates (same field, normalised value, method, source) keeping the first context. */
export function dedupeIdentifiers(list: Identifier[]): Identifier[] {
  const seen = new Set<string>();
  return list.filter((i) => {
    const key = `${i.fieldType}|${i.normalisedValue ?? i.rawValue}|${i.method}|${i.sourceUrl}|${i.displayContext}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
