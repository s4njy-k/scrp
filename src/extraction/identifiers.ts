/**
 * Conservative identifier extraction (blueprint §11). Ordered approach:
 * DOM text/attributes and observed JSON first; QR and OCR are separate
 * methods with their own provenance. Every value keeps raw and normalised
 * forms, method, source, surrounding context and validation state.
 */
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { btcAddressValid, ethAddressState, ifscValid, normalisePhone, tronAddressValid, UPI_HANDLES } from './validators.js';
import { findBrandClaims, type BrandDictionary } from '../investigation/brands.js';

export type FieldType =
  | 'email' | 'phone' | 'whatsapp' | 'telegram' | 'social_profile' | 'upi_vpa' | 'upi_uri' | 'qr_payload'
  | 'bank_account' | 'ifsc' | 'crypto_btc' | 'crypto_eth' | 'crypto_tron' | 'form_action' | 'api_endpoint'
  | 'analytics_id' | 'business_identity' | 'gstin' | 'cin' | 'fraud_claim_text'
  | 'adsense_id' | 'chat_widget_id' | 'app_store_link' | 'apk_link' | 'brand_claim' | 'sensitive_form' | 'dom_template_hash' | 'payment_gateway_id';

export const ALL_FIELDS: FieldType[] = [
  'email', 'phone', 'whatsapp', 'telegram', 'social_profile', 'upi_vpa', 'upi_uri', 'qr_payload', 'bank_account', 'ifsc',
  'crypto_btc', 'crypto_eth', 'crypto_tron', 'form_action', 'api_endpoint', 'analytics_id', 'business_identity', 'gstin', 'cin', 'fraud_claim_text',
  'adsense_id', 'chat_widget_id', 'app_store_link', 'apk_link', 'brand_claim', 'sensitive_form', 'dom_template_hash', 'payment_gateway_id',
];

/** Fields that are operator/infrastructure SIGNALS only: never treated as identity or used alone for attribution. */
export const SIGNAL_ONLY_FIELDS: ReadonlySet<FieldType> = new Set<FieldType>([
  'analytics_id', 'adsense_id', 'chat_widget_id', 'dom_template_hash', 'business_identity', 'brand_claim', 'fraud_claim_text', 'api_endpoint',
]);

export const EXTRACTOR_VERSION = 'extract-2026.10.3';

/** Heuristic confidence for a finding (provenance quality, not a probability of fraud). */
export function confidenceFor(i: Pick<Identifier, 'method' | 'validation' | 'displayContext'>): number {
  if (i.validation === 'format_invalid') return 0.1;
  const base: Record<string, number> = { qr: 0.95, dom: 0.85, attribute: 0.8, json: 0.7, http_body: 0.7, network: 0.6, ocr: 0.4 };
  let c = base[i.method] ?? 0.5;
  if (i.validation === 'uncertain') c -= 0.25;
  if (i.validation === 'unvalidated') c -= 0.1;
  if (i.displayContext === 'resource_string') c -= 0.25;
  return Math.max(0.05, Math.min(0.99, Number(c.toFixed(3))));
}

/** Stable per-field key used for analyst reviews and correlation across re-extraction. */
export function valueKey(i: Pick<Identifier, 'fieldType' | 'normalisedValue' | 'rawValue'>): string {
  const v = i.normalisedValue ?? i.rawValue;
  return ['email', 'upi_vpa', 'telegram', 'social_profile'].includes(i.fieldType) ? v.toLowerCase() : v;
}

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

// Unicode local parts and internationalised domains are accepted (RFC 6531/IDNA); the
// domain is normalised to its ASCII (punycode) form, the raw form is preserved.
const EMAIL_RE = /(?<![\p{L}\p{M}\p{N}._%+-])[\p{L}\p{M}\p{N}._%+-]{1,64}@(?:[\p{L}\p{M}\p{N}-]{1,63}\.)+[\p{L}\p{M}]{2,24}(?![\p{L}\p{M}\p{N}])/gu;
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
const ADSENSE_RE = /\bca-pub-\d{16}\b/gi;
/**
 * Payment-gateway merchant references as published by the gateways themselves
 * (checkout key IDs, hosted payment pages, merchant IDs in payment links).
 * Candidates only: aggregators, sub-merchants and shared test keys mean a match
 * is a lead for a lawful request to the gateway, never proof of the operator.
 */
const PAYMENT_GATEWAYS: [RegExp, string, string][] = [
  [/\brzp_(?:live|test)_[A-Za-z0-9]{14}\b/g, 'razorpay_key', 'Razorpay checkout key ID (public); identifies a merchant account at the gateway; test keys are not live accounts'],
  [/\b(?:rzp\.io\/(?:l|i|rzp)|pages\.razorpay\.com)\/([A-Za-z0-9_-]{3,64})/g, 'razorpay_page', 'Razorpay hosted payment page/link'],
  [/\bpaytm\.(?:com|in|me)\/[^\s"'<>]*?[?&]mid=([A-Za-z0-9]{8,24})\b/gi, 'paytm_mid', 'Paytm merchant ID in a Paytm link'],
  [/\bpayments\.cashfree\.com\/forms\/([A-Za-z0-9_-]{3,64})/g, 'cashfree_form', 'Cashfree hosted payment form'],
  [/\binstamojo\.com\/@([A-Za-z0-9_.-]{3,64})/g, 'instamojo', 'Instamojo payment handle'],
];
const CHAT_WIDGETS: [RegExp, string][] = [
  [/embed\.tawk\.to\/([a-f0-9]{24}(?:\/[a-z0-9]{6,12})?)/gi, 'tawk'],
  [/CRISP_WEBSITE_ID\s*=\s*["']([0-9a-f-]{36})["']/gi, 'crisp'],
  [/static\.zdassets\.com\/ekr\/snippet\.js\?key=([0-9a-f-]{36})/gi, 'zendesk'],
  [/code\.tidio\.co\/([a-z0-9]{20,40})\.js/gi, 'tidio'],
  [/__lc\.license\s*=\s*(\d{5,12})/gi, 'livechat'],
  [/widget\.intercom\.io\/widget\/([a-z0-9]{6,12})/gi, 'intercom'],
  [/wchat\.freshchat\.com[^"']*token["':=\s]+([0-9a-f-]{36})/gi, 'freshchat'],
];
const PLAY_RE = /play\.google\.com\/store\/apps\/details\?(?:[^"'\s<>]*&)?id=([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/g;
const APPLE_RE = /apps\.apple\.com\/[a-z]{2}\/app\/[^"'\s<>]*?\/id(\d{6,12})/g;
const GSTIN_RE = /\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b/g;
const CIN_RE = /\b[LU]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b/g;
const CLAIM_RE = /\b(kyc (update|pending|expired)|refund (process|initiated)|lottery|you have won|prize money|guaranteed (returns|profit)|double your (money|investment)|customer care (number|helpline)|account (will be )?(blocked|suspended)|electricity (connection|bill) (will be )?(disconnected|cut)|task[- ]based (job|earning)|work from home earn|investment plan|crypto (trading|mining) profit|loan approved|processing fee)\b/gi;

function push(out: Identifier[], src: TextSource, fieldType: FieldType, raw: string, normalised: string | null, validation: Validation, index: number, note?: string): void {
  let v = validation;
  if (src.fromOcr && v === 'format_valid' && !note?.includes('checksum verified')) v = 'uncertain';
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
    const at = raw.lastIndexOf('@');
    const domainAscii = domainToASCII(raw.slice(at + 1).toLowerCase());
    if (!domainAscii) continue;
    const norm = `${raw.slice(0, at).toLowerCase()}@${domainAscii}`;
    emails.add(raw.toLowerCase());
    emails.add(norm);
    push(out, src, 'email', raw, norm, 'format_valid', m.index, domainAscii !== raw.slice(at + 1).toLowerCase() ? 'internationalised domain normalised to ASCII (punycode)' : undefined);
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
    const st = ethAddressState(m[0]);
    const mixed = m[0].slice(2) !== m[0].slice(2).toLowerCase() && m[0].slice(2) !== m[0].slice(2).toUpperCase();
    push(out, src, 'crypto_eth', m[0], m[0].toLowerCase(), st, m.index,
      `EVM address: chain/network (Ethereum, BSC, Polygon, ...) and token are NOT inferable from the format${mixed ? (st === 'format_valid' ? '; EIP-55 checksum verified' : '; EIP-55 checksum FAILED') : '; no checksum present'}`);
  }
  for (const m of text.matchAll(TRON_RE)) {
    const ok = tronAddressValid(m[0]);
    if (!ok) continue;
    push(out, src, 'crypto_tron', m[0], m[0], 'format_valid', m.index, 'checksum verified');
  }
  for (const m of text.matchAll(GA_RE)) push(out, src, 'analytics_id', m[0], m[0], 'unvalidated', m.index, 'operator signal only; shared SDK defaults and agencies cause false clusters');
  for (const m of text.matchAll(FBPIXEL_RE)) push(out, src, 'analytics_id', m[0], `fbpixel:${m[1]}`, 'unvalidated', m.index, 'operator signal only');
  for (const m of text.matchAll(ADSENSE_RE)) push(out, src, 'adsense_id', m[0], m[0].toLowerCase(), 'unvalidated', m.index, 'operator signal only');
  for (const [re, vendor] of CHAT_WIDGETS) {
    for (const m of text.matchAll(re)) push(out, src, 'chat_widget_id', m[0], `${vendor}:${m[1]}`, 'unvalidated', m.index, 'operator signal only; widget accounts may be shared or resold');
  }
  for (const [re, gw, note] of PAYMENT_GATEWAYS) {
    for (const m of text.matchAll(re)) push(out, src, 'payment_gateway_id', m[0], `${gw}:${m[1] ?? m[0]}`, 'unvalidated', m.index, `${note}; candidate merchant reference, not verified with the gateway`);
  }
  for (const m of text.matchAll(PLAY_RE)) push(out, src, 'app_store_link', m[0], `play:${m[1]}`, 'unvalidated', m.index, 'package name can be spoofed; verified signer requires the APK bytes');
  for (const m of text.matchAll(APPLE_RE)) push(out, src, 'app_store_link', m[0], `appstore:id${m[1]}`, 'unvalidated', m.index);
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
  for (const m of html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+\.apk(?:\?[^"']*)?)["']/gi)) {
    const u = abs(m[1]!);
    if (u) push(identifiers, s, 'apk_link', m[1]!, u, 'unvalidated', m.index, 'download link observed; the file was not fetched or executed');
  }
  // Credential or payment-card collection forms (signals for review; nothing is submitted).
  const pw = /<input\b[^>]*\btype\s*=\s*["']?password/i.exec(html);
  if (pw) push(identifiers, s, 'sensitive_form', 'password field', 'password_field', 'unvalidated', pw.index, 'page contains a password input');
  const card = /<input\b[^>]*(?:autocomplete\s*=\s*["']cc-(?:number|csc|exp)|name\s*=\s*["'][^"']*(?:card_?num|cardnumber|cvv|cvc|expiry)[^"']*["'])/i.exec(html);
  if (card) push(identifiers, s, 'sensitive_form', 'payment card field', 'payment_card_field', 'unvalidated', card.index, 'page asks for payment-card details');
  const otp = /<input\b[^>]*(?:autocomplete\s*=\s*["']one-time-code|name\s*=\s*["'][^"']*\b(?:otp|mpin|upi_?pin)\b[^"']*["'])/i.exec(html);
  if (otp) push(identifiers, s, 'sensitive_form', 'OTP/PIN field', 'otp_or_pin_field', 'unvalidated', otp.index, 'page asks for an OTP, MPIN or UPI PIN');
  const og = /<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']{1,200})["']/i.exec(html);
  if (og) push(identifiers, s, 'business_identity', og[1]!, og[1]!.trim(), 'unvalidated', og.index, 'og:site_name (claimed)');
  const title = /<title[^>]*>([^<]{1,300})<\/title>/i.exec(html);
  if (title) push(identifiers, s, 'business_identity', title[1]!.trim(), title[1]!.trim(), 'unvalidated', title.index, 'document title (claimed)');
  return { identifiers, links, formActions };
}

/**
 * Structural template fingerprint: SHA-256 of the first 4000 tag names of the
 * DOM. Shared kits/templates produce equal hashes; so do generic site builders,
 * so this is a weak correlation signal only.
 */
export function domTemplateHash(html: string): string | null {
  const tags: string[] = [];
  for (const m of html.matchAll(/<([a-zA-Z][a-zA-Z0-9-]{0,30})\b/g)) {
    tags.push(m[1]!.toLowerCase());
    if (tags.length >= 4000) break;
  }
  if (tags.length < 30) return null;
  return createHash('sha256').update(tags.join(' ')).digest('hex');
}

/** Brand claims in visible text, as reviewable signals with the matched phrase. */
export function extractBrandClaims(src: TextSource, dict?: BrandDictionary): Identifier[] {
  const out: Identifier[] = [];
  for (const c of findBrandClaims(src.text, dict)) push(out, src, 'brand_claim', c.matched, c.brandId, 'unvalidated', c.index, `claims or mentions ${c.brandName}; mentions are not impersonation by themselves`);
  return out;
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
