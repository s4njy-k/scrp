/**
 * Response/page signals used by the failure-specific router (blueprint §8).
 *
 * `cf-mitigated: challenge` and HTML-versus-expected-JSON mismatch recognise
 * Cloudflare challenge responses; DOM/page signals supplement them. Absence of
 * the header does not prove unrestricted content, and a Cloudflare server/CDN
 * header alone does not prove blocking.
 */

export interface ChallengeSignals {
  challenge: boolean;
  vendor: string | null;
  signals: string[];
}

const STRONG_TITLE_PATTERNS: [RegExp, string][] = [
  [/^\s*just a moment\.{0,3}\s*$/i, 'cloudflare'],
  [/attention required!? \| cloudflare/i, 'cloudflare'],
  [/^\s*please wait\.{0,3}\s*\|\s*cloudflare/i, 'cloudflare'],
  [/checking (your|if the site connection is) (browser|secure)/i, 'generic'],
  [/^\s*ddos-guard\s*$/i, 'ddos-guard'],
  [/^\s*verifying (you are|that you are) (human|not a robot)/i, 'generic'],
  [/^\s*human verification\s*$/i, 'generic'],
  [/^\s*security check\s*$/i, 'generic'],
];

const STRONG_BODY_PATTERNS: [RegExp, string][] = [
  [/\/cdn-cgi\/challenge-platform\/h\/[bg]\/orchestrate/i, 'cloudflare'],
  [/window\._cf_chl_opt\s*=/i, 'cloudflare'],
  [/id=["']challenge-form["']/i, 'cloudflare'],
  [/id=["']cf-challenge-running["']/i, 'cloudflare'],
  [/_Incapsula_Resource\?/i, 'imperva'],
  [/Request unsuccessful\. Incapsula incident ID/i, 'imperva'],
  [/geo\.captcha-delivery\.com/i, 'datadome'],
  [/id=["']px-captcha["']/i, 'perimeterx'],
  [/sucuri_cloudproxy_js/i, 'sucuri'],
  [/check\.ddos-guard\.net/i, 'ddos-guard'],
  [/awswaf\.com\/.*challenge\.js|AwsWafIntegration/i, 'aws-waf'],
];

const WEAK_BODY_PATTERNS: [RegExp, string][] = [
  [/challenges\.cloudflare\.com\/turnstile/i, 'turnstile_widget'],
  [/hcaptcha\.com\/1\/api\.js|class=["'][^"']*h-captcha/i, 'hcaptcha_widget'],
  [/google\.com\/recaptcha\/(api|enterprise)\.js|class=["'][^"']*g-recaptcha/i, 'recaptcha_widget'],
  [/enable javascript and cookies to continue/i, 'js_cookie_gate_text'],
];

export function headerValue(headers: Record<string, string | string[] | undefined>, name: string): string | null {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  if (!key) return null;
  const v = headers[key];
  return Array.isArray(v) ? v.join(', ') : v ?? null;
}

export function extractTitle(html: string): string | null {
  const m = /<title[^>]*>([\s\S]{0,500}?)<\/title>/i.exec(html);
  return m ? decodeEntities(m[1]!.replace(/\s+/g, ' ').trim()) : null;
}

export function decodeEntities(s: string): string {
  return s
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d{1,6});/g, (_, d: string) => safeCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]{1,6});/gi, (_, h: string) => safeCodePoint(parseInt(h, 16)));
}

function safeCodePoint(n: number): string {
  return n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : '�';
}

/** Approximate visible text of raw HTML (scripts/styles/templates removed). Bounded input. */
export function htmlToText(html: string, maxInput = 2_000_000): string {
  return decodeEntities(
    html
      .slice(0, maxInput)
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(script|style|noscript|template|svg)\b[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<[^>]+>/g, ' '),
  )
    .replace(/\s+/g, ' ')
    .trim();
}

export function detectChallenge(input: {
  headers?: Record<string, string | string[] | undefined>;
  html?: string | null;
  title?: string | null;
  visibleTextLength?: number;
  frameUrls?: string[];
}): ChallengeSignals {
  const signals: string[] = [];
  let vendor: string | null = null;
  let strong = false;
  const headers = input.headers ?? {};
  const html = input.html ?? '';
  const title = input.title ?? (html ? extractTitle(html) : null);

  const mitigated = headerValue(headers, 'cf-mitigated');
  if (mitigated && /challenge/i.test(mitigated)) {
    signals.push('header:cf-mitigated=challenge');
    vendor = 'cloudflare';
    strong = true;
  }
  if (title) {
    for (const [re, v] of STRONG_TITLE_PATTERNS) {
      if (re.test(title)) {
        signals.push(`title:${v}`);
        vendor ??= v;
        strong = true;
      }
    }
  }
  for (const [re, v] of STRONG_BODY_PATTERNS) {
    if (re.test(html)) {
      signals.push(`body:${v}`);
      vendor ??= v;
      strong = true;
    }
  }
  const weak: string[] = [];
  for (const [re, v] of WEAK_BODY_PATTERNS) if (re.test(html)) weak.push(v);
  for (const f of input.frameUrls ?? []) {
    if (/challenges\.cloudflare\.com/i.test(f)) weak.push('frame:cloudflare_challenge');
    if (/hcaptcha\.com/i.test(f)) weak.push('frame:hcaptcha');
    if (/google\.com\/recaptcha/i.test(f)) weak.push('frame:recaptcha');
  }
  signals.push(...weak.map((w) => `weak:${w}`));
  const textLength = input.visibleTextLength ?? (html ? htmlToText(html).length : 0);
  // A CAPTCHA widget embedded in an otherwise rich page (e.g. a login form) is not
  // a challenge interstitial; on a near-empty page it is.
  const weakChallenge = weak.length > 0 && textLength < 600;
  return { challenge: strong || weakChallenge, vendor: vendor ?? (weakChallenge ? 'captcha_widget' : null), signals };
}

/** A login/authentication wall: password field or explicit auth status. */
export function detectAuthWall(input: { status?: number | null; html?: string | null; hasPasswordField?: boolean; headers?: Record<string, string | string[] | undefined> }): string[] {
  const s: string[] = [];
  if (input.status === 401) s.push('status:401');
  if (input.headers && headerValue(input.headers, 'www-authenticate')) s.push('header:www-authenticate');
  if (input.hasPasswordField) s.push('dom:password_field');
  else if (input.html && /<input[^>]+type=["']?password/i.test(input.html)) s.push('html:password_field');
  return s;
}

/** A client-rendered application shell whose meaningful content needs JavaScript. */
export function detectJsShell(html: string, text = htmlToText(html)): string[] {
  const s: string[] = [];
  if (text.length >= 400) return s;
  const scriptCount = (html.match(/<script\b/gi) ?? []).length;
  if (/<div[^>]+id=["'](root|app|__next|__nuxt|svelte|main-app)["'][^>]*>\s*<\/div>/i.test(html)) s.push('empty_mount_node');
  if (/<noscript[^>]*>[\s\S]*?(enable|turn on)\s+javascript/i.test(html)) s.push('noscript_enable_js');
  if (/\bng-app\b|data-reactroot|__NEXT_DATA__|window\.__NUXT__/i.test(html)) s.push('framework_marker');
  if (scriptCount >= 3) s.push(`scripts:${scriptCount}`);
  if (text.length < 120) s.push(`low_text:${text.length}`);
  return s.length >= 2 || s.includes('empty_mount_node') ? s : [];
}

export function parseRetryAfter(value: string | null, now = Date.now()): number | null {
  if (!value) return null;
  const v = value.trim();
  if (/^\d+$/.test(v)) return Number(v);
  const t = Date.parse(v);
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.round((t - now) / 1000));
}

export type NetErrorKind = 'dns' | 'tls' | 'timeout' | 'refused' | 'reset' | 'proxy_denied' | 'proxy_tunnel' | 'aborted' | 'crash' | 'other';

/** Map Chromium/Firefox/Node network error text onto a router category. */
export function classifyNetError(message: string): NetErrorKind {
  const m = message.toUpperCase();
  if (/ERR_NAME_NOT_RESOLVED|NS_ERROR_UNKNOWN_HOST|ENOTFOUND|EAI_AGAIN|DNS_NXDOMAIN|DNS_TIMEOUT|DNS_ERROR/.test(m)) return 'dns';
  if (/ERR_CERT_|ERR_SSL_|SSL_ERROR|SEC_ERROR|MOZILLA_PKIX|CERT_|UNABLE_TO_VERIFY|SELF_SIGNED|DEPTH_ZERO|ERR_TLS|EPROTO|HANDSHAKE|ERR_BAD_SSL/.test(m)) return 'tls';
  if (/DESTINATION_DENIED|PORT_DENIED|SCHEME_DENIED/.test(m)) return 'proxy_denied';
  if (/ERR_TUNNEL_CONNECTION_FAILED|ERR_PROXY_CONNECTION_FAILED|NS_ERROR_PROXY/.test(m)) return 'proxy_tunnel';
  if (/TIMEOUT|TIMED_OUT|ETIMEDOUT|UND_ERR_HEADERS_TIMEOUT|UND_ERR_BODY_TIMEOUT|CONNECT_TIMEOUT/.test(m)) return 'timeout';
  if (/ERR_CONNECTION_REFUSED|ECONNREFUSED|NS_ERROR_CONNECTION_REFUSED|CONNECT_REFUSED/.test(m)) return 'refused';
  if (/ERR_CONNECTION_RESET|ECONNRESET|ERR_EMPTY_RESPONSE|NS_ERROR_NET_RESET|ERR_CONNECTION_CLOSED|UND_ERR_SOCKET|SOCKET HANG UP|NS_ERROR_NET_INTERRUPT/.test(m)) return 'reset';
  if (/TARGET CRASHED|PAGE CRASHED|RENDERER|TARGET PAGE, CONTEXT OR BROWSER HAS BEEN CLOSED/.test(m)) return 'crash';
  if (/ERR_ABORTED|NS_BINDING_ABORTED/.test(m)) return 'aborted';
  return 'other';
}
