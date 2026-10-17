/**
 * Target parsing and normalisation (blueprint §6).
 *
 * Rules implemented here:
 *  - Exact supplied paths, query strings (including order and "tracking-looking"
 *    fields) and fragments are preserved. Fragments may select a client-side route.
 *  - Original input, parsed URL, IDNA (ASCII) and Unicode hostnames, and a
 *    conservative deduplication key are kept separately.
 *  - Registrable-domain grouping uses the Public Suffix List (tldts).
 *  - IP literals and nonstandard ports are explicit policy cases, not parse errors.
 *  - Unsupported schemes and user-info credential URLs are rejected with a reason.
 *  - A domain-only seed yields one explicitly tracked candidate per scheme; HTTP
 *    content is never relabelled as an HTTPS observation.
 */
import { domainToASCII, domainToUnicode } from 'node:url';
import { isIP } from 'node:net';
import { parse as parseDomain } from 'tldts';

export interface ScopePolicy {
  allowed_schemes: readonly string[];
  allowed_ports: readonly number[];
  domain_seed_schemes: readonly string[];
  allow_ip_literals: boolean;
}

export interface TargetCandidate {
  inputKind: 'url' | 'domain' | 'subdomain' | 'ip';
  /** The supplied text this candidate was generated from when input was domain-only. */
  candidateOfInput: string | null;
  candidateScheme: string | null;
  url: string;
  scheme: string;
  hostnameAscii: string;
  hostnameUnicode: string;
  port: number | null;
  pathAndQuery: string;
  fragment: string | null;
  registrableDomain: string;
  isIpLiteral: boolean;
  nonstandardPort: boolean;
  dedupKey: string;
}

export type ParseResult =
  | { ok: true; candidates: TargetCandidate[] }
  | { ok: false; reason: string };

const DEFAULT_PORTS: Record<string, number> = { http: 80, https: 443 };
const SCHEME_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):/;

function reject(reason: string): ParseResult {
  return { ok: false, reason };
}

/**
 * Extract the raw fragment exactly as supplied. WHATWG URL parsing
 * percent-encodes some fragment characters; the original spelling is evidence.
 */
function rawFragment(input: string): string | null {
  const idx = input.indexOf('#');
  return idx === -1 ? null : input.slice(idx + 1);
}

/**
 * Extract the raw path+query as supplied (after authority, before '#').
 * WHATWG URL would re-encode characters and normalise dot segments; the
 * browser does its own normalisation on navigation, but we preserve what
 * the caller gave us separately from the parsed form.
 */
function rawPathAndQuery(input: string): string {
  const noFrag = input.split('#', 1)[0] ?? '';
  const afterScheme = noFrag.replace(SCHEME_RE, '');
  const withoutSlashes = afterScheme.replace(/^\/\//, '');
  const firstPathChar = withoutSlashes.search(/[/?]/);
  if (firstPathChar === -1) return '/';
  const rest = withoutSlashes.slice(firstPathChar);
  return rest.startsWith('?') ? `/${rest}` : rest;
}

function stripIpv6Brackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function registrableDomainFor(hostAscii: string, isIpLiteral: boolean): string | null {
  if (isIpLiteral) return hostAscii; // an IP literal is its own grouping key
  const info = parseDomain(hostAscii, { allowPrivateDomains: true, extractHostname: false });
  if (!info.domain || !info.publicSuffix) return null;
  // Group by ICANN registrable domain; private suffixes (e.g. github.io) yield the
  // user's subdomain as the registrable unit, which is the conservative choice.
  return info.domain;
}

function hasUserInfo(input: string): boolean {
  const afterScheme = input.replace(SCHEME_RE, '').replace(/^\/\//, '');
  const authority = afterScheme.split(/[/?#]/, 1)[0] ?? '';
  return authority.includes('@');
}

/**
 * Parse one supplied location. `kindHint` comes from an optional input column;
 * otherwise a value with a scheme is a URL and anything else is a domain seed.
 */
export function parseTargetInput(
  input: string,
  scope: ScopePolicy,
  kindHint?: 'url' | 'domain' | 'subdomain' | null,
): ParseResult {
  const original = input;
  const trimmed = input.trim();
  if (trimmed.length === 0) return reject('empty_input');
  if (trimmed.length > 8192) return reject('input_too_long');
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return reject('control_characters_in_input');
  if (/\s/.test(trimmed)) return reject('whitespace_inside_input');

  const schemeMatch = SCHEME_RE.exec(trimmed);
  // "example.com:8080/path" is a host:port, not a scheme named "example.com".
  const looksLikeHostPort = schemeMatch && /^[^:/]+:\d+(?:[/?#]|$)/.test(trimmed);
  const hasScheme = Boolean(schemeMatch) && !looksLikeHostPort && trimmed.includes('://') ;

  if (schemeMatch && !looksLikeHostPort && !trimmed.includes('://')) {
    // mailto:, javascript:, data:, file:, etc.
    return reject(`unsupported_scheme:${schemeMatch[1]!.toLowerCase()}`);
  }

  if (hasScheme) {
    const scheme = schemeMatch![1]!.toLowerCase();
    if (!scope.allowed_schemes.includes(scheme)) return reject(`unsupported_scheme:${scheme}`);
    if (hasUserInfo(trimmed)) return reject('userinfo_credentials_in_url');
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      return reject('unparseable_url');
    }
    const c = buildCandidate(parsed, scope, {
      inputKind: kindHint === 'domain' || kindHint === 'subdomain' ? kindHint : 'url',
      candidateOfInput: null,
      candidateScheme: null,
      pathAndQuery: rawPathAndQuery(trimmed),
      fragment: rawFragment(trimmed),
    });
    return typeof c === 'string' ? reject(c) : { ok: true, candidates: [c] };
  }

  // Domain / subdomain / IP seed with no scheme: generate tracked scheme candidates.
  if (hasUserInfo(`//${trimmed}`)) return reject('userinfo_credentials_in_url');
  const candidates: TargetCandidate[] = [];
  let lastError: string | null = null;
  for (const scheme of scope.domain_seed_schemes) {
    if (!scope.allowed_schemes.includes(scheme)) continue;
    let parsed: URL;
    try {
      parsed = new URL(`${scheme}://${trimmed}`);
    } catch {
      return reject('unparseable_domain');
    }
    const hostOnly = rawPathAndQuery(`${scheme}://${trimmed}`);
    const c = buildCandidate(parsed, scope, {
      inputKind: 'domain',
      candidateOfInput: original,
      candidateScheme: scheme,
      pathAndQuery: hostOnly,
      fragment: rawFragment(trimmed),
    });
    if (typeof c === 'string') {
      lastError = c;
      continue;
    }
    if (c.isIpLiteral) c.inputKind = 'ip';
    else if (kindHint === 'subdomain' || (kindHint !== 'domain' && c.hostnameAscii !== c.registrableDomain)) c.inputKind = 'subdomain';
    candidates.push(c);
  }
  if (candidates.length === 0) return reject(lastError ?? 'no_allowed_seed_scheme');
  return { ok: true, candidates };
}

function buildCandidate(
  parsed: URL,
  scope: ScopePolicy,
  extra: Pick<TargetCandidate, 'inputKind' | 'candidateOfInput' | 'candidateScheme' | 'pathAndQuery' | 'fragment'>,
): TargetCandidate | string {
  const scheme = parsed.protocol.replace(/:$/, '');
  if (!scope.allowed_schemes.includes(scheme)) return `unsupported_scheme:${scheme}`;
  if (parsed.username || parsed.password) return 'userinfo_credentials_in_url';

  const bareHost = stripIpv6Brackets(parsed.hostname);
  if (!bareHost) return 'missing_hostname';
  const ipVersion = isIP(bareHost);
  const isIpLiteral = ipVersion !== 0;
  if (isIpLiteral && !scope.allow_ip_literals) return 'ip_literal_not_permitted';

  let hostnameAscii: string;
  let hostnameUnicode: string;
  if (isIpLiteral) {
    hostnameAscii = bareHost.toLowerCase();
    hostnameUnicode = hostnameAscii;
  } else {
    hostnameAscii = domainToASCII(bareHost).toLowerCase();
    if (!hostnameAscii) return 'invalid_idna_hostname';
    hostnameUnicode = domainToUnicode(hostnameAscii) || hostnameAscii;
    if (hostnameAscii.endsWith('.')) hostnameAscii = hostnameAscii.slice(0, -1);
    if (!hostnameAscii.includes('.')) return 'single_label_hostname';
    if (hostnameAscii.length > 253) return 'hostname_too_long';
  }

  const registrableDomain = registrableDomainFor(hostnameAscii, isIpLiteral);
  if (!registrableDomain) return 'no_registrable_domain_public_suffix_only_or_unknown';

  const explicitPort = parsed.port ? Number(parsed.port) : null;
  const effectivePort = explicitPort ?? DEFAULT_PORTS[scheme]!;
  const nonstandardPort = effectivePort !== DEFAULT_PORTS[scheme];
  if (!scope.allowed_ports.includes(effectivePort)) return `port_not_permitted:${effectivePort}`;

  // Parsed URL for navigation. WHATWG serialisation keeps query order; the raw
  // spelling of path/query/fragment is stored separately.
  const url = parsed.href;
  const hostForKey = isIpLiteral && ipVersion === 6 ? `[${hostnameAscii}]` : hostnameAscii;
  // Conservative dedup key: scheme + host + effective port + exact path/query + fragment.
  // Nothing is stripped (tracking-looking parameters may be victim selectors).
  const dedupKey = `${scheme}://${hostForKey}:${effectivePort}${parsed.pathname}${parsed.search}${parsed.hash}`;

  return {
    ...extra,
    url,
    scheme,
    hostnameAscii,
    hostnameUnicode,
    port: explicitPort,
    registrableDomain,
    isIpLiteral,
    nonstandardPort,
    dedupKey,
  };
}
