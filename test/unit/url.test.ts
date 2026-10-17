import { describe, expect, it } from 'vitest';
import { parseTargetInput, type ScopePolicy } from '../../src/importer/url.js';

const scope: ScopePolicy = { allowed_schemes: ['https', 'http'], allowed_ports: [80, 443], domain_seed_schemes: ['https', 'http'], allow_ip_literals: true };

function one(input: string, s = scope) {
  const r = parseTargetInput(input, s);
  if (!r.ok) throw new Error(r.reason);
  expect(r.candidates).toHaveLength(1);
  return r.candidates[0]!;
}

describe('target parsing (§6)', () => {
  it('preserves exact deep path, query order, tracking-looking fields and fragment route', () => {
    const c = one('https://pay.example.co.uk/v/claim?utm_source=sms&victim=8812&z=1&a=2#/case/42?step=2');
    expect(c.url).toBe('https://pay.example.co.uk/v/claim?utm_source=sms&victim=8812&z=1&a=2#/case/42?step=2');
    expect(c.pathAndQuery).toBe('/v/claim?utm_source=sms&victim=8812&z=1&a=2');
    expect(c.fragment).toBe('/case/42?step=2');
    expect(c.registrableDomain).toBe('example.co.uk');
    expect(c.dedupKey).toContain('utm_source=sms&victim=8812&z=1&a=2#/case/42');
  });

  it('keeps fragment-distinct URLs as distinct dedup keys', () => {
    expect(one('https://a.example.com/#/x').dedupKey).not.toBe(one('https://a.example.com/#/y').dedupKey);
  });

  it('stores IDNA and Unicode hostnames separately', () => {
    const c = one('https://bücher.example/kaufen');
    expect(c.hostnameAscii).toBe('xn--bcher-kva.example');
    expect(c.hostnameUnicode).toBe('bücher.example');
  });

  it('uses the Public Suffix List including private suffixes', () => {
    expect(one('https://scam-user.github.io/x').registrableDomain).toBe('scam-user.github.io');
    expect(one('https://a.b.example.com.au/').registrableDomain).toBe('example.com.au');
  });

  it('rejects user-info credential URLs and unsupported schemes with reasons', () => {
    expect(parseTargetInput('https://user:pass@evil.example/', scope)).toEqual({ ok: false, reason: 'userinfo_credentials_in_url' });
    expect(parseTargetInput('https://user@evil.example/', scope)).toEqual({ ok: false, reason: 'userinfo_credentials_in_url' });
    expect(parseTargetInput('ftp://files.example.com/', scope)).toEqual({ ok: false, reason: 'unsupported_scheme:ftp' });
    expect(parseTargetInput('javascript:alert(1)', scope)).toEqual({ ok: false, reason: 'unsupported_scheme:javascript' });
    expect(parseTargetInput('file:///etc/passwd', scope)).toEqual({ ok: false, reason: 'unsupported_scheme:file' });
  });

  it('treats IP literals and nonstandard ports as explicit policy cases', () => {
    const ip = one('http://203.0.113.9/login');
    expect(ip.isIpLiteral).toBe(true);
    expect(ip.registrableDomain).toBe('203.0.113.9');
    expect(parseTargetInput('https://example.com:8443/', scope)).toEqual({ ok: false, reason: 'port_not_permitted:8443' });
    const allowed = one('https://example.com:8443/', { ...scope, allowed_ports: [80, 443, 8443] });
    expect(allowed.nonstandardPort).toBe(true);
    expect(parseTargetInput('http://[::1]/', { ...scope, allow_ip_literals: false })).toEqual({ ok: false, reason: 'ip_literal_not_permitted' });
  });

  it('generates tracked HTTPS then HTTP candidates for a domain-only seed', () => {
    const r = parseTargetInput('login.example-bank.in', scope);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.candidates.map((c) => c.scheme)).toEqual(['https', 'http']);
    expect(r.candidates.every((c) => c.candidateOfInput === 'login.example-bank.in')).toBe(true);
    expect(r.candidates[0]!.inputKind).toBe('subdomain');
    expect(new Set(r.candidates.map((c) => c.dedupKey)).size).toBe(2);
  });

  it('rejects public-suffix-only and single-label hosts', () => {
    expect(parseTargetInput('https://co.uk/', scope).ok).toBe(false);
    expect(parseTargetInput('https://intranet/', scope)).toEqual({ ok: false, reason: 'single_label_hostname' });
  });

  it('accepts host:port seeds without mistaking the host for a scheme', () => {
    const r = parseTargetInput('example.com:443/path', scope);
    expect(r.ok).toBe(true);
  });
});
