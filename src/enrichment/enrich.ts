/**
 * Asynchronous infrastructure enrichment (blueprint v4 §25.4; checklist §4).
 *
 * Runs in the coordinator AFTER first evidence exists, never on the capture
 * path, without a browser permit. Every lookup leaves through the egress
 * gateway: DNS via its bounded /__dns endpoint, TLS via a CONNECT tunnel,
 * RDAP via the proxied HTTP client. Each result records its source, method,
 * observation point, retrieval time, TTL and source-specific errors. Registrant
 * identity is usually redacted and is never assumed; a CDN edge is not the
 * origin; any "origin IP" is a hypothesis. Certificate Transparency (crt.sh) is
 * a third-party service and is off unless the policy enables it.
 */
import { connect as netConnect } from 'node:net';
import ipaddr from 'ipaddr.js';
import { connect as tlsConnect, type PeerCertificate, type TLSSocket } from 'node:tls';
import { request } from 'undici';
import type { Policy } from '../config/policy.js';
import { createDispatcher, type EgressConfig } from '../acquisition/egress.js';
import type { Pool, Queryable } from '../db/pool.js';
import { systemDnsRecords, enrichmentNameRefused, type DnsRecordType } from '../gateway/server.js';
import { logger } from '../observability/logger.js';

export type EnrichmentSource = 'dns' | 'tls' | 'rdap_domain' | 'rdap_ip' | 'ct';

export interface EnrichmentRecord {
  subject_kind: 'domain' | 'host' | 'ip';
  subject: string;
  source: EnrichmentSource;
  status: 'ok' | 'error' | 'not_found' | 'redacted' | 'disabled';
  data: Record<string, unknown>;
  error: string | null;
  method: string;
}

// ---------------------------------------------------------------- DNS
export async function dnsLookup(egress: EgressConfig, name: string, type: DnsRecordType, timeoutMs: number): Promise<{ records: unknown[]; error: string | null }> {
  if (egress.proxyUrl) {
    const url = new URL('/__dns', egress.proxyUrl);
    url.searchParams.set('name', name);
    url.searchParams.set('type', type);
    const res = await request(url, { method: 'GET', headersTimeout: timeoutMs, bodyTimeout: timeoutMs });
    const body = (await res.body.json()) as { records?: unknown[]; error?: string };
    return { records: body.records ?? [], error: res.statusCode === 200 ? body.error ?? null : body.error ?? `gateway_status_${res.statusCode}` };
  }
  // Development only (COLLECTOR_ALLOW_DIRECT_EGRESS): same bounds, local resolver.
  if (type !== 'PTR' && enrichmentNameRefused(name)) return { records: [], error: enrichmentNameRefused(name) };
  try {
    return { records: (await systemDnsRecords(name, type)).slice(0, 100), error: null };
  } catch (err) {
    const code = (err as { code?: string }).code ?? '';
    return { records: [], error: code === 'ENOTFOUND' || code === 'ENODATA' ? 'no_records' : 'dns_error' };
  }
}

export async function dnsProfile(egress: EgressConfig, host: string, registrableDomain: string, timeoutMs: number): Promise<EnrichmentRecord> {
  const data: Record<string, unknown> = {};
  const errors: string[] = [];
  const plan: [string, DnsRecordType, 'host' | 'domain'][] = [[host, 'A', 'host'], [host, 'AAAA', 'host'], [host, 'CNAME', 'host'], [registrableDomain, 'MX', 'domain'], [registrableDomain, 'NS', 'domain'], [registrableDomain, 'TXT', 'domain']];
  for (const [name, type, role] of plan) {
    const r = await dnsLookup(egress, name, type, timeoutMs).catch((err: Error) => ({ records: [], error: err.message.slice(0, 100) }));
    data[`${role}_${type}`] = r.records;
    if (r.error && r.error !== 'no_records') errors.push(`${type}:${r.error}`);
  }
  const ips = [...((data.host_A as string[]) ?? []), ...((data.host_AAAA as string[]) ?? [])].slice(0, 4);
  const ptr: Record<string, unknown[]> = {};
  for (const ip of ips) ptr[ip] = (await dnsLookup(egress, ip, 'PTR', timeoutMs).catch(() => ({ records: [] }))).records;
  data.reverse_dns = ptr;
  data.spf = ((data.domain_TXT as string[]) ?? []).filter((t) => /^v=spf1/i.test(t));
  const empty = ips.length === 0 && !(data.host_CNAME as unknown[])?.length;
  return {
    subject_kind: 'host', subject: host, source: 'dns', status: errors.length && empty ? 'error' : empty ? 'not_found' : 'ok', data, error: errors.join('; ') || null,
    method: 'A/AAAA/CNAME (host), MX/NS/TXT (registrable domain), PTR (first addresses) via the egress gateway resolver',
  };
}

// ---------------------------------------------------------------- TLS
function certSummary(c: PeerCertificate & { issuerCertificate?: PeerCertificate }, authorized: boolean, authorizationError: string | null): Record<string, unknown> {
  return {
    subject: c.subject, issuer: c.issuer, valid_from: c.valid_from, valid_to: c.valid_to, serial_number: c.serialNumber,
    fingerprint_sha256: c.fingerprint256, subject_alt_names: (c.subjectaltname ?? '').split(/,\s*/).filter(Boolean).slice(0, 200),
    chain_trusted: authorized, chain_error: authorizationError,
    issuer_chain: (() => {
      const out: { subject: unknown; fingerprint_sha256: string }[] = [];
      type Linked = PeerCertificate & { issuerCertificate?: Linked };
      let cur = (c as Linked).issuerCertificate;
      while (cur && out.length < 5 && cur.fingerprint256 !== out[out.length - 1]?.fingerprint_sha256) {
        out.push({ subject: cur.subject, fingerprint_sha256: cur.fingerprint256 });
        if (cur.issuerCertificate === cur) break;
        cur = cur.issuerCertificate;
      }
      return out;
    })(),
  };
}

/** The live certificate presented to this vantage (distinct from CT history). */
export async function fetchCertificate(egress: EgressConfig, host: string, port: number, timeoutMs: number): Promise<EnrichmentRecord> {
  const base = { subject_kind: 'host' as const, subject: host, source: 'tls' as const, method: `TLS handshake to ${host}:${port} through the egress gateway (SNI ${host}); certificate not trusted by this lookup unless chain_trusted` };
  try {
    const socket = await new Promise<TLSSocket>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('tls_timeout')), timeoutMs);
      const startTls = (raw?: import('node:net').Socket) => {
        const s = tlsConnect({ ...(raw ? { socket: raw } : { host, port }), servername: host, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] });
        s.once('secureConnect', () => { clearTimeout(timer); resolve(s); });
        s.once('error', (e) => { clearTimeout(timer); reject(e); });
      };
      if (!egress.proxyUrl) return startTls();
      const proxy = new URL(egress.proxyUrl);
      const raw = netConnect(Number(proxy.port || 3128), proxy.hostname);
      raw.once('error', (e) => { clearTimeout(timer); reject(e); });
      raw.once('connect', () => raw.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
      let buf = '';
      const onData = (d: Buffer) => {
        buf += d.toString('latin1');
        const end = buf.indexOf('\r\n\r\n');
        if (end < 0) {
          if (buf.length > 8192) { raw.destroy(); reject(new Error('bad_proxy_response')); }
          return;
        }
        raw.off('data', onData);
        const status = Number(buf.split(' ')[1]);
        if (status !== 200) {
          const egressErr = /x-egress-error:\s*([a-z_]+)/i.exec(buf)?.[1] ?? `proxy_status_${status}`;
          raw.destroy();
          clearTimeout(timer);
          reject(new Error(egressErr));
          return;
        }
        startTls(raw);
      };
      raw.on('data', onData);
    });
    const cert = socket.getPeerCertificate(true) as PeerCertificate & { issuerCertificate?: PeerCertificate };
    const data = cert && Object.keys(cert).length ? certSummary(cert, socket.authorized, socket.authorizationError ? String(socket.authorizationError) : null) : {};
    data.protocol = socket.getProtocol();
    socket.destroy();
    return { ...base, status: Object.keys(data).length > 1 ? 'ok' : 'error', data, error: Object.keys(data).length > 1 ? null : 'no certificate presented' };
  } catch (err) {
    return { ...base, status: 'error', data: {}, error: (err as Error).message.slice(0, 200) };
  }
}

// ---------------------------------------------------------------- RDAP
interface Bootstrap { services: [string[], string[]][] }
const bootstrapCache = new Map<string, { at: number; data: Bootstrap }>();

async function getJson(egress: EgressConfig, url: string, timeoutMs: number, maxBytes: number): Promise<{ status: number; json: unknown }> {
  const dispatcher = createDispatcher(egress, { relaxedTls: false, connectTimeoutMs: timeoutMs });
  try {
    const res = await request(url, { method: 'GET', dispatcher, headersTimeout: timeoutMs, bodyTimeout: timeoutMs, headers: { accept: 'application/rdap+json, application/json' } });
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of res.body) {
      size += (c as Buffer).length;
      if (size > maxBytes) throw new Error('response_too_large');
      chunks.push(c as Buffer);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { status: res.statusCode, json };
  } finally {
    await dispatcher.close().catch(() => undefined);
  }
}

async function bootstrap(egress: EgressConfig, url: string, timeoutMs: number, maxBytes: number): Promise<Bootstrap> {
  const hit = bootstrapCache.get(url);
  if (hit && Date.now() - hit.at < 24 * 3600_000) return hit.data;
  const r = await getJson(egress, url, timeoutMs, maxBytes * 8);
  if (r.status !== 200 || !r.json || !Array.isArray((r.json as Bootstrap).services)) throw new Error(`rdap_bootstrap_unavailable (${r.status})`);
  bootstrapCache.set(url, { at: Date.now(), data: r.json as Bootstrap });
  return r.json as Bootstrap;
}

type Vcard = [string, Record<string, unknown>, string, unknown][];
interface RdapEntity { roles?: string[]; vcardArray?: [string, Vcard]; publicIds?: { type: string; identifier: string }[]; entities?: RdapEntity[]; handle?: string }

function vcardField(e: RdapEntity, field: string): string | null {
  const v = e.vcardArray?.[1]?.find((x) => x[0] === field);
  if (!v) return null;
  const val = v[3];
  return typeof val === 'string' ? val : Array.isArray(val) ? val.filter((x) => typeof x === 'string').join(' ') : null;
}

function findEntities(list: RdapEntity[] | undefined, role: string, depth = 0): RdapEntity[] {
  if (!list || depth > 3) return [];
  return list.flatMap((e) => [...(e.roles?.includes(role) ? [e] : []), ...findEntities(e.entities, role, depth + 1)]);
}

export function parseRdapDomain(j: Record<string, unknown>): Record<string, unknown> {
  const entities = (j.entities as RdapEntity[] | undefined) ?? [];
  const registrar = findEntities(entities, 'registrar')[0];
  const abuse = findEntities(registrar?.entities ?? entities, 'abuse')[0] ?? findEntities(entities, 'abuse')[0];
  const registrant = findEntities(entities, 'registrant')[0];
  const text = JSON.stringify(j);
  return {
    ldh_name: j.ldhName ?? null,
    registrar: registrar ? { name: vcardField(registrar, 'fn'), iana_id: registrar.publicIds?.find((p) => /iana/i.test(p.type))?.identifier ?? null, handle: registrar.handle ?? null } : null,
    abuse_contact: abuse ? { email: vcardField(abuse, 'email'), phone: vcardField(abuse, 'tel'), name: vcardField(abuse, 'fn') } : null,
    registrant: registrant ? { name: vcardField(registrant, 'fn'), organisation: vcardField(registrant, 'org'), country: null, note: 'as published by the registry; often redacted' } : null,
    events: ((j.events as { eventAction: string; eventDate: string }[] | undefined) ?? []).map((e) => ({ action: e.eventAction, date: e.eventDate })),
    status: j.status ?? [],
    nameservers: ((j.nameservers as { ldhName?: string }[] | undefined) ?? []).map((n) => n.ldhName).filter(Boolean),
    redacted: Array.isArray(j.redacted) || /redacted for privacy|REDACTED|data protected/i.test(text),
  };
}

const CDN_ORGS: [RegExp, string][] = [
  [/cloudflare/i, 'Cloudflare'], [/akamai/i, 'Akamai'], [/fastly/i, 'Fastly'], [/amazon|aws|cloudfront/i, 'Amazon (possibly CloudFront)'],
  [/google/i, 'Google'], [/microsoft|azure/i, 'Microsoft Azure'], [/incapsula|imperva/i, 'Imperva'], [/sucuri/i, 'Sucuri'], [/bunny/i, 'BunnyCDN'],
];

export function parseRdapIp(j: Record<string, unknown>): Record<string, unknown> {
  const entities = (j.entities as RdapEntity[] | undefined) ?? [];
  const reg = findEntities(entities, 'registrant')[0];
  const abuse = findEntities(entities, 'abuse')[0];
  const org = (reg && (vcardField(reg, 'fn') ?? vcardField(reg, 'org'))) ?? (j.name as string | undefined) ?? null;
  const cdn = CDN_ORGS.find(([re]) => re.test(`${org ?? ''} ${String(j.name ?? '')}`));
  return {
    network_name: j.name ?? null, handle: j.handle ?? null, start_address: j.startAddress ?? null, end_address: j.endAddress ?? null, country: j.country ?? null,
    organisation: org, abuse_contact: abuse ? { email: vcardField(abuse, 'email'), phone: vcardField(abuse, 'tel') } : null,
    cdn_or_proxy: cdn ? { likely: true, provider: cdn[1], note: 'heuristic from the network owner name: the edge network is not necessarily the origin host' } : { likely: false },
  };
}

export async function rdapDomain(egress: EgressConfig, policy: Policy, domain: string): Promise<EnrichmentRecord> {
  const e = policy.enrichment;
  const base = { subject_kind: 'domain' as const, subject: domain, source: 'rdap_domain' as const };
  try {
    const tld = domain.split('.').pop()!.toLowerCase();
    const boot = await bootstrap(egress, e.rdap_bootstrap_dns_url, e.timeout_seconds * 1000, e.max_response_kib * 1024);
    // Longest matching suffix wins (multi-label entries exist in the bootstrap).
    const labels = domain.toLowerCase().split('.');
    let service: string | null = null;
    for (let i = 0; i < labels.length && !service; i += 1) {
      const suffix = labels.slice(i).join('.');
      const hit = boot.services.find(([tlds]) => tlds.map((t) => t.toLowerCase()).includes(suffix));
      if (hit) service = hit[1].find((u) => u.startsWith('https://')) ?? hit[1][0] ?? null;
    }
    if (!service) return { ...base, status: 'not_found', data: { tld }, error: 'no RDAP service in the IANA bootstrap for this TLD', method: 'IANA RDAP bootstrap' };
    const url = `${service.replace(/\/?$/, '/')}domain/${encodeURIComponent(domain)}`;
    const r = await getJson(egress, url, e.timeout_seconds * 1000, e.max_response_kib * 1024);
    if (r.status === 404) return { ...base, status: 'not_found', data: { rdap_url: url }, error: 'registry has no record (may be unregistered or deleted)', method: `RDAP ${url}` };
    if (r.status !== 200 || !r.json) return { ...base, status: 'error', data: { rdap_url: url }, error: `rdap_status_${r.status}`, method: `RDAP ${url}` };
    const parsed = parseRdapDomain(r.json as Record<string, unknown>);
    return { ...base, status: parsed.redacted ? 'redacted' : 'ok', data: { ...parsed, rdap_url: url, registry_rdap_service: new URL(service).host }, error: null, method: `RDAP ${url} (via IANA bootstrap)` };
  } catch (err) {
    return { ...base, status: 'error', data: {}, error: (err as Error).message.slice(0, 200), method: 'RDAP' };
  }
}

function ipInRange(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/');
    const a = ipaddr.parse(ip);
    const r = ipaddr.parse(range!);
    return a.kind() === r.kind() && a.match(r, Number(bits));
  } catch {
    return false;
  }
}

export async function rdapIp(egress: EgressConfig, policy: Policy, ip: string): Promise<EnrichmentRecord> {
  const e = policy.enrichment;
  const base = { subject_kind: 'ip' as const, subject: ip, source: 'rdap_ip' as const };
  try {
    const v6 = ip.includes(':');
    const boot = await bootstrap(egress, v6 ? e.rdap_bootstrap_ipv6_url : e.rdap_bootstrap_ipv4_url, e.timeout_seconds * 1000, e.max_response_kib * 1024);
    const hit = boot.services.find(([ranges]) => ranges.some((c) => ipInRange(ip, c)));
    const service = hit?.[1].find((u) => u.startsWith('https://')) ?? hit?.[1][0];
    if (!service) return { ...base, status: 'not_found', data: {}, error: 'no RDAP service for this address', method: 'IANA RDAP bootstrap' };
    const url = `${service.replace(/\/?$/, '/')}ip/${encodeURIComponent(ip)}`;
    const r = await getJson(egress, url, e.timeout_seconds * 1000, e.max_response_kib * 1024);
    if (r.status !== 200 || !r.json) return { ...base, status: 'error', data: { rdap_url: url }, error: `rdap_status_${r.status}`, method: `RDAP ${url}` };
    return { ...base, status: 'ok', data: { ...parseRdapIp(r.json as Record<string, unknown>), rdap_url: url }, error: null, method: `RDAP ${url} (via IANA bootstrap)` };
  } catch (err) {
    return { ...base, status: 'error', data: {}, error: (err as Error).message.slice(0, 200), method: 'RDAP' };
  }
}

export async function ctCandidates(egress: EgressConfig, policy: Policy, domain: string): Promise<EnrichmentRecord> {
  const base = { subject_kind: 'domain' as const, subject: domain, source: 'ct' as const };
  if (!policy.enrichment.certificate_transparency) return { ...base, status: 'disabled', data: {}, error: null, method: 'certificate transparency disabled by policy (third-party service)' };
  const url = `${policy.enrichment.ct_search_url.replace(/\/?$/, '/')}?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
  try {
    const r = await getJson(egress, url, policy.enrichment.timeout_seconds * 1000, policy.enrichment.max_response_kib * 1024);
    if (r.status !== 200 || !Array.isArray(r.json)) return { ...base, status: 'error', data: {}, error: `ct_status_${r.status}`, method: url };
    const names = new Set<string>();
    for (const row of r.json as { name_value?: string }[]) for (const n of String(row.name_value ?? '').split('\n')) if (n.endsWith(domain) && names.size < 500) names.add(n.toLowerCase());
    return { ...base, status: 'ok', data: { candidates: [...names].sort(), note: 'historical certificate names: candidates only, not visited, possibly stale; not evidence of malicious hosts' }, error: null, method: url };
  } catch (err) {
    return { ...base, status: 'error', data: {}, error: (err as Error).message.slice(0, 200), method: url };
  }
}

// ---------------------------------------------------------------- worker
async function fresh(db: Queryable, subject: string, source: string): Promise<boolean> {
  const r = await db.query('SELECT 1 FROM enrichment_results WHERE subject = $1 AND source = $2 AND expires_at > now() LIMIT 1', [subject, source]);
  return Boolean(r.rowCount);
}

async function save(db: Queryable, r: EnrichmentRecord, observationPoint: string, cacheHours: number): Promise<void> {
  // Errors are retried sooner than successful lookups.
  const ttl = r.status === 'ok' || r.status === 'redacted' || r.status === 'not_found' ? cacheHours : Math.min(cacheHours, 2);
  await db.query(
    `INSERT INTO enrichment_results (subject_kind, subject, source, status, data, error, method, observation_point, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now() + make_interval(secs => $9::numeric * 3600))`,
    [r.subject_kind, r.subject, r.source, r.status, JSON.stringify(r.data), r.error, r.method, observationPoint, ttl],
  );
}

/** Enrich up to N targets that already have first evidence. Returns how many targets were processed. */
export async function enrichPending(pool: Pool, policy: Policy, egress: EgressConfig): Promise<number> {
  const e = policy.enrichment;
  if (!e.enabled) return 0;
  const { rows } = await pool.query<{ id: number; hostname_ascii: string; registrable_domain: string; scheme: string; port: number | null; is_ip_literal: boolean }>(
    `SELECT t.id, t.hostname_ascii, t.registrable_domain, t.scheme, t.port, t.is_ip_literal FROM targets t
      WHERE EXISTS (SELECT 1 FROM jobs j JOIN attempts a ON a.job_id = j.id WHERE j.target_id = t.id AND a.status IN ('committed','recovered'))
        AND (t.enrichment_done_at IS NULL OR t.enrichment_done_at < now() - make_interval(secs => $1::numeric * 3600))
        AND (t.enrichment_requested_at IS NULL OR t.enrichment_requested_at < now() - interval '10 minutes')
      ORDER BY t.enrichment_done_at NULLS FIRST, t.id LIMIT $2`,
    [e.cache_hours, e.targets_per_cycle],
  );
  const point = `egress gateway (${egress.vantage})`;
  const timeoutMs = e.timeout_seconds * 1000;
  for (const t of rows) {
    await pool.query('UPDATE targets SET enrichment_requested_at = now() WHERE id = $1', [t.id]);
    try {
      let ips: string[] = t.is_ip_literal ? [t.hostname_ascii.replace(/^\[|\]$/g, '')] : [];
      if (e.dns && !t.is_ip_literal && !(await fresh(pool, t.hostname_ascii, 'dns'))) {
        const d = await dnsProfile(egress, t.hostname_ascii, t.registrable_domain, timeoutMs);
        await save(pool, d, point, e.cache_hours);
      }
      if (!t.is_ip_literal) {
        const last = (await pool.query<{ data: { host_A?: string[]; host_AAAA?: string[] } }>(`SELECT data FROM enrichment_results WHERE subject = $1 AND source = 'dns' ORDER BY retrieved_at DESC LIMIT 1`, [t.hostname_ascii])).rows[0];
        ips = [...(last?.data.host_A ?? []), ...(last?.data.host_AAAA ?? [])];
      }
      if (e.tls && t.scheme === 'https' && !(await fresh(pool, t.hostname_ascii, 'tls'))) await save(pool, await fetchCertificate(egress, t.hostname_ascii, t.port ?? 443, timeoutMs), point, e.cache_hours);
      if (e.rdap && !t.is_ip_literal && !(await fresh(pool, t.registrable_domain, 'rdap_domain'))) await save(pool, await rdapDomain(egress, policy, t.registrable_domain), point, e.cache_hours);
      if (e.rdap && ips[0] && !(await fresh(pool, ips[0], 'rdap_ip'))) await save(pool, await rdapIp(egress, policy, ips[0]), point, e.cache_hours);
      if (!t.is_ip_literal && !(await fresh(pool, t.registrable_domain, 'ct'))) await save(pool, await ctCandidates(egress, policy, t.registrable_domain), point, e.cache_hours);
      await pool.query('UPDATE targets SET enrichment_done_at = now() WHERE id = $1', [t.id]);
    } catch (err) {
      logger.warn({ target: t.id, err: (err as Error).message }, 'enrichment failed for target');
    }
  }
  return rows.length;
}

export interface Addressee {
  role: 'registrar' | 'registry' | 'hosting_provider' | 'cdn' | 'app_distributor';
  name: string | null;
  contact: string | null;
  basis: string;
  confidence: 'observed' | 'heuristic';
  note: string;
}

/** Suggest the correct action addressee per role from enrichment; never treats roles as interchangeable. */
export function suggestAddressees(rows: { source: string; status: string; data: Record<string, unknown> }[], appLinks: string[]): Addressee[] {
  const out: Addressee[] = [];
  const rd = rows.find((r) => r.source === 'rdap_domain' && (r.status === 'ok' || r.status === 'redacted'))?.data;
  const ip = rows.find((r) => r.source === 'rdap_ip' && r.status === 'ok')?.data;
  if (rd) {
    const reg = rd.registrar as { name?: string } | null;
    const abuse = rd.abuse_contact as { email?: string; phone?: string } | null;
    out.push({ role: 'registrar', name: reg?.name ?? null, contact: abuse?.email ?? abuse?.phone ?? null, basis: 'RDAP registrar entity and its abuse contact', confidence: 'observed',
      note: 'Sponsoring registrar for the domain: contractual anti-abuse route.' });
    if (rd.registry_rdap_service) out.push({ role: 'registry', name: String(rd.registry_rdap_service), contact: null, basis: 'RDAP service that answered for the TLD', confidence: 'observed', note: 'Escalate only when the registrar route is exhausted or inappropriate, under the registry\'s documented policy.' });
  }
  if (ip) {
    const cdn = ip.cdn_or_proxy as { likely?: boolean; provider?: string } | undefined;
    const abuse = ip.abuse_contact as { email?: string } | null;
    out.push({
      role: cdn?.likely ? 'cdn' : 'hosting_provider', name: (ip.organisation as string | null) ?? (ip.network_name as string | null), contact: abuse?.email ?? null,
      basis: 'RDAP network owner of the first resolved address', confidence: cdn?.likely ? 'heuristic' : 'observed',
      note: cdn?.likely ? 'Likely a CDN/proxy edge: it is not the origin host or the registrar; use its abuse channel and do not request edge-IP blocking.' : 'Network owner of the observed address; the actual hosting customer may be a reseller.',
    });
  }
  for (const l of appLinks.slice(0, 3)) {
    out.push({ role: 'app_distributor', name: l.startsWith('play:') ? 'Google Play' : l.startsWith('appstore:') ? 'Apple App Store' : 'App distributor', contact: null, basis: `observed store link ${l}`, confidence: 'observed', note: 'Package names can be spoofed; confirm the listing before complaining.' });
  }
  return out;
}
