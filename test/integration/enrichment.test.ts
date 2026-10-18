/**
 * Asynchronous enrichment and monitoring comparison (checklist §4, §8):
 * gateway-mediated DNS with internal-namespace refusal, TLS certificate through
 * a CONNECT tunnel, RDAP via a (local) bootstrap with redaction and CDN
 * heuristics, role-specific addressee suggestions, and revisit classification.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { join } from 'node:path';
import { request } from 'undici';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EgressGateway } from '../../src/gateway/server.js';
import { classifyAddress } from '../../src/gateway/policy.js';
import { dnsProfile, fetchCertificate, rdapDomain, rdapIp, suggestAddressees } from '../../src/enrichment/enrich.js';
import { classifyRevisit } from '../../src/monitoring/monitor.js';
import { differenceHash, hammingDistance, textSimilarity } from '../../src/monitoring/compare.js';
import { tempRoot, testPolicy } from '../helpers.js';

describe('enrichment through the egress gateway', () => {
  let gw: EgressGateway;
  let gwPort: number;
  let tlsServer: Server;
  let tlsPort: number;
  let rdap: Server;
  let rdapPort: number;
  let cleanup: () => Promise<void>;

  beforeAll(async () => {
    const t = await tempRoot();
    cleanup = t.cleanup;
    const key = join(t.root, 'k.pem');
    const crt = join(t.root, 'c.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt, '-days', '2', '-subj', '/CN=refund-desk.example',
      '-addext', 'subjectAltName=DNS:refund-desk.example,DNS:www.refund-desk.example'], { stdio: 'ignore' });
    tlsServer = createHttpsServer({ key: readFileSync(key), cert: readFileSync(crt) }, (_q, res) => res.end('ok')) as unknown as Server;
    await new Promise<void>((r) => tlsServer.listen(0, '127.0.0.1', () => r()));
    tlsPort = (tlsServer.address() as { port: number }).port;

    rdap = createHttpServer((q, res) => {
      const base = `http://127.0.0.1:${rdapPort}/rdap/`;
      const json = (o: unknown, status = 200) => { res.writeHead(status, { 'content-type': 'application/rdap+json' }); res.end(JSON.stringify(o)); };
      if (q.url === '/boot/dns.json') return json({ services: [[['example'], [base]]] });
      if (q.url === '/boot/ipv4.json') return json({ services: [[['127.0.0.0/8'], [base]]] });
      if (q.url === '/rdap/domain/refund-desk.example') {
        return json({
          ldhName: 'refund-desk.example', status: ['client transfer prohibited'],
          events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 5 * 86_400_000).toISOString() }, { eventAction: 'expiration', eventDate: '2027-10-01T00:00:00Z' }],
          nameservers: [{ ldhName: 'ns1.parking.example' }],
          entities: [
            { roles: ['registrar'], publicIds: [{ type: 'IANA Registrar ID', identifier: '9999' }], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar Ltd']]],
              entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['fn', {}, 'text', 'Abuse Desk'], ['email', {}, 'text', 'abuse@registrar.example'], ['tel', {}, 'uri', 'tel:+1.5550100']]] }] },
            { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'REDACTED FOR PRIVACY']]] },
          ],
          redacted: [{ name: { description: 'Registrant Name' } }],
        });
      }
      if (q.url === '/rdap/domain/unknown.example') return json({ errorCode: 404 }, 404);
      if (q.url === '/rdap/ip/127.0.0.1') {
        return json({ name: 'CLOUDFLARENET', handle: 'NET-127', startAddress: '127.0.0.0', endAddress: '127.255.255.255', country: 'US',
          entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['email', {}, 'text', 'abuse@cdn.example']]] }] });
      }
      return json({ error: 'nope' }, 404);
    });
    await new Promise<void>((r) => rdap.listen(0, '127.0.0.1', () => r()));
    rdapPort = (rdap.address() as { port: number }).port;

    gw = new EgressGateway({
      port: 0, host: '127.0.0.1', allowedPorts: [443, tlsPort], extraDenyCidrs: [], connectTimeoutMs: 3000, dnsTimeoutMs: 2000, idleTimeoutMs: 10_000,
      maxTunnelMs: 30_000, maxConcurrentTunnels: 20,
      resolve: async (h) => (h === 'refund-desk.example' ? ['127.0.0.1'] : Promise.reject(Object.assign(new Error('nx'), { code: 'ENOTFOUND' }))),
      classify: (a) => (a === '127.0.0.1' ? { allowed: true, normalised: a, family: 4 } : classifyAddress(a)),
      dnsRecords: async (name, type) => {
        if (name === 'refund-desk.example' && type === 'A') return ['203.0.113.7'];
        if (name === 'refund-desk.example' && type === 'MX') return [{ exchange: 'mx.mail.example', priority: 10 }];
        if (name === 'refund-desk.example' && type === 'TXT') return ['v=spf1 include:_spf.mail.example ~all', 'google-site-verification=x'];
        if (name === '7.113.0.203.in-addr.arpa' && type === 'PTR') return ['host7.hosting.example'];
        throw Object.assign(new Error('no data'), { code: 'ENODATA' });
      },
    });
    gwPort = (await gw.listen()).port;
  });
  afterAll(async () => {
    await gw.close();
    await new Promise((r) => tlsServer.close(r));
    await new Promise((r) => rdap.close(r));
    await cleanup();
  });

  it('serves bounded DNS lookups and refuses internal namespaces and single labels', async () => {
    const q = async (name: string, type = 'A') => (await (await request(`http://127.0.0.1:${gwPort}/__dns?name=${encodeURIComponent(name)}&type=${type}`)).body.json()) as Record<string, unknown>;
    expect((await q('refund-desk.example')).records).toEqual(['203.0.113.7']);
    expect((await q('db.internal')).error).toBe('internal_namespace');
    expect((await q('postgres')).error).toBe('single_label_name');
    expect((await q('printer.local')).error).toBe('internal_namespace');
    expect((await q('203.0.113.7', 'PTR')).records).toEqual(['host7.hosting.example']);
    expect((await q('refund-desk.example', 'AXFR')).error).toBe('unsupported_type');
    const egress = { proxyUrl: `http://127.0.0.1:${gwPort}`, vantage: 'test-gw' };
    const p = await dnsProfile(egress, 'refund-desk.example', 'refund-desk.example', 3000);
    expect(p.status).toBe('ok');
    expect(p.data.spf).toEqual(['v=spf1 include:_spf.mail.example ~all']);
    expect(p.data.reverse_dns).toEqual({ '203.0.113.7': ['host7.hosting.example'] });
  });

  it('records the live certificate through a CONNECT tunnel, and reports gateway refusals', async () => {
    const egress = { proxyUrl: `http://127.0.0.1:${gwPort}`, vantage: 'test-gw' };
    const r = await fetchCertificate(egress, 'refund-desk.example', tlsPort, 5000);
    expect(r.status).toBe('ok');
    expect(r.data.subject_alt_names).toEqual(['DNS:refund-desk.example', 'DNS:www.refund-desk.example']);
    expect(r.data.chain_trusted).toBe(false); // self-signed: recorded, not hidden
    expect(String(r.data.fingerprint_sha256)).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    const refused = await fetchCertificate(egress, 'refund-desk.example', 22, 5000);
    expect(refused).toMatchObject({ status: 'error', error: 'port_denied' });
  });

  it('parses RDAP registrar, abuse contact, redaction and CDN heuristics; suggests role-specific addressees', async () => {
    const policy = testPolicy({ enrichment: {
      rdap_bootstrap_dns_url: `http://127.0.0.1:${rdapPort}/boot/dns.json`, rdap_bootstrap_ipv4_url: `http://127.0.0.1:${rdapPort}/boot/ipv4.json`,
    } });
    const direct = { proxyUrl: null, vantage: 'test-direct' };
    const d = await rdapDomain(direct, policy, 'refund-desk.example');
    expect(d.status).toBe('redacted');
    expect(d.data.registrar).toMatchObject({ name: 'Example Registrar Ltd', iana_id: '9999' });
    expect(d.data.abuse_contact).toMatchObject({ email: 'abuse@registrar.example' });
    expect((d.data.events as { action: string }[]).map((e) => e.action)).toContain('registration');
    expect((await rdapDomain(direct, policy, 'unknown.example')).status).toBe('not_found');
    expect((await rdapDomain(direct, policy, 'x.nosuchtld')).status).toBe('not_found');
    const ip = await rdapIp(direct, policy, '127.0.0.1');
    expect(ip.data.cdn_or_proxy).toMatchObject({ likely: true, provider: 'Cloudflare' });
    const a = suggestAddressees([{ source: 'rdap_domain', status: d.status, data: d.data }, { source: 'rdap_ip', status: 'ok', data: ip.data }], ['play:com.fake.app']);
    expect(a.map((x) => x.role)).toEqual(['registrar', 'registry', 'cdn', 'app_distributor']);
    expect(a.find((x) => x.role === 'cdn')!.note).toMatch(/not the origin host/);
  });
});

describe('revisit comparison (takedown verification)', () => {
  const facts = (o: Partial<Parameters<typeof classifyRevisit>[1]> = {}) => ({
    id: 'a', outcome: 'CONTENT_CAPTURED', classification: 'content_captured', artifact_dir: null, final_url: 'https://refund-desk.example/pay',
    identifiers: new Set(['upi_vpa:payee@ybl']), text: 'Pay the refund processing fee to payee@ybl now to receive your refund today', dhash: 0b1010n, ...o,
  });
  it('separates still-live, changed payee, parked, blocked-at-vantage, DNS and redirect outcomes', () => {
    expect(classifyRevisit(facts(), facts(), 'refund-desk.example').outcome).toBe('still_live');
    const changed = classifyRevisit(facts(), facts({ identifiers: new Set(['upi_vpa:newpayee@ybl']) }), 'refund-desk.example');
    expect(changed.outcome).toBe('observed_changed_content');
    expect(changed.differences).toMatchObject({ identifiers_added: ['upi_vpa:newpayee@ybl'], identifiers_removed: ['upi_vpa:payee@ybl'] });
    expect(classifyRevisit(facts(), facts({ classification: 'parked_domain' }), 'refund-desk.example').outcome).toBe('parked_or_suspended_page');
    expect(classifyRevisit(facts(), facts({ outcome: 'ACCESS_BLOCKED', classification: 'isp_block_notice' }), 'refund-desk.example').outcome).toBe('blocked_at_tested_vantage');
    expect(classifyRevisit(facts(), facts({ outcome: 'DNS_FAILURE', classification: 'dns_failure' }), 'refund-desk.example').outcome).toBe('dns_not_resolving');
    expect(classifyRevisit(facts(), facts({ final_url: 'https://legit-bank.example/' }), 'refund-desk.example').outcome).toBe('redirected_elsewhere');
    expect(classifyRevisit(facts(), facts({ outcome: 'ORIGIN_UNAVAILABLE', classification: 'timeout' }), 'refund-desk.example').outcome).toBe('temporarily_unreachable');
  });
  it('measures text and screenshot change', () => {
    expect(textSimilarity('a b c d e f', 'a b c d e f')).toBe(1);
    expect(textSimilarity('pay the fee to this upi id now', 'welcome to our genuine bakery menu today')).toBeLessThan(0.1);
    const png = readFileSync(new URL('../fixtures/upi-qr.png', import.meta.url));
    const h = differenceHash(png, 40)!;
    expect(hammingDistance(h, h)).toBe(0);
  });
});
