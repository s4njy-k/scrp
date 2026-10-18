import { connect } from 'node:net';
import { request } from 'undici';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EgressGateway } from '../../src/gateway/server.js';
import { classifyAddress } from '../../src/gateway/policy.js';
import { createDispatcher } from '../../src/acquisition/egress.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';

let fixture: FixtureServer;
let gw: EgressGateway;
let gwPort: number;

/** Test resolver: fixture.test is "public" (pinned to the loopback fixture); rebind.test returns a private answer too. */
const resolve = async (host: string): Promise<string[]> => {
  if (host === 'fixture.test') return ['127.0.0.1'];
  if (host === 'rebind.test') return ['93.184.215.14', '10.0.0.5'];
  if (host === 'metadata.test') return ['169.254.169.254'];
  if (host === 'mapped.test') return ['::ffff:127.0.0.1'];
  if (host === 'slow.test') {
    // Slow DNS, then the (allowed) local fixture: no outbound traffic from the test.
    await new Promise((r) => setTimeout(r, 300));
    return ['127.0.0.1'];
  }
  const err = Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
  throw err;
};

function connectRaw(target: string): Promise<{ status: number; headers: string }> {
  return new Promise((res, rej) => {
    const s = connect(gwPort, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let buf = '';
    s.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('\r\n\r\n')) {
        s.destroy();
        res({ status: Number(buf.split(' ')[1]), headers: buf });
      }
    });
    s.on('error', rej);
  });
}

describe('egress gateway connection-time policy (§13)', () => {
  beforeAll(async () => {
    fixture = await startFixtureServer();
    gw = new EgressGateway({
      port: 0, host: '127.0.0.1', allowedPorts: [80, 443, fixture.port], extraDenyCidrs: [], connectTimeoutMs: 3000, dnsTimeoutMs: 2000,
      idleTimeoutMs: 10_000, maxTunnelMs: 30_000, maxConcurrentTunnels: 50, resolve,
      // Only the pinned fixture loopback address is treated as public in this test.
      classify: (a) => (a === '127.0.0.1' ? { allowed: true, normalised: a, family: 4 } : classifyAddress(a)),
    });
    gwPort = (await gw.listen()).port;
  });
  afterAll(async () => { await gw.close(); await fixture.close(); });

  it('tunnels to an allowed destination using the pinned address', async () => {
    const dispatcher = createDispatcher({ proxyUrl: `http://127.0.0.1:${gwPort}`, vantage: 'test' }, { relaxedTls: false, connectTimeoutMs: 3000 });
    const res = await request(`http://fixture.test:${fixture.port}/static`, { dispatcher });
    expect(res.statusCode).toBe(200);
    expect(await res.body.text()).toContain('Acme Refund Desk');
    await dispatcher.close();
  });

  it.each([
    ['loopback IP literal', `127.0.0.2:${443}`, 'destination_denied'],
    ['private IP literal', '10.0.0.1:443', 'destination_denied'],
    ['metadata via DNS', 'metadata.test:80', 'destination_denied'],
    ['IPv4-mapped IPv6 via DNS', 'mapped.test:443', 'destination_denied'],
    ['IPv4-mapped IPv6 literal', '[::ffff:127.0.0.1]:443', 'destination_denied'],
    ['IPv6 loopback literal', '[::1]:443', 'destination_denied'],
    ['rebinding (mixed public/private answers)', 'rebind.test:443', 'destination_denied'],
    ['localhost name', 'localhost:443', 'destination_denied'],
    ['nonstandard port', 'fixture.test:22', 'port_denied'],
    ['unresolvable name', 'nx.test:443', 'dns_nxdomain'],
  ])('refuses CONNECT: %s', async (_name, target, error) => {
    const r = await connectRaw(target);
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(r.headers).toContain(`X-Egress-Error: ${error}`);
  });

  it('refuses absolute-form HTTP to internal targets and does not follow redirects itself', async () => {
    const raw = await new Promise<string>((res, rej) => {
      const s = connect(gwPort, '127.0.0.1', () => s.write('GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n'));
      let buf = '';
      s.on('data', (d) => { buf += d.toString(); });
      s.on('end', () => res(buf));
      s.on('error', rej);
    });
    expect(raw).toMatch(/^HTTP\/1\.1 403/);
    expect(raw.toLowerCase()).toContain('x-egress-error: destination_denied');
    // A redirect from an allowed origin to metadata is returned to the client, whose next
    // connection is checked again by the gateway.
    const dispatcher = createDispatcher({ proxyUrl: `http://127.0.0.1:${gwPort}`, vantage: 'test' }, { relaxedTls: false, connectTimeoutMs: 3000 });
    const r2 = await request(`http://fixture.test:${fixture.port}/redirect-internal`, { dispatcher });
    expect(r2.statusCode).toBe(302);
    await r2.body.dump();
    await expect(request('http://169.254.169.254/latest/meta-data/', { dispatcher })).rejects.toThrow();
    await dispatcher.close();
  });

  it('survives clients that reset while DNS or connect is still pending', async () => {
    for (let i = 0; i < 5; i += 1) {
      await new Promise<void>((res) => {
        const s = connect(gwPort, '127.0.0.1', () => {
          s.write(`CONNECT slow.test:${fixture.port} HTTP/1.1\r\nHost: slow.test:${fixture.port}\r\n\r\n`);
          setTimeout(() => { s.resetAndDestroy(); res(); }, 20);
        });
        s.on('error', () => res());
      });
    }
    await new Promise((r) => setTimeout(r, 600));
    const h = await request(`http://127.0.0.1:${gwPort}/__health`);
    expect(h.statusCode).toBe(200);
    expect((await h.body.json() as { active_tunnels: number }).active_tunnels).toBe(0);
  });

  it('reports decisions on /__resolve for DNS-versus-policy classification', async () => {
    const r = await request(`http://127.0.0.1:${gwPort}/__resolve?host=nx.test&port=443`);
    expect(await r.body.json()).toMatchObject({ allowed: false, error: 'dns_nxdomain' });
    const r2 = await request(`http://127.0.0.1:${gwPort}/__resolve?host=rebind.test&port=443`);
    expect(await r2.body.json()).toMatchObject({ allowed: false, error: 'destination_denied' });
  });
});
