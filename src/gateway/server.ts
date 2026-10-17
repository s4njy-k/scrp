/**
 * Egress gateway: an HTTP forward proxy that enforces the public-destination
 * policy at connection time for HTTP, HTTPS (CONNECT) and WebSocket traffic
 * from the browser engine and HTTP triage (blueprint §5, §13).
 *
 * The gateway is the only acquisition component with a route to the Internet
 * (compose: the browser-engine network is `internal: true`). It does not
 * change the public IP address of the host; it protects the host and internal
 * services and records every decision.
 */
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { connect as netConnect, isIP, type Socket } from 'node:net';
import { lookup } from 'node:dns/promises';
import type { Duplex } from 'node:stream';
import { logger, bounded } from '../observability/logger.js';
import { classifyAddress, classifyHostname, type AddressVerdict } from './policy.js';

export interface GatewayOptions {
  port: number;
  host: string;
  allowedPorts: number[];
  extraDenyCidrs: string[];
  connectTimeoutMs: number;
  dnsTimeoutMs: number;
  idleTimeoutMs: number;
  maxTunnelMs: number;
  maxConcurrentTunnels: number;
  /** Injectable for tests. Defaults to the system resolver (all A/AAAA records). */
  resolve?: (host: string) => Promise<string[]>;
  /** Injectable for tests. Defaults to classifyAddress with extraDenyCidrs. */
  classify?: (address: string) => AddressVerdict;
}

export type EgressError =
  | 'destination_denied' | 'port_denied' | 'scheme_denied' | 'bad_request'
  | 'dns_nxdomain' | 'dns_timeout' | 'dns_error'
  | 'connect_refused' | 'connect_timeout' | 'unreachable' | 'connect_error' | 'capacity';

interface Decision {
  allowed: boolean;
  host: string;
  port: number;
  pinned?: string[];
  error?: EgressError;
  reason?: string;
  addresses?: { address: string; allowed: boolean; reason?: string }[];
}

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(Object.assign(new Error(`${label} timeout`), { code: 'ETIMEOUT' })), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e: unknown) => { clearTimeout(t); reject(e); });
  });
}

async function systemResolve(host: string): Promise<string[]> {
  const res = await lookup(host, { all: true, verbatim: true });
  return res.map((r) => r.address);
}

function dnsErrorKind(err: unknown): EgressError {
  const code = (err as { code?: string }).code;
  if (code === 'ENOTFOUND' || code === 'ENODATA' || code === 'NXDOMAIN') return 'dns_nxdomain';
  if (code === 'ETIMEOUT' || code === 'EAI_AGAIN' || code === 'ETIMEDOUT') return 'dns_timeout';
  return 'dns_error';
}

function connectErrorKind(err: unknown): EgressError {
  const code = (err as { code?: string }).code;
  if (code === 'ECONNREFUSED') return 'connect_refused';
  if (code === 'ETIMEDOUT' || code === 'ETIMEOUT') return 'connect_timeout';
  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return 'unreachable';
  return 'connect_error';
}

export class EgressGateway {
  private server: Server | null = null;
  private activeTunnels = 0;
  private readonly resolveFn: (host: string) => Promise<string[]>;
  private readonly classifyFn: (address: string) => AddressVerdict;
  readonly stats = { allowed: 0, denied: 0, failed: 0 };
  /**
   * Short positive DNS cache (pages open many connections to the same hosts).
   * Safe against rebinding: every cached answer is re-classified on use and the
   * connection is still pinned to those checked addresses.
   */
  private readonly dnsCache = new Map<string, { addresses: string[]; expires: number }>();
  private static readonly DNS_CACHE_MS = 30_000;
  private static readonly DNS_CACHE_MAX = 2000;

  private async resolveCached(host: string): Promise<string[]> {
    const hit = this.dnsCache.get(host);
    if (hit && hit.expires > Date.now()) return hit.addresses;
    const addresses = await withTimeout(this.resolveFn(host), this.opts.dnsTimeoutMs, 'dns');
    if (this.dnsCache.size >= EgressGateway.DNS_CACHE_MAX) {
      const oldest = this.dnsCache.keys().next().value;
      if (oldest !== undefined) this.dnsCache.delete(oldest);
    }
    this.dnsCache.set(host, { addresses, expires: Date.now() + EgressGateway.DNS_CACHE_MS });
    return addresses;
  }

  constructor(private readonly opts: GatewayOptions) {
    this.resolveFn = opts.resolve ?? systemResolve;
    this.classifyFn = opts.classify ?? ((a) => classifyAddress(a, opts.extraDenyCidrs));
  }

  /** Decide whether host:port may be contacted, resolving and pinning addresses. */
  async decide(rawHost: string, port: number): Promise<Decision> {
    const host = rawHost.replace(/^\[|\]$/g, '').toLowerCase();
    if (!Number.isInteger(port) || !this.opts.allowedPorts.includes(port)) {
      return { allowed: false, host, port, error: 'port_denied', reason: `port ${port} not in allowed list` };
    }
    let addresses: string[];
    if (isIP(host)) {
      addresses = [host];
    } else {
      const hv = classifyHostname(host);
      if (!hv.ok) return { allowed: false, host, port, error: 'destination_denied', reason: hv.reason };
      try {
        addresses = await this.resolveCached(host);
      } catch (err) {
        return { allowed: false, host, port, error: dnsErrorKind(err), reason: bounded((err as Error).message, 200) };
      }
      if (addresses.length === 0) return { allowed: false, host, port, error: 'dns_nxdomain', reason: 'no addresses' };
    }
    const verdicts = addresses.map((a) => this.classifyFn(a));
    const summary = verdicts.map((v) => ({ address: v.normalised, allowed: v.allowed, ...(v.allowed ? {} : { reason: v.reason }) }));
    const denied = verdicts.find((v) => !v.allowed);
    if (denied && !denied.allowed) {
      // Any non-public answer denies the whole name: mixed answers are a rebinding signal.
      return { allowed: false, host, port, error: 'destination_denied', reason: denied.reason, addresses: summary };
    }
    // Prefer IPv4 first (containers commonly lack IPv6 egress), keep resolver order otherwise.
    const pinned = [...verdicts].sort((a, b) => (a.allowed && b.allowed ? a.family - b.family : 0)).map((v) => v.normalised);
    return { allowed: true, host, port, pinned, addresses: summary };
  }

  private log(kind: string, d: Decision, extra: Record<string, unknown> = {}): void {
    if (d.allowed) this.stats.allowed += 1;
    else this.stats.denied += 1;
    logger.info({ egress: kind, allowed: d.allowed, host: bounded(d.host, 260), port: d.port, error: d.error, reason: d.reason, pinned: d.pinned?.[0], ...extra }, 'egress decision');
  }

  /**
   * Connect to the checked (pinned) addresses in order. When `client` is given,
   * an in-progress connect is cancelled as soon as that client goes away, so an
   * abandoned request never holds a tunnel slot until the connect timeout.
   */
  private async connectPinned(d: Decision, client?: Duplex): Promise<Socket> {
    let lastErr: unknown = null;
    for (const addr of d.pinned ?? []) {
      if (client?.destroyed) throw Object.assign(new Error('client disconnected'), { code: 'ECONNABORTED' });
      try {
        return await new Promise<Socket>((resolve, reject) => {
          const sock = netConnect({ host: addr, port: d.port });
          const cancel = () => sock.destroy(Object.assign(new Error('client disconnected'), { code: 'ECONNABORTED' }));
          client?.once('close', cancel);
          const t = setTimeout(() => sock.destroy(Object.assign(new Error('connect timeout'), { code: 'ETIMEDOUT' })), this.opts.connectTimeoutMs);
          const done = () => { clearTimeout(t); client?.off('close', cancel); };
          sock.once('connect', () => { done(); resolve(sock); });
          sock.once('error', (e) => { done(); reject(e); });
        });
      } catch (err) {
        lastErr = err;
        if ((err as { code?: string }).code === 'ECONNABORTED') break;
      }
    }
    throw lastErr ?? new Error('no pinned address');
  }

  private refuseSocket(socket: Duplex, status: number, error: EgressError, reason?: string): void {
    const body = JSON.stringify({ error, reason: reason ? bounded(reason, 200) : undefined });
    socket.end(
      `HTTP/1.1 ${status} ${status === 403 ? 'Forbidden' : status === 504 ? 'Gateway Timeout' : status === 503 ? 'Service Unavailable' : 'Bad Gateway'}\r\n` +
      `X-Egress-Error: ${error}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
    );
  }

  private statusFor(error: EgressError): number {
    if (error === 'destination_denied' || error === 'port_denied' || error === 'scheme_denied') return 403;
    if (error === 'connect_timeout' || error === 'dns_timeout') return 504;
    if (error === 'capacity') return 503;
    if (error === 'bad_request') return 400;
    return 502;
  }

  private armTunnelLimits(a: Socket | Duplex, b: Socket | Duplex): void {
    const kill = () => { a.destroy(); b.destroy(); };
    const life = setTimeout(kill, this.opts.maxTunnelMs);
    life.unref();
    for (const s of [a, b]) {
      if ('setTimeout' in s && typeof (s as Socket).setTimeout === 'function') (s as Socket).setTimeout(this.opts.idleTimeoutMs, kill);
      s.on('close', () => clearTimeout(life));
      s.on('error', kill);
    }
  }

  private async handleConnect(req: IncomingMessage, clientSocket: Duplex, head: Buffer): Promise<void> {
    // Attach immediately: a client that resets during DNS/connect must not raise an
    // unhandled 'error' event (which would crash the gateway for every other client).
    clientSocket.on('error', () => clientSocket.destroy());
    const target = req.url ?? '';
    const m = /^(\[[^\]]+\]|[^:]+):(\d{1,5})$/.exec(target);
    if (!m) {
      this.refuseSocket(clientSocket, 400, 'bad_request', 'CONNECT target must be host:port');
      return;
    }
    if (this.activeTunnels >= this.opts.maxConcurrentTunnels) {
      this.refuseSocket(clientSocket, 503, 'capacity');
      return;
    }
    // Count pending tunnels too, so a burst of slow DNS lookups cannot exceed the cap.
    this.activeTunnels += 1;
    let counted = true;
    const uncount = () => {
      if (counted) {
        counted = false;
        this.activeTunnels -= 1;
      }
    };
    const d = await this.decide(m[1]!, Number(m[2]));
    if (!d.allowed) {
      uncount();
      this.log('connect', d);
      this.refuseSocket(clientSocket, this.statusFor(d.error!), d.error!, d.reason);
      return;
    }
    let upstream: Socket;
    try {
      upstream = await this.connectPinned(d, clientSocket);
    } catch (err) {
      uncount();
      const error = connectErrorKind(err);
      this.stats.failed += 1;
      this.log('connect', { ...d, allowed: false, error, reason: (err as Error).message });
      this.refuseSocket(clientSocket, this.statusFor(error), error, (err as Error).message);
      return;
    }
    upstream.once('close', uncount);
    if (clientSocket.destroyed) {
      // Client went away while we were connecting: do not leave an orphan upstream socket.
      upstream.destroy();
      return;
    }
    this.log('connect', d);
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) upstream.write(head);
    this.armTunnelLimits(clientSocket, upstream);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  }

  private parseAbsolute(req: IncomingMessage): URL | null {
    try {
      const u = new URL(req.url ?? '');
      return u;
    } catch {
      return null;
    }
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? '';
    if (url.startsWith('/')) {
      await this.handleLocal(req, res);
      return;
    }
    const u = this.parseAbsolute(req);
    const fail = (status: number, error: EgressError, reason?: string) => {
      if (res.headersSent) { res.destroy(); return; }
      res.writeHead(status, { 'x-egress-error': error, 'content-type': 'application/json', connection: 'close' });
      res.end(JSON.stringify({ error, reason: reason ? bounded(reason, 200) : undefined }));
    };
    if (!u) return fail(400, 'bad_request', 'absolute-form URL required');
    if (u.protocol !== 'http:') return fail(403, 'scheme_denied', `scheme ${u.protocol} not proxied in absolute form`);
    if (u.username || u.password) return fail(403, 'destination_denied', 'userinfo not permitted');
    const d = await this.decide(u.hostname, u.port ? Number(u.port) : 80);
    this.log('http', d, { method: req.method });
    if (!d.allowed) return fail(this.statusFor(d.error!), d.error!, d.reason);

    const headers: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined || HOP_BY_HOP.has(k.toLowerCase())) continue;
      headers[k] = v;
    }
    headers.host = u.host;
    let upstreamSocket: Socket;
    try {
      upstreamSocket = await this.connectPinned(d);
    } catch (err) {
      const error = connectErrorKind(err);
      this.stats.failed += 1;
      return fail(this.statusFor(error), error, (err as Error).message);
    }
    const upstreamReq = httpRequest({
      method: req.method,
      path: `${u.pathname}${u.search}`,
      headers,
      createConnection: () => upstreamSocket,
      timeout: this.opts.idleTimeoutMs,
    });
    upstreamReq.on('response', (up) => {
      const outHeaders: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(up.headers)) {
        if (v === undefined || HOP_BY_HOP.has(k.toLowerCase())) continue;
        outHeaders[k] = v;
      }
      res.writeHead(up.statusCode ?? 502, up.statusMessage, outHeaders);
      up.pipe(res);
    });
    upstreamReq.on('timeout', () => upstreamReq.destroy(Object.assign(new Error('upstream idle timeout'), { code: 'ETIMEDOUT' })));
    upstreamReq.on('error', (err) => fail(this.statusFor(connectErrorKind(err)), connectErrorKind(err), err.message));
    req.pipe(upstreamReq);
  }

  /** Absolute-form WebSocket upgrade (ws://). wss:// arrives as CONNECT. */
  private async handleUpgrade(req: IncomingMessage, clientSocket: Duplex, head: Buffer): Promise<void> {
    clientSocket.on('error', () => clientSocket.destroy());
    const u = this.parseAbsolute(req);
    if (!u || u.protocol !== 'http:' && u.protocol !== 'ws:') {
      this.refuseSocket(clientSocket, 403, 'scheme_denied', 'absolute-form ws/http URL required');
      return;
    }
    const d = await this.decide(u.hostname, u.port ? Number(u.port) : 80);
    this.log('upgrade', d);
    if (!d.allowed) {
      this.refuseSocket(clientSocket, this.statusFor(d.error!), d.error!, d.reason);
      return;
    }
    let upstream: Socket;
    try {
      upstream = await this.connectPinned(d, clientSocket);
    } catch (err) {
      const error = connectErrorKind(err);
      this.refuseSocket(clientSocket, this.statusFor(error), error, (err as Error).message);
      return;
    }
    if (clientSocket.destroyed) {
      upstream.destroy();
      return;
    }
    const lines = [`${req.method} ${u.pathname}${u.search} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const k = req.rawHeaders[i]!;
      const lk = k.toLowerCase();
      if (lk.startsWith('proxy-') || lk === 'host') continue;
      lines.push(`${k}: ${req.rawHeaders[i + 1]}`);
    }
    lines.push(`Host: ${u.host}`);
    upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (head.length) upstream.write(head);
    this.armTunnelLimits(clientSocket, upstream);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  }

  /** Origin-form requests address the gateway itself: health and DNS/policy lookup. */
  private async handleLocal(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const u = new URL(req.url ?? '/', 'http://gateway.invalid');
    if (u.pathname === '/__health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, active_tunnels: this.activeTunnels, ...this.stats }));
      return;
    }
    if (u.pathname === '/__resolve') {
      const host = u.searchParams.get('host') ?? '';
      const port = Number(u.searchParams.get('port') ?? '443');
      const d = await this.decide(host, port);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ host: d.host, port: d.port, allowed: d.allowed, error: d.error ?? null, reason: d.reason ?? null, addresses: d.addresses ?? [] }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  }

  listen(): Promise<{ port: number }> {
    this.server = createServer((req, res) => {
      this.handleRequest(req, res).catch((err) => {
        logger.error({ err: bounded(err) }, 'gateway request handler failed');
        if (!res.headersSent) res.writeHead(502, { 'x-egress-error': 'connect_error' });
        res.end();
      });
    });
    this.server.on('connect', (req, socket, head) => {
      this.handleConnect(req, socket, head).catch((err) => {
        logger.error({ err: bounded(err) }, 'gateway CONNECT handler failed');
        socket.destroy();
      });
    });
    this.server.on('upgrade', (req, socket, head) => {
      this.handleUpgrade(req, socket, head).catch(() => socket.destroy());
    });
    this.server.on('clientError', (_err, socket) => socket.destroy());
    this.server.headersTimeout = 15_000;
    this.server.requestTimeout = 0; // long downloads are bounded by the client's own attempt deadline
    return new Promise((resolve) => {
      this.server!.listen(this.opts.port, this.opts.host, () => {
        const addr = this.server!.address();
        resolve({ port: typeof addr === 'object' && addr ? addr.port : this.opts.port });
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.closeAllConnections();
      this.server.close(() => resolve());
    });
  }
}

export function gatewayOptionsFromEnv(env = process.env): GatewayOptions {
  const list = (v: string | undefined, d: string) => (v ?? d).split(',').map((s) => s.trim()).filter(Boolean);
  return {
    port: Number(env.GATEWAY_PORT ?? 3128),
    host: env.GATEWAY_BIND ?? '0.0.0.0',
    allowedPorts: list(env.GATEWAY_ALLOWED_PORTS, '80,443').map(Number),
    extraDenyCidrs: list(env.GATEWAY_EXTRA_DENY_CIDRS, ''),
    connectTimeoutMs: Number(env.GATEWAY_CONNECT_TIMEOUT_MS ?? 10_000),
    dnsTimeoutMs: Number(env.GATEWAY_DNS_TIMEOUT_MS ?? 5_000),
    idleTimeoutMs: Number(env.GATEWAY_IDLE_TIMEOUT_MS ?? 60_000),
    maxTunnelMs: Number(env.GATEWAY_MAX_TUNNEL_MS ?? 600_000),
    maxConcurrentTunnels: Number(env.GATEWAY_MAX_TUNNELS ?? 512),
  };
}
