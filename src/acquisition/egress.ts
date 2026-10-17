/**
 * Client side of the egress gateway: dispatcher for HTTP triage and the
 * gateway lookup used to tell DNS failure from policy denial after a proxy
 * tunnel error (browsers only report a generic tunnel failure).
 */
import { Agent, ProxyAgent, request, type Dispatcher } from 'undici';
import { logger } from '../observability/logger.js';

export interface EgressConfig {
  /** e.g. http://egress-gateway:3128. Unset only in local development/tests. */
  proxyUrl: string | null;
  /** Free-text description of the network vantage recorded with every attempt. */
  vantage: string;
}

export function egressConfigFromEnv(env = process.env): EgressConfig {
  const proxyUrl = env.EGRESS_PROXY_URL?.trim() || null;
  if (!proxyUrl && env.COLLECTOR_ALLOW_DIRECT_EGRESS !== 'true') {
    throw new Error('EGRESS_PROXY_URL is required (set COLLECTOR_ALLOW_DIRECT_EGRESS=true only for local fixture tests)');
  }
  return { proxyUrl, vantage: env.EGRESS_VANTAGE_LABEL ?? (proxyUrl ? 'local-egress-gateway' : 'direct-unprotected-dev') };
}

export function createDispatcher(cfg: EgressConfig, opts: { relaxedTls: boolean; connectTimeoutMs: number }): Dispatcher {
  const connect = { timeout: opts.connectTimeoutMs, rejectUnauthorized: !opts.relaxedTls };
  if (!cfg.proxyUrl) {
    logger.warn('HTTP triage running WITHOUT the egress gateway (development mode)');
    return new Agent({ connect, maxRedirections: 0 } as Agent.Options);
  }
  // Always tunnel (CONNECT), also for http:// targets, so gateway refusals are
  // never confused with a response from the origin.
  return new ProxyAgent({ uri: cfg.proxyUrl, proxyTunnel: true, requestTls: { rejectUnauthorized: !opts.relaxedTls }, connect } as ProxyAgent.Options);
}

export interface GatewayLookup {
  allowed: boolean;
  error: string | null;
  reason: string | null;
  addresses: { address: string; allowed: boolean; reason?: string }[];
}

/** Ask the gateway what it decided for host:port. Null when the gateway is not configured/reachable. */
export async function lookupViaGateway(cfg: EgressConfig, host: string, port: number): Promise<GatewayLookup | null> {
  if (!cfg.proxyUrl) return null;
  try {
    const url = new URL('/__resolve', cfg.proxyUrl);
    url.searchParams.set('host', host);
    url.searchParams.set('port', String(port));
    const res = await request(url, { method: 'GET', headersTimeout: 8000, bodyTimeout: 8000 });
    if (res.statusCode !== 200) {
      await res.body.dump();
      return null;
    }
    return (await res.body.json()) as GatewayLookup;
  } catch (err) {
    logger.warn({ err: (err as Error).message }, 'gateway lookup failed');
    return null;
  }
}

export async function gatewayHealthy(cfg: EgressConfig): Promise<boolean> {
  if (!cfg.proxyUrl) return true;
  try {
    const res = await request(new URL('/__health', cfg.proxyUrl), { method: 'GET', headersTimeout: 5000, bodyTimeout: 5000 });
    await res.body.dump();
    return res.statusCode === 200;
  } catch {
    return false;
  }
}
