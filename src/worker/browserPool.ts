/**
 * Browser connection management for the driver worker.
 *
 * Hardened profile (BROWSER_MODE=connect): the driver connects to a separate
 * private browser-engine container running `playwright run-server`; the engine
 * has no database credentials and reaches the Internet only via the gateway.
 * Development profile (BROWSER_MODE=local): the browser runs inside the
 * driver container. This is a WEAKER process/network boundary and must not be
 * described as equivalent (§13).
 */
import { chromium, firefox, type Browser, type LaunchOptions } from 'playwright-core';
import type { Policy } from '../config/policy.js';
import type { EgressConfig } from '../acquisition/egress.js';
import { logger } from '../observability/logger.js';

export type Engine = 'chromium' | 'firefox';

export interface BrowserPoolConfig {
  mode: 'connect' | 'local';
  wsEndpoint: string | null;
  connectTimeoutMs: number;
  /**
   * Chromium sandbox. Always on in the hardened (connect) profile. It may be
   * disabled ONLY in local development (e.g. a root CI container), and every
   * attempt then records `chromium_sandbox: false` — never silently.
   */
  chromiumSandbox: boolean;
}

export function browserPoolConfigFromEnv(env = process.env): BrowserPoolConfig {
  const mode = (env.BROWSER_MODE ?? 'connect') as 'connect' | 'local';
  if (mode !== 'connect' && mode !== 'local') throw new Error('BROWSER_MODE must be connect or local');
  const wsEndpoint = env.BROWSER_WS_ENDPOINT ?? null;
  if (mode === 'connect' && !wsEndpoint) throw new Error('BROWSER_WS_ENDPOINT is required when BROWSER_MODE=connect');
  const chromiumSandbox = env.CHROMIUM_SANDBOX !== 'false';
  if (!chromiumSandbox && mode === 'connect') {
    throw new Error('CHROMIUM_SANDBOX=false is refused in the hardened connect profile: fix host isolation support instead (deployment blocker)');
  }
  return { mode, wsEndpoint, connectTimeoutMs: Number(env.BROWSER_CONNECT_TIMEOUT_MS ?? 30_000), chromiumSandbox };
}

/**
 * Launch options sent to the engine. Everything that could let page traffic
 * bypass the gateway is closed here AND by the network topology:
 *  - all traffic through the proxy, including loopback (<-loopback>), so a page
 *    cannot reach the run-server or anything else on the engine's localhost;
 *  - QUIC disabled; WebRTC limited to proxied (TCP) routes;
 *  - Firefox DNS-over-HTTPS and HTTP/3 disabled, localhost not exempt.
 */
export function launchOptionsFor(engine: Engine, policy: Policy, egress: EgressConfig, chromiumSandbox = true): LaunchOptions {
  const proxy = egress.proxyUrl ? { server: egress.proxyUrl, bypass: '<-loopback>' } : undefined;
  if (engine === 'chromium') {
    return {
      headless: true,
      chromiumSandbox,
      ...(policy.browser.chromium_channel === 'chromium' ? { channel: 'chromium' } : {}),
      ...(proxy ? { proxy } : {}),
      args: [
        '--disable-quic',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--disable-features=DnsOverHttps,AsyncDns',
        '--disable-background-networking',
        '--no-pings',
        '--metrics-recording-only',
        '--disable-domain-reliability',
        '--disable-component-update',
      ],
    };
  }
  return {
    headless: true,
    ...(proxy ? { proxy } : {}),
    firefoxUserPrefs: {
      'network.http.http3.enable': false,
      'network.trr.mode': 5,
      'network.proxy.allow_hijacking_localhost': true,
      'media.peerconnection.ice.proxy_only': true,
      'toolkit.telemetry.enabled': false,
      'datareporting.healthreport.uploadEnabled': false,
      'app.normandy.enabled': false,
      'browser.safebrowsing.malware.enabled': false,
      'browser.safebrowsing.phishing.enabled': false,
    },
  };
}

interface Entry {
  browser: Browser;
  launchedAt: number;
  jobs: number;
}

export class BrowserPool {
  private readonly entries = new Map<Engine, Entry>();

  constructor(
    readonly cfg: BrowserPoolConfig,
    private readonly policy: Policy,
    private readonly egress: EgressConfig,
  ) {}

  private async open(engine: Engine): Promise<Browser> {
    const type = engine === 'chromium' ? chromium : firefox;
    const launch = launchOptionsFor(engine, this.policy, this.egress, this.cfg.chromiumSandbox);
    if (!this.cfg.chromiumSandbox) logger.warn({ engine }, 'Chromium sandbox DISABLED (local development profile); recorded on every attempt');
    if (this.cfg.mode === 'connect') {
      return type.connect(this.cfg.wsEndpoint!, {
        timeout: this.cfg.connectTimeoutMs,
        headers: { 'x-playwright-launch-options': JSON.stringify(launch) },
        exposeNetwork: '', // never expose the driver's network to the engine
      });
    }
    return type.launch({ ...launch, timeout: this.cfg.connectTimeoutMs });
  }

  /** Get a live browser, recycling after a bounded job count or age (§16). */
  async acquire(engine: Engine): Promise<Browser> {
    const e = this.entries.get(engine);
    const tooOld = e && (Date.now() - e.launchedAt > this.policy.browser.recycle_after_minutes * 60_000 || e.jobs >= this.policy.browser.recycle_after_jobs);
    if (e && e.browser.isConnected() && !tooOld) {
      e.jobs += 1;
      return e.browser;
    }
    if (e) {
      logger.info({ engine, jobs: e.jobs, age_s: Math.round((Date.now() - e.launchedAt) / 1000) }, 'recycling browser');
      this.entries.delete(engine);
      await e.browser.close().catch(() => undefined);
    }
    const browser = await this.open(engine);
    browser.on('disconnected', () => {
      if (this.entries.get(engine)?.browser === browser) this.entries.delete(engine);
    });
    this.entries.set(engine, { browser, launchedAt: Date.now(), jobs: 1 });
    logger.info({ engine, version: browser.version(), mode: this.cfg.mode }, 'browser ready');
    return browser;
  }

  /** Force a recycle after a crash or abnormal memory growth. */
  async discard(engine: Engine): Promise<void> {
    const e = this.entries.get(engine);
    this.entries.delete(engine);
    await e?.browser.close().catch(() => undefined);
  }

  async closeAll(): Promise<void> {
    for (const engine of [...this.entries.keys()]) await this.discard(engine);
  }
}
