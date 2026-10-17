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
  engine: Engine;
  browser: Browser;
  launchedAt: number;
  jobs: number;
  /** Captures currently using this browser. */
  active: number;
  /** Retired browsers take no new work and close once their last capture releases them. */
  retired: boolean;
}

/** A capture's claim on a shared browser. Always call release() in finally. */
export interface BrowserLease {
  browser: Browser;
  release(): void;
}

export class BrowserPool {
  private readonly current = new Map<Engine, Entry>();
  private readonly opening = new Map<Engine, Promise<Entry>>();
  private readonly retiredEntries = new Set<Entry>();

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

  /** Concurrent first callers share one launch instead of each starting (and leaking) a browser. */
  private openShared(engine: Engine): Promise<Entry> {
    const pending = this.opening.get(engine);
    if (pending) return pending;
    const p = (async () => {
      const browser = await this.open(engine);
      const entry: Entry = { engine, browser, launchedAt: Date.now(), jobs: 0, active: 0, retired: false };
      browser.on('disconnected', () => this.retire(entry, 'disconnected'));
      this.current.set(engine, entry);
      logger.info({ engine, version: browser.version(), mode: this.cfg.mode }, 'browser ready');
      return entry;
    })();
    this.opening.set(engine, p);
    void p.finally(() => this.opening.delete(engine)).catch(() => undefined);
    return p;
  }

  private tooOld(e: Entry): boolean {
    return Date.now() - e.launchedAt > this.policy.browser.recycle_after_minutes * 60_000 || e.jobs >= this.policy.browser.recycle_after_jobs;
  }

  /**
   * Retire a browser: no new captures use it; it closes when its last
   * in-flight capture releases it. Never closes a browser under a running capture.
   */
  private retire(e: Entry, reason: string): void {
    if (this.current.get(e.engine) === e) this.current.delete(e.engine);
    if (!e.retired) {
      e.retired = true;
      this.retiredEntries.add(e);
      logger.info({ engine: e.engine, jobs: e.jobs, active: e.active, age_s: Math.round((Date.now() - e.launchedAt) / 1000), reason }, 'browser retired');
    }
    this.maybeClose(e);
  }

  private maybeClose(e: Entry): void {
    if (!e.retired || e.active > 0) return;
    this.retiredEntries.delete(e);
    if (e.browser.isConnected()) e.browser.close().catch(() => undefined);
  }

  /** Get a live browser, recycling after a bounded job count or age (§16). */
  async acquire(engine: Engine): Promise<BrowserLease> {
    let e = this.current.get(engine);
    if (e && (!e.browser.isConnected() || this.tooOld(e))) {
      this.retire(e, e.browser.isConnected() ? 'recycle_after_jobs_or_age' : 'disconnected');
      e = undefined;
    }
    if (!e) e = await this.openShared(engine);
    const entry = e;
    entry.jobs += 1;
    entry.active += 1;
    let released = false;
    return {
      browser: entry.browser,
      release: () => {
        if (released) return;
        released = true;
        entry.active -= 1;
        this.maybeClose(entry);
      },
    };
  }

  /** Recycle after a crash or abnormal memory growth; in-flight captures finish first. */
  discard(engine: Engine, reason = 'discarded'): void {
    const e = this.current.get(engine);
    if (e) this.retire(e, reason);
  }

  /** Retire every browser (graceful). */
  retireAll(reason: string): void {
    for (const e of [...this.current.values()]) this.retire(e, reason);
  }

  /** Shutdown: close everything, including browsers still in use. */
  async closeAll(): Promise<void> {
    const all = [...this.current.values(), ...this.retiredEntries];
    this.current.clear();
    this.retiredEntries.clear();
    await Promise.all(all.map((e) => e.browser.close().catch(() => undefined)));
  }
}
