import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Browser, BrowserContextOptions } from 'playwright-core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { captureWithBrowser, type BrowserCaptureResult } from '../../src/capture/browserCapture.js';
import { AttemptWriter } from '../../src/storage/artifactStore.js';
import { BrowserPool } from '../../src/worker/browserPool.js';
import { EgressGateway } from '../../src/gateway/server.js';
import { classifyAddress } from '../../src/gateway/policy.js';
import { evaluateRequired, PROFILE_DEFAULT_REQUIRED, type AttemptManifest } from '../../src/acquisition/contract.js';
import { classifyBrowser } from '../../src/router/router.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';
import { BROWSERS_AVAILABLE, TEST_CHROMIUM_SANDBOX, tempRoot, testPolicy } from '../helpers.js';

const policy = testPolicy({ browser: { navigation_timeout_seconds: 6, readiness_max_seconds: 3, challenge_wait_seconds: 2, scroll_step_wait_ms: 100 } });
let fixture: FixtureServer;
let root: string;
let cleanup: () => Promise<void>;
const pools: BrowserPool[] = [];

async function browserVia(proxyUrl: string | null): Promise<Browser> {
  const pool = new BrowserPool({ mode: 'local', wsEndpoint: null, connectTimeoutMs: 30_000, chromiumSandbox: TEST_CHROMIUM_SANDBOX }, policy, { proxyUrl, vantage: 'test' });
  pools.push(pool);
  return (await pool.acquire('chromium')).browser;
}

async function capture(browser: Browser, url: string, seconds = 40, interactions = ['scroll'], proxyUrl: string | null = null, storageState?: BrowserContextOptions['storageState']): Promise<{ r: BrowserCaptureResult; manifest: AttemptManifest; dir: string }> {
  const id = randomUUID();
  const writer = new AttemptWriter(root, id, 50 * 1024 * 1024);
  await writer.init();
  const started = new Date().toISOString();
  const r = await captureWithBrowser({
    browser, engine: 'chromium', url, policy, writer, deadline: Date.now() + seconds * 1000, allowedInteractions: interactions,
    captureVariant: 'desktop', relaxedTls: false, egress: { proxyUrl, vantage: 'test' }, signal: new AbortController().signal,
    isolation: { mode: 'local', chromiumSandbox: TEST_CHROMIUM_SANDBOX },
    ...(storageState ? { storageState } : {}),
  });
  const fin = await writer.finalise((entries) => {
    const c = evaluateRequired(PROFILE_DEFAULT_REQUIRED.browser_evidence, entries);
    const cls = classifyBrowser({ ...r.observation, requiredSatisfied: c.satisfied, missingRequired: c.missing });
    return { attemptId: id, jobId: 1, attemptNo: 1, kind: 'browser', engine: 'chromium', adapter: 'playwright', vantage: 'test', requestedUrl: url, finalUrl: r.finalUrl,
      startedAt: started, endedAt: new Date().toISOString(), outcome: cls.outcome, classification: cls.classification, requiredArtifacts: PROFILE_DEFAULT_REQUIRED.browser_evidence,
      requiredSatisfied: c.satisfied, missingRequired: c.missing, limitations: r.limitations };
  });
  return { r, manifest: fin.manifest, dir: join(root, fin.relativeDir) };
}

const types = (m: AttemptManifest) => m.artifacts.filter((a) => a.path).map((a) => a.type);

describe.skipIf(!BROWSERS_AVAILABLE)('staged browser evidence capture (§9, §10)', () => {
  let direct: Browser;
  beforeAll(async () => {
    fixture = await startFixtureServer();
    ({ root, cleanup } = await tempRoot());
    direct = await browserVia(null);
  });
  afterAll(async () => {
    for (const p of pools) await p.closeAll();
    await fixture.close();
    await cleanup();
  });

  it('captures the exact deep URL with fragment route (no homepage substitution)', async () => {
    const url = fixture.url('/spa?ref=sms&victim=42#/victim/42');
    const { r, manifest, dir } = await capture(direct, url);
    expect(manifest.requestedUrl).toBe(url);
    expect(r.finalUrl).toBe(url);
    const text = await readFile(join(dir, 'dom/rendered.txt'), 'utf8');
    expect(text).toContain('Victim portal for case 42');
    expect(manifest.outcome).toBe('CONTENT_CAPTURED');
    expect(manifest.requiredSatisfied).toBe(true);
    for (const t of ['screenshot_early', 'screenshot_settled', 'rendered_dom', 'rendered_text', 'network_events', 'har', 'action_log', 'session_state']) {
      expect(types(manifest)).toContain(t);
    }
    const early = manifest.artifacts.find((a) => a.type === 'screenshot_early')!;
    const settled = manifest.artifacts.find((a) => a.type === 'screenshot_settled')!;
    expect(Date.parse(early.observedStart!)).toBeLessThanOrEqual(Date.parse(settled.observedStart!));
    expect(manifest.artifacts.find((a) => a.type === 'session_state')?.restricted).toBe(true);
    expect(manifest.artifacts.find((a) => a.type === 'har')?.restricted).toBe(true);
  });

  it('captures hydrated JS content and lazy content after controlled scrolling', async () => {
    const h = await capture(direct, fixture.url('/hydrate'));
    expect(await readFile(join(h.dir, 'dom/rendered.txt'), 'utf8')).toContain('Hydrated offer');
    const l = await capture(direct, fixture.url('/long'));
    expect(await readFile(join(l.dir, 'dom/rendered.html'), 'utf8')).toContain('lazy-content');
    expect(types(l.manifest)).toContain('screenshot_full_or_tiles');
  });

  it('preserves a best-effort screenshot and DOM when navigation never finishes', async () => {
    const { r, manifest, dir } = await capture(direct, fixture.url('/slow'), 35);
    expect(r.observation.navigationTimedOut).toBe(true);
    expect(r.observation.validScreenshots).toBeGreaterThan(0);
    expect(types(manifest)).toContain('screenshot_early');
    expect(await readFile(join(dir, 'dom/rendered.txt'), 'utf8')).toContain('Partial content visible');
    expect(manifest.classification).toBe('navigation_timeout_salvaged');
    expect(manifest.outcome).toBe('CONTENT_INCOMPLETE');
  });

  it('records a challenge interstitial as a challenge outcome with its screenshot', async () => {
    const { r, manifest } = await capture(direct, fixture.url('/challenge'));
    expect(r.observation.challenge.challenge).toBe(true);
    expect(manifest.outcome).toBe('CHALLENGE_PAGE_CAPTURED');
    expect(types(manifest)).toContain('screenshot_early');
  });

  it('records frames, popups, service workers, WebSocket frames and fetch bodies', async () => {
    const { manifest, dir } = await capture(direct, fixture.url('/rich'));
    const events = (await readFile(join(dir, 'network/events.jsonl'), 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as { type: string; [k: string]: unknown });
    const kinds = new Set(events.map((e) => e.type));
    for (const k of ['request', 'response', 'frame_attached', 'popup', 'websocket_open', 'websocket_frame']) expect(kinds).toContain(k);
    expect(events.some((e) => e.type === 'service_worker' || (e.type === 'request' && e.service_worker))).toBe(true);
    expect(types(manifest)).toContain('frame_dom');
    const body = manifest.artifacts.find((a) => a.type === 'response_body' && String(a.metadata?.url).includes('/api/items'));
    expect(body?.path).toBeTruthy();
  });

  it('captures a QR element crop with locator, frame URL and bounding box', async () => {
    const { manifest } = await capture(direct, fixture.url('/qr'));
    const crop = manifest.artifacts.find((a) => a.type === 'element_crop' && a.metadata?.kind === 'qr_candidate');
    expect(crop?.path).toBeTruthy();
    expect(crop?.metadata).toMatchObject({ frame_url: fixture.url('/qr') });
    expect(crop?.metadata?.locator).toMatch(/^html > /);
    expect(crop?.metadata?.bbox).toBeTruthy();
  });

  it('treats a navigation timeout with no document response as a timeout, not salvaged evidence', async () => {
    const { r, manifest } = await capture(direct, fixture.url('/hang'), 25);
    expect(r.observation.netError?.kind).toBe('timeout');
    expect(r.observation.validScreenshots).toBe(0);
    expect(manifest.classification).toBe('timeout');
    // The browser's blank/error page is preserved but never counts as target evidence.
    expect(manifest.requiredSatisfied).toBe(false);
    expect(manifest.missingRequired).toContain('screenshot_viewport');
  });

  it('judges a challenge that clears by itself by the document finally shown', async () => {
    const { r, manifest } = await capture(direct, fixture.url('/challenge-js'), 45);
    expect(r.observation.challengeResolvedDuringWait).toBe(true);
    expect(r.observation.status).toBe(200);
    expect(manifest.outcome).toBe('CONTENT_CAPTURED');
  });

  it('accepts a legitimately text-free page as complete evidence', async () => {
    const { manifest } = await capture(direct, fixture.url('/image-only'));
    const text = manifest.artifacts.find((a) => a.type === 'rendered_text');
    expect(text).toMatchObject({ completeness: 'complete', sizeBytes: 0 });
    expect(manifest.requiredSatisfied).toBe(true);
  });

  it('isolates cookies between targets and keeps them within one target session', async () => {
    const first = await capture(direct, fixture.url('/set-cookie'));
    const other = await capture(direct, fixture.url('/echo-cookie'));
    expect(await readFile(join(other.dir, 'dom/rendered.txt'), 'utf8')).toContain('cookie=[none]');
    const state = JSON.parse(await readFile(join(first.dir, 'session/storage-state.json'), 'utf8')) as BrowserContextOptions['storageState'];
    const same = await capture(direct, fixture.url('/echo-cookie'), 40, ['scroll'], null, state);
    expect(await readFile(join(same.dir, 'dom/rendered.txt'), 'utf8')).toContain('session=target-a-secret');
    // Cookies are restricted evidence: redacted from the ordinary event log.
    expect(await readFile(join(same.dir, 'network/events.jsonl'), 'utf8')).not.toContain('target-a-secret');
  });

  it('never closes a shared browser under a running capture when it is retired', async () => {
    const pool = new BrowserPool({ mode: 'local', wsEndpoint: null, connectTimeoutMs: 30_000, chromiumSandbox: TEST_CHROMIUM_SANDBOX },
      testPolicy({ browser: { recycle_after_jobs: 1 } }), { proxyUrl: null, vantage: 'test' });
    pools.push(pool);
    const [a, b] = await Promise.all([pool.acquire('chromium'), pool.acquire('chromium')]);
    expect(a.browser).toBe(b.browser); // concurrent first acquires share one launch
    const c = await pool.acquire('chromium'); // job limit reached: old browser retired, new one opened
    expect(c.browser).not.toBe(a.browser);
    expect(a.browser.isConnected()).toBe(true); // still in use by a and b
    pool.discard('chromium');
    expect(c.browser.isConnected()).toBe(true); // retired but leased
    a.release();
    expect(b.browser.isConnected()).toBe(true);
    b.release();
    c.release();
    await new Promise((res) => setTimeout(res, 500));
    expect(a.browser.isConnected()).toBe(false);
    expect(c.browser.isConnected()).toBe(false);
  });

  it('routes browser loopback traffic through the gateway, which refuses it', async () => {
    const gw = new EgressGateway({ port: 0, host: '127.0.0.1', allowedPorts: [80, 443, fixture.port], extraDenyCidrs: [], connectTimeoutMs: 3000, dnsTimeoutMs: 2000, idleTimeoutMs: 10_000, maxTunnelMs: 30_000, maxConcurrentTunnels: 50 });
    const { port } = await gw.listen();
    try {
      const proxied = await browserVia(`http://127.0.0.1:${port}`);
      const { r, manifest } = await capture(proxied, fixture.url('/static'), 30, ['scroll'], `http://127.0.0.1:${port}`);
      expect(r.observation.netError?.egressError).toBe('destination_denied');
      expect(r.observation.contentAppeared).toBe(false);
      expect(manifest.outcome).not.toBe('CONTENT_CAPTURED');
      expect(gw.stats.denied).toBeGreaterThan(0);
    } finally {
      await gw.close();
    }
  });

  it('refuses page subresources and redirects aimed at internal/metadata addresses', async () => {
    const gw = new EgressGateway({
      port: 0, host: '127.0.0.1', allowedPorts: [80, 443, fixture.port, 1], extraDenyCidrs: [], connectTimeoutMs: 3000, dnsTimeoutMs: 2000, idleTimeoutMs: 10_000, maxTunnelMs: 30_000, maxConcurrentTunnels: 50,
      resolve: async (h) => { if (h === 'fixture.test') return ['127.0.0.1']; throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' }); },
      classify: (a) => (a === '127.0.0.1' ? { allowed: true, normalised: a, family: 4 } : classifyAddress(a)),
    });
    const { port } = await gw.listen();
    try {
      const proxied = await browserVia(`http://127.0.0.1:${port}`);
      const probe = await capture(proxied, `http://fixture.test:${fixture.port}/internal-probe`, 30, ['scroll'], `http://127.0.0.1:${port}`);
      expect(probe.manifest.outcome).toBe('CONTENT_CAPTURED');
      const events = (await readFile(join(probe.dir, 'network/events.jsonl'), 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as { type: string; url?: string; status?: number });
      const reachedInternal = events.filter((e) => e.type === 'response' && /10\.0\.0\.1|169\.254\.169\.254|::ffff/.test(e.url ?? '') && e.status === 200);
      expect(reachedInternal).toEqual([]);
      const redirect = await capture(proxied, `http://fixture.test:${fixture.port}/redirect-internal`, 30, ['scroll'], `http://127.0.0.1:${port}`);
      expect(redirect.r.observation.status === 403 || redirect.r.observation.netError !== null || redirect.manifest.outcome !== 'CONTENT_CAPTURED').toBe(true);
      expect(gw.stats.denied).toBeGreaterThanOrEqual(3);
    } finally {
      await gw.close();
    }
  });
});
