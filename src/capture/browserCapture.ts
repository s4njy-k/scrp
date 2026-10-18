/**
 * Staged browser evidence capture (blueprint §9, §10).
 *
 * Screenshot production is a staged evidence workflow with failure handling
 * independent of extraction:
 *   1. isolated context; recorders registered before navigation; profile recorded
 *   2. bounded navigation; a timeout does not discard the surviving page
 *   3. early viewport as soon as a renderable target/challenge state exists
 *   4. bounded content-readiness checks (never networkidle alone)
 *   5. settled viewport + rendered DOM/text (+ accessible frame DOM)
 *   6. controlled scrolling, then full page or bounded tiles
 *   7. element crops with provenance
 *   8. image validation
 *   9. finalisation within the reserved time; per-artifact errors recorded
 */
import type { Browser, BrowserContext, BrowserContextOptions, Page, Response } from 'playwright-core';
import { devices } from 'playwright-core';
import type { Policy } from '../config/policy.js';
import { MiB } from '../config/policy.js';
import type { AttemptWriter } from '../storage/artifactStore.js';
import type { BrowserObservation } from '../router/router.js';
import { classifyNetError, detectAuthWall, detectChallenge, detectPlaceholderPage, parseRetryAfter } from '../router/signals.js';
import type { DomainEdgeInput } from '../queue/queue.js';
import { lookupViaGateway, type EgressConfig } from '../acquisition/egress.js';
import { NetworkRecorder } from './networkRecorder.js';
import { checkPng } from './imageCheck.js';
import { findElementCandidates } from './elements.js';
import type { ArtifactType } from '../acquisition/contract.js';

export interface BrowserCaptureArgs {
  browser: Browser;
  engine: 'chromium' | 'firefox';
  url: string;
  policy: Policy;
  writer: AttemptWriter;
  /** Epoch ms when the whole attempt (including finalisation) must end. */
  deadline: number;
  allowedInteractions: string[];
  captureVariant: string;
  relaxedTls: boolean;
  egress: EgressConfig;
  /** Aborted when the lease is lost: stop target activity immediately. */
  signal: AbortSignal;
  /** Restricted storage state from an earlier attempt of the same target session. */
  storageState?: BrowserContextOptions['storageState'];
  /** Recorded isolation facts of the browser process (sandbox, connect vs local). */
  isolation: { mode: 'connect' | 'local'; chromiumSandbox: boolean };
}

export interface BrowserCaptureResult {
  observation: BrowserObservation;
  finalUrl: string | null;
  edges: DomainEdgeInput[];
  userAgent: string | null;
  engineVersion: string;
  settings: Record<string, unknown>;
  limitations: string[];
}

interface ActionEntry {
  at: string;
  action: string;
  detail?: Record<string, unknown>;
}

const RENDER_INCOMPAT = /(your )?browser (is )?(not supported|unsupported|outdated|too old)|please (use|upgrade|switch to|update) (to )?(a )?(different|modern|newer|supported|latest)? ?(web )?browser|this (site|page) (requires|only works (in|with)) (google )?(chrome|firefox|edge|safari)/i;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}

async function bounded<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`${label} exceeded ${Math.round(ms)}ms (TIMEOUT)`)), Math.max(1, ms));
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export async function captureWithBrowser(args: BrowserCaptureArgs): Promise<BrowserCaptureResult> {
  const { policy, writer, browser } = args;
  const reserveMs = policy.limits.finalisation_reserve_seconds * 1000;
  const workEnd = args.deadline - reserveMs;
  const remaining = () => workEnd - Date.now();
  const stopped = () => args.signal.aborted || remaining() <= 0;
  const actions: ActionEntry[] = [];
  const log = (action: string, detail?: Record<string, unknown>) => actions.push({ at: new Date().toISOString(), action, ...(detail ? { detail } : {}) });
  const limitations: string[] = [];
  const engineVersion = `${args.engine} ${browser.version()}`;

  // ---- 1. Isolated context with a fixed, recorded profile ----
  const mobile = args.captureVariant === 'mobile' && args.engine === 'chromium';
  const mobileDevice = devices['Pixel 7'];
  const contextOptions: BrowserContextOptions = {
    viewport: mobile ? mobileDevice.viewport : policy.capture.viewport,
    deviceScaleFactor: mobile ? mobileDevice.deviceScaleFactor : policy.capture.device_scale_factor,
    isMobile: mobile || undefined,
    hasTouch: mobile || undefined,
    userAgent: mobile ? mobileDevice.userAgent : policy.browser.user_agent ?? undefined,
    locale: policy.browser.locale,
    timezoneId: policy.browser.timezone,
    serviceWorkers: policy.capture.original_service_workers,
    ignoreHTTPSErrors: args.relaxedTls,
    acceptDownloads: false,
    javaScriptEnabled: true,
    bypassCSP: false,
    recordHar: { path: writer.pathFor('network/network.har'), content: 'omit', mode: 'full' },
    ...(args.storageState ? { storageState: args.storageState } : {}),
  };
  if (args.captureVariant === 'mobile' && !mobile) limitations.push(`mobile variant not emulated on ${args.engine}; desktop profile used`);
  if (args.relaxedTls) limitations.push('RELAXED TLS INSPECTION PROFILE: certificate errors ignored for this attempt only');

  const settings = {
    engine: args.engine,
    engine_version: engineVersion,
    viewport: contextOptions.viewport,
    device_scale_factor: contextOptions.deviceScaleFactor,
    mobile,
    locale: contextOptions.locale,
    timezone: contextOptions.timezoneId,
    service_workers: contextOptions.serviceWorkers,
    block_ads: policy.capture.block_ads,
    suppress_render_resources: policy.capture.suppress_render_resources,
    relaxed_tls: args.relaxedTls,
    egress: { proxied: Boolean(args.egress.proxyUrl), vantage: args.egress.vantage },
    allowed_interactions: args.allowedInteractions,
    browser_mode: args.isolation.mode,
    chromium_sandbox: args.engine === 'chromium' ? args.isolation.chromiumSandbox : null,
  };
  if (args.engine === 'chromium' && !args.isolation.chromiumSandbox) limitations.push('Chromium sandbox disabled (local development profile): weaker isolation');
  if (args.isolation.mode === 'local') limitations.push('browser ran inside the driver container (local profile): weaker process/network boundary than the hardened profile');

  let context: BrowserContext | null = null;
  let page: Page | null = null;
  let userAgent: string | null = null;
  let finalUrl: string | null = null;
  let mainResponse: Response | null = null;
  let netError: BrowserObservation['netError'] = null;
  let navigationTimedOut = false;
  let contentAppeared = false;
  let validScreenshots = 0;
  let challengeResolved = false;
  let challenge = { challenge: false, signals: [] as string[] };
  let authSignals: string[] = [];
  let placeholder: ReturnType<typeof detectPlaceholderPage> = { kind: null, signals: [] };
  let visibleTextLength = 0;
  let renderIncompat: string[] = [];
  let recorder: NetworkRecorder | null = null;
  let harOk = false;

  const shot = async (rel: string, type: ArtifactType, opts: { fullPage?: boolean; clip?: { x: number; y: number; width: number; height: number } }, meta: Record<string, unknown> = {}): Promise<boolean> => {
    if (!page || page.isClosed() || recorder?.rendererCrashed) {
      writer.recordMissing({ type, observedStart: null, observedEnd: null, creationMethod: 'page.screenshot', completeness: 'failed', limitations: [], error: 'page closed or renderer crashed', metadata: meta });
      return false;
    }
    const start = new Date().toISOString();
    try {
      // page.screenshot waits for web fonts; on a document that never finishes loading
      // that wait never ends. Keep it short then, and fall back to a raw CDP capture.
      const timeout = Math.max(1000, Math.min(navigationTimedOut ? 4000 : 15_000, remaining() + reserveMs / 3));
      let buf: Buffer;
      let method = `Playwright page.screenshot(${opts.fullPage ? 'fullPage' : opts.clip ? 'clip' : 'viewport'})`;
      const extraLimitations: string[] = [];
      try {
        // Playwright's own timeout is not always honoured on a page stuck mid-navigation: race it too.
        buf = await bounded(page.screenshot({ type: 'png', fullPage: opts.fullPage ?? false, ...(opts.clip ? { clip: opts.clip } : {}), timeout, animations: 'allow', caret: 'initial' }), timeout + 1000, 'page.screenshot');
      } catch (err) {
        if (args.engine !== 'chromium' || opts.fullPage || !/Timeout|fonts/i.test((err as Error).message)) throw err;
        const cdp = await bounded(page.context().newCDPSession(page), 3000, 'CDP session');
        try {
          const r = await bounded(cdp.send('Page.captureScreenshot', { format: 'png', ...(opts.clip ? { clip: { ...opts.clip, scale: 1 } } : {}) }), 6000, 'CDP captureScreenshot');
          buf = Buffer.from(r.data, 'base64');
        } finally {
          await bounded(cdp.detach(), 2000, 'CDP detach').catch(() => undefined);
        }
        method = 'CDP Page.captureScreenshot (Chromium-only fallback)';
        extraLimitations.push(`page.screenshot did not complete (${(err as Error).message.split('\n')[0]?.slice(0, 120)}); raw compositor capture used, fonts may be incomplete`);
      }
      const end = new Date().toISOString();
      const check = checkPng(buf, policy.bounds.max_image_decode_megapixels);
      if (!check.valid) {
        writer.recordMissing({ type, observedStart: start, observedEnd: end, creationMethod: 'page.screenshot', completeness: 'failed', limitations: [], error: `invalid image: ${check.error}`, metadata: meta });
        return false;
      }
      const ok = await writer.writeArtifact(rel, buf, {
        type, observedStart: start, observedEnd: end, creationMethod: method,
        completeness: 'complete', limitations: [...check.warnings, ...extraLimitations],
        metadata: { ...meta, width: check.width, height: check.height, page_url: page.url() },
      });
      if (ok && (type === 'screenshot_early' || type === 'screenshot_settled' || type === 'screenshot_viewport')) validScreenshots += 1;
      return ok;
    } catch (err) {
      writer.recordMissing({ type, observedStart: start, observedEnd: new Date().toISOString(), creationMethod: 'page.screenshot', completeness: 'failed', limitations: [], error: (err as Error).message.slice(0, 500), metadata: meta });
      return false;
    }
  };

  const pageState = async (): Promise<{ title: string; text: string; html: string; hasPassword: boolean; frameUrls: string[] } | null> => {
    if (!page || page.isClosed()) return null;
    try {
      const s = await bounded(page.evaluate(() => ({
        title: document.title,
        text: (document.body?.innerText ?? '').slice(0, 20000),
        textLength: (document.body?.innerText ?? '').length,
        html: document.documentElement.outerHTML.slice(0, 200000),
        hasPassword: Boolean(document.querySelector('input[type="password"]')),
      })), Math.max(500, Math.min(5000, remaining())), 'page state');
      visibleTextLength = s.textLength;
      return { ...s, frameUrls: page.frames().map((f) => f.url()) };
    } catch {
      return null;
    }
  };

  // Lease lost: stop target activity at once by closing the pages (the context is
  // still closed in finally, which flushes the HAR of what was observed so far).
  const onAbort = () => {
    log('lease_lost_stopping_target_activity');
    for (const p of context?.pages() ?? []) p.close().catch(() => undefined);
  };
  args.signal.addEventListener('abort', onAbort, { once: true });

  try {
    context = await bounded(browser.newContext(contextOptions), 15_000, 'newContext');
    if (args.signal.aborted) throw new Error('lease lost before navigation');
    recorder = new NetworkRecorder(writer, policy, (p) => { p.close().catch(() => undefined); });
    recorder.attach(context);
    page = await bounded(context.newPage(), 15_000, 'newPage');
    recorder.attachPage(page, false);
    userAgent = await bounded(page.evaluate(() => navigator.userAgent), 5000, 'userAgent').catch(() => null);
    log('context_created', { user_agent: userAgent });

    // ---- 2. Bounded navigation (exact supplied URL, fragment preserved) ----
    log('navigate', { url: args.url });
    const navTimeout = Math.max(1000, Math.min(policy.browser.navigation_timeout_seconds * 1000, remaining()));
    const navStart = Date.now();
    try {
      mainResponse = await bounded(page.goto(args.url, { waitUntil: 'commit', timeout: navTimeout }), navTimeout + 2000, 'goto (TIMEOUT)');
      log('navigation_committed', { status: mainResponse?.status() ?? null, url: page.url() });
    } catch (err) {
      const message = (err as Error).message.slice(0, 1000);
      const kind = classifyNetError(message);
      log('navigation_error', { message, kind });
      if (kind === 'timeout') {
        navigationTimedOut = true;
        // No document response at all: nothing renderable exists (the page is still
        // about:blank). That is a network timeout, not a salvageable slow page.
        if (recorder.mainDocumentResponses.length === 0) netError = { kind, message };
      } else {
        netError = { kind, message };
      }
    }
    if (!netError) {
      try {
        const dclMs = Math.max(500, navTimeout - (Date.now() - navStart));
        await bounded(page.waitForLoadState('domcontentloaded', { timeout: dclMs }), dclMs + 1000, 'domcontentloaded');
        log('domcontentloaded');
      } catch {
        navigationTimedOut = true;
        log('domcontentloaded_timeout', { note: 'surviving page inspected instead of discarded' });
      }
    }

    // Main-document status/headers: goto response, else the recorder's last main navigation.
    const mainDocs = recorder.mainDocumentResponses;
    const mainStatus = mainResponse?.status() ?? mainDocs.at(-1)?.status ?? null;
    const mainHeaders = mainResponse ? await bounded(mainResponse.allHeaders(), 3000, 'allHeaders').catch(() => mainResponse!.headers()) : mainDocs.at(-1)?.headers ?? {};

    // Gateway refusals of absolute-form http:// arrive as a response with X-Egress-Error.
    // Only trusted when this attempt is actually proxied (a site could send the header itself).
    const egressHeader = args.egress.proxyUrl ? mainHeaders['x-egress-error'] ?? null : null;
    let egressRefused = false;
    if (egressHeader || (netError && (netError.kind === 'proxy_tunnel' || netError.kind === 'other' || netError.kind === 'dns'))) {
      const u = new URL(args.url);
      const look = await lookupViaGateway(args.egress, u.hostname, Number(u.port || (u.protocol === 'https:' ? 443 : 80)));
      if (look && !look.allowed && look.error) {
        netError = { kind: classifyNetError(look.error), message: netError?.message ?? `gateway refused: ${look.error}`, egressError: look.error };
        egressRefused = true;
        log('gateway_lookup', { error: look.error, reason: look.reason });
      } else if (egressHeader) {
        netError = { kind: classifyNetError(egressHeader), message: `gateway refused (unconfirmed by lookup): ${egressHeader}`, egressError: egressHeader };
        egressRefused = true;
      } else if (netError?.kind === 'proxy_tunnel') {
        netError = { ...netError, kind: 'refused' };
      }
    }
    if (egressRefused) mainResponse = null; // the gateway's refusal page is not target content
    let currentStatus = egressRefused ? null : mainStatus;
    let currentHeaders: Record<string, string> = egressRefused ? {} : mainHeaders;

    // ---- 3. Early viewport (also preserves a challenge or error state) ----
    if (!netError || mainResponse) {
      const st = await pageState();
      contentAppeared = Boolean(st && (st.text.trim().length > 0 || /<(img|canvas|svg|video|iframe)\b/i.test(st.html)));
      await shot('screenshots/01-early-viewport.png', 'screenshot_early', {}, { stage: 'early', navigation_timed_out: navigationTimedOut, note: 'observation, not proof that loading completed' });
      log('early_screenshot');
      if (st) {
        challenge = detectChallenge({ headers: mainHeaders, html: st.html, title: st.title, visibleTextLength: st.text.length, frameUrls: st.frameUrls });
        if (challenge.challenge) log('challenge_detected', { signals: challenge.signals });
      }
    } else {
      // Navigation failed outright: still attempt a best-effort screenshot of the error state
      // unless the renderer is dead (it shows the browser error page, labelled as such).
      await shot('screenshots/01-error-state.png', 'screenshot_early', {}, {
        stage: 'navigation_error', not_target_content: true,
        note: egressRefused ? 'egress gateway refusal page; not target content' : 'browser error page; not target content',
      });
      validScreenshots = 0; // an error page is not a renderable target state
    }

    // ---- Bounded ordinary challenge completion (no CAPTCHA solving, no clicks) ----
    if (challenge.challenge && !stopped()) {
      const waitUntil = Date.now() + Math.min(policy.browser.challenge_wait_seconds * 1000, Math.max(0, remaining() - 15_000));
      log('challenge_wait_start', { max_ms: Math.max(0, waitUntil - Date.now()) });
      while (Date.now() < waitUntil && !stopped()) {
        await sleep(1000);
        const st = await pageState();
        if (!st) break;
        const again = detectChallenge({ html: st.html, title: st.title, visibleTextLength: st.text.length, frameUrls: st.frameUrls });
        if (!again.challenge) {
          challengeResolved = true;
          log('challenge_cleared_by_ordinary_browser_completion', { url: page.url() });
          break;
        }
      }
      if (!challengeResolved) log('challenge_unresolved');
    }

    if (!netError || mainResponse) {
      // ---- 4. Bounded content readiness (load, DOM quiet, fonts, viewport images) ----
      if (!stopped()) {
        const readinessMs = Math.max(0, Math.min(policy.browser.readiness_max_seconds * 1000, remaining() - 10_000));
        const t0 = Date.now();
        let loadFired = false;
        try {
          await bounded(page.waitForLoadState('load', { timeout: Math.max(1, readinessMs) }), Math.max(1, readinessMs) + 1000, 'load');
          loadFired = true;
        } catch { /* bounded */ }
        const left = Math.max(0, readinessMs - (Date.now() - t0));
        const readiness = await bounded(page.evaluate(async ({ quietMs, maxMs }) => {
          const start = performance.now();
          let last = performance.now();
          const obs = new MutationObserver(() => { last = performance.now(); });
          obs.observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
          while (performance.now() - last < quietMs && performance.now() - start < maxMs) {
            await new Promise((r) => setTimeout(r, 100));
          }
          obs.disconnect();
          const fontsStatus = document.fonts ? document.fonts.status : 'unsupported';
          const vh = innerHeight;
          const imgs = Array.from(document.images).filter((i) => { const r = i.getBoundingClientRect(); return r.bottom > 0 && r.top < vh && r.width > 0; });
          return {
            dom_quiet: performance.now() - last >= quietMs,
            waited_ms: Math.round(performance.now() - start),
            fonts_status: fontsStatus,
            viewport_images: imgs.length,
            viewport_images_incomplete: imgs.filter((i) => !i.complete).length,
            loader_visible: Boolean(Array.from(document.querySelectorAll('[class*="loader" i],[class*="spinner" i],[id*="loader" i],[aria-busy="true"]'))
              .find((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).display !== 'none'; })),
          };
        }, { quietMs: policy.browser.readiness_quiet_ms, maxMs: left }), left + 3000, 'readiness').catch((err: Error) => ({ error: err.message }));
        log('readiness', { load_event: loadFired, ...readiness });
      }

      // ---- 5. Settled viewport, rendered DOM/text, frame DOM ----
      if (!stopped()) {
        await shot('screenshots/02-settled-viewport.png', 'screenshot_settled', {}, { stage: 'settled' });
        log('settled_screenshot');
      }
      if (!args.signal.aborted) await saveDomAndText(page, writer, policy, remaining, log, limitations);
      // The document now shown may differ from the first one (challenge auto-completion,
      // JS/meta redirects): judge status and headers by the latest main-frame document.
      const latest = recorder.mainDocumentResponses.at(-1);
      if (latest && !egressRefused) {
        currentStatus = latest.status;
        currentHeaders = latest.headers;
      }
      const st = await pageState();
      if (st) {
        contentAppeared ||= st.text.trim().length > 0;
        authSignals = detectAuthWall({ status: currentStatus, hasPasswordField: st.hasPassword, headers: currentHeaders });
        renderIncompat = RENDER_INCOMPAT.test(st.text) ? ['page_text:browser_unsupported'] : [];
        placeholder = detectPlaceholderPage({ html: st.html, text: st.text, title: st.title });
        if (challengeResolved) {
          challenge = detectChallenge({ html: st.html, title: st.title, visibleTextLength: st.text.length, frameUrls: st.frameUrls });
        }
      }

      // ---- 6. Controlled scrolling, then full page or bounded tiles ----
      if (!stopped()) await captureFullOrTiles(page, args, shot, remaining, log, limitations);

      // ---- 7. Element crops with provenance ----
      if (!stopped() && policy.bounds.max_element_captures > 0) await captureElements(page, args, remaining, log);
    }

    finalUrl = page.url();
    const result: BrowserObservation = {
      netError: contentAppeared ? null : netError,
      status: currentStatus,
      challenge,
      challengeResolvedDuringWait: challengeResolved && !challenge.challenge,
      authSignals,
      contentAppeared,
      navigationTimedOut,
      rendererCrashed: recorder.rendererCrashed,
      renderingIncompatibilitySignals: renderIncompat,
      validScreenshots,
      requiredSatisfied: false, // computed from the hashed manifest by the worker
      missingRequired: [],
      visibleTextLength,
      retryAfterSeconds: parseRetryAfter(currentHeaders['retry-after'] ?? null),
      placeholder,
    };
    if (args.signal.aborted) limitations.push('lease lost during capture: target activity stopped early');
    return { observation: result, finalUrl, edges: recorder.edges, userAgent, engineVersion, settings, limitations };
  } catch (err) {
    log('capture_error', { message: (err as Error).message.slice(0, 1000) });
    const message = (err as Error).message;
    const crashed = recorder?.rendererCrashed || /crash|Target closed|has been closed/i.test(message);
    return {
      observation: {
        netError: crashed ? null : { kind: classifyNetError(message), message: message.slice(0, 1000) },
        status: mainResponse?.status() ?? null, challenge, challengeResolvedDuringWait: false, authSignals,
        contentAppeared, navigationTimedOut, rendererCrashed: Boolean(crashed), renderingIncompatibilitySignals: renderIncompat,
        validScreenshots, requiredSatisfied: false, missingRequired: [], visibleTextLength, retryAfterSeconds: null,
      },
      finalUrl: page && !page.isClosed() ? page.url() : finalUrl,
      edges: recorder?.edges ?? [],
      userAgent,
      engineVersion,
      settings,
      limitations: (limitations.push(`capture aborted by error: ${message.slice(0, 300)}`), limitations),
    };
  } finally {
    args.signal.removeEventListener('abort', onAbort);
    // ---- 9. Finalisation inside the reserved window ----
    const finalStart = Date.now();
    const finalBudget = () => Math.max(500, args.deadline - Date.now());
    recorder?.stop();
    if (context) {
      try {
        const state = await bounded(context.storageState(), Math.min(3000, finalBudget()), 'storageState');
        await writer.writeArtifact('session/storage-state.json', JSON.stringify(state), {
          type: 'session_state', observedStart: new Date().toISOString(), observedEnd: new Date().toISOString(),
          creationMethod: 'BrowserContext.storageState()', completeness: 'complete', restricted: true,
          limitations: ['RESTRICTED: cookies/tokens; excluded from general logs and ordinary exports'],
        });
      } catch (err) {
        writer.recordMissing({ type: 'session_state', observedStart: null, observedEnd: null, creationMethod: 'BrowserContext.storageState()', completeness: 'failed', limitations: [], error: (err as Error).message.slice(0, 300) });
      }
      try {
        // Closing the context flushes the HAR file.
        await bounded(context.close(), Math.min(10_000, finalBudget()), 'context close / HAR flush');
        harOk = true;
      } catch (err) {
        limitations.push(`context close/HAR flush failed: ${(err as Error).message.slice(0, 200)}`);
        // Do not leave a stuck context open in the shared browser.
        context.close().catch(() => undefined);
      }
    }
    if (harOk) {
      writer.registerExternalFile('network/network.har', {
        type: 'har', observedStart: actions[0]?.at ?? null, observedEnd: new Date().toISOString(),
        creationMethod: `Playwright recordHar (mode=full, content=omit) on ${args.engine}`, completeness: 'complete', restricted: true,
        limitations: [
          'bodies omitted from HAR; retained bodies are under bodies/ with explicit omission records in network/events.jsonl',
          'HAR is not packet capture or traceroute; non-HTTP protocols are not represented',
          'RESTRICTED: contains request/response cookies and headers',
        ],
      });
    } else {
      writer.recordMissing({ type: 'har', observedStart: null, observedEnd: null, creationMethod: 'Playwright recordHar', completeness: 'failed', limitations: [], error: 'HAR not flushed within finalisation reserve' });
    }
    const net = recorder ? await recorder.end() : { bytes: 0, truncated: true };
    if (recorder) {
      writer.registerExternalFile('network/events.jsonl', {
        type: 'network_events', observedStart: actions[0]?.at ?? null, observedEnd: new Date().toISOString(),
        creationMethod: 'BrowserContext/Page event listeners registered before navigation',
        completeness: net.truncated ? 'truncated' : 'complete',
        limitations: [
          ...(net.truncated ? ['event recording truncated by policy bounds (see recorder_truncated record)'] : []),
          'only what this browser session observed; hidden backend connections and other visitors\' variants are not visible',
          ...(args.engine !== 'chromium' ? ['Chromium-only CDP details unavailable on this engine'] : []),
        ],
        metadata: { ...recorder.stats },
      });
      if (recorder.console.length) {
        await writer.writeArtifact('logs/console.jsonl', `${recorder.console.join('\n')}\n`, {
          type: 'console_log', observedStart: actions[0]?.at ?? null, observedEnd: new Date().toISOString(),
          creationMethod: 'page console/pageerror events (bounded)', completeness: recorder.console.length >= policy.bounds.max_console_messages ? 'truncated' : 'complete', limitations: [],
        });
      }
    }
    const pendingAtDeadline = await writer.settle(Math.max(500, args.deadline - Date.now()));
    if (pendingAtDeadline > 0) limitations.push(`${pendingAtDeadline} artifact write(s) still pending at the finalisation deadline; marked incomplete`);
    log('finalised', { finalisation_ms: Date.now() - finalStart, pending_writes: pendingAtDeadline });
    await writer.writeArtifact('logs/action-log.json', JSON.stringify({ actions, limitations }, null, 2), {
      type: 'action_log', observedStart: actions[0]?.at ?? null, observedEnd: new Date().toISOString(),
      creationMethod: 'collector action log', completeness: 'complete', limitations: [],
    }).catch(() => undefined);
    await writer.writeArtifact('attempt-metadata.json', JSON.stringify({ ...settings, user_agent: userAgent, requested_url: args.url, final_url: finalUrl, limitations }, null, 2), {
      type: 'attempt_metadata', observedStart: actions[0]?.at ?? null, observedEnd: new Date().toISOString(),
      creationMethod: 'collector', completeness: 'complete', limitations: [],
    }).catch(() => undefined);
  }
}

async function saveDomAndText(page: Page, writer: AttemptWriter, policy: Policy, remaining: () => number, log: (a: string, d?: Record<string, unknown>) => void, limitations: string[]): Promise<void> {
  const maxDom = Math.floor(policy.bounds.max_dom_snapshot_mib * MiB);
  const start = new Date().toISOString();
  const budget = () => Math.max(1000, Math.min(10_000, remaining() + 5000));
  try {
    let html = await bounded(page.content(), budget(), 'page.content');
    const truncated = Buffer.byteLength(html) > maxDom;
    if (truncated) html = Buffer.from(html).subarray(0, maxDom).toString('utf8');
    await writer.writeArtifact('dom/rendered.html', html, {
      type: 'rendered_dom', observedStart: start, observedEnd: new Date().toISOString(), creationMethod: 'Playwright page.content() (serialised live DOM)',
      completeness: truncated ? 'truncated' : 'complete',
      limitations: [...(truncated ? [`truncated at ${maxDom} bytes`] : []), 'closed shadow roots and canvas pixels are not represented in serialised DOM'],
      metadata: { url: page.url() },
    });
  } catch (err) {
    writer.recordMissing({ type: 'rendered_dom', observedStart: start, observedEnd: null, creationMethod: 'page.content()', completeness: 'failed', limitations: [], error: (err as Error).message.slice(0, 300) });
  }
  const tStart = new Date().toISOString();
  try {
    const text = await bounded(page.evaluate(() => document.body?.innerText ?? ''), budget(), 'innerText');
    await writer.writeArtifact('dom/rendered.txt', text, {
      type: 'rendered_text', observedStart: tStart, observedEnd: new Date().toISOString(), creationMethod: 'document.body.innerText (main frame)',
      completeness: 'complete', limitations: text.length === 0 ? ['empty visible text: may be a legitimate sparse/image-only page'] : [],
      metadata: { empty_is_legitimate: true },
    });
  } catch (err) {
    writer.recordMissing({ type: 'rendered_text', observedStart: tStart, observedEnd: null, creationMethod: 'innerText', completeness: 'failed', limitations: [], error: (err as Error).message.slice(0, 300) });
  }
  const frames = page.frames().filter((f) => f !== page.mainFrame()).slice(0, policy.bounds.max_frames_per_page);
  if (page.frames().length - 1 > frames.length) limitations.push(`frame DOM capture limited to ${frames.length} frames`);
  let idx = 0;
  for (const f of frames) {
    if (remaining() < 3000) {
      limitations.push('frame DOM capture stopped: attempt time budget');
      break;
    }
    idx += 1;
    const fStart = new Date().toISOString();
    try {
      const html = await bounded(f.content(), Math.min(4000, remaining()), 'frame.content');
      const capped = Buffer.byteLength(html) > maxDom ? Buffer.from(html).subarray(0, maxDom).toString('utf8') : html;
      await writer.writeArtifact(`dom/frames/${String(idx).padStart(3, '0')}.html`, capped, {
        type: 'frame_dom', observedStart: fStart, observedEnd: new Date().toISOString(), creationMethod: 'Playwright frame.content()',
        completeness: capped.length < html.length ? 'truncated' : 'complete', limitations: [],
        metadata: { frame_url: f.url(), frame_name: f.name(), parent_url: f.parentFrame()?.url() ?? null },
      });
    } catch (err) {
      writer.recordMissing({ type: 'frame_dom', observedStart: fStart, observedEnd: null, creationMethod: 'frame.content()', completeness: 'failed', limitations: [], error: (err as Error).message.slice(0, 200), metadata: { frame_url: f.url() } });
    }
  }
  log('dom_saved', { frames: idx });
}

type ShotFn = (rel: string, type: ArtifactType, opts: { fullPage?: boolean; clip?: { x: number; y: number; width: number; height: number } }, meta?: Record<string, unknown>) => Promise<boolean>;

async function captureFullOrTiles(page: Page, args: BrowserCaptureArgs, shot: ShotFn, remaining: () => number, log: (a: string, d?: Record<string, unknown>) => void, limitations: string[]): Promise<void> {
  const { policy, writer } = args;
  const dims = async () => bounded(page.evaluate(() => ({
    w: Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth ?? 0),
    h: Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight ?? 0),
    vh: innerHeight, vw: innerWidth,
  })), 3000, 'dimensions');
  let d: { w: number; h: number; vh: number; vw: number };
  try {
    d = await dims();
  } catch (err) {
    writer.recordMissing({ type: 'screenshot_full_or_tiles', observedStart: null, observedEnd: null, creationMethod: 'page.screenshot', completeness: 'failed', limitations: [], error: (err as Error).message.slice(0, 200) });
    return;
  }
  let infinite = false;
  if (args.allowedInteractions.includes('scroll')) {
    // Controlled scrolling to trigger lazy images/content; fullPage alone does not.
    let lastH = d.h;
    let growth = 0;
    for (let i = 1; i <= policy.bounds.max_scroll_steps && remaining() > 8000; i += 1) {
      const y = i * d.vh;
      await bounded(page.evaluate((yy) => window.scrollTo(0, yy), y), 3000, 'scroll').catch(() => undefined);
      await sleep(policy.browser.scroll_step_wait_ms);
      const nd = await dims().catch(() => d);
      if (nd.h > lastH) growth += 1;
      lastH = nd.h;
      log('scroll', { y, page_height: nd.h });
      if (y + d.vh >= nd.h) break;
      if (i === policy.bounds.max_scroll_steps && nd.h > y + d.vh) infinite = growth >= 2;
    }
    await bounded(page.evaluate(() => window.scrollTo(0, 0)), 3000, 'scroll').catch(() => undefined);
    await sleep(policy.browser.scroll_step_wait_ms);
    d = await dims().catch(() => d);
    log('scroll_reset', { page_height: d.h, infinite_or_virtualised_suspected: infinite });
  } else {
    limitations.push('scrolling not permitted for this job: lazy-loaded content may be absent');
  }

  const dpr = args.captureVariant === 'mobile' ? (devices['Pixel 7'].deviceScaleFactor ?? 1) : policy.capture.device_scale_factor;
  const fullMp = (d.w * d.h * dpr * dpr) / 1e6;
  if (fullMp <= policy.capture.full_image_megapixels_max && remaining() > 5000 && !infinite) {
    const ok = await shot('screenshots/03-full-page.png', 'screenshot_full_or_tiles', { fullPage: true }, {
      stage: 'full_page', page_width: d.w, page_height: d.h, megapixels: Number(fullMp.toFixed(2)),
      note: 'fullPage after controlled scrolling; virtualised/off-screen data not guaranteed',
    });
    log('full_page_screenshot', { ok, megapixels: fullMp });
    return;
  }
  // Over budget (or infinite/virtualised): bounded viewport tiles with positions and timestamps.
  const tiles: { index: number; y: number; path: string | null; at: string }[] = [];
  const maxTiles = policy.capture.scroll_tiles_max;
  for (let i = 0; i < maxTiles && remaining() > 4000; i += 1) {
    const y = i * d.vh;
    if (y >= d.h) break;
    await bounded(page.evaluate((yy) => window.scrollTo(0, yy), y), 3000, 'scroll').catch(() => undefined);
    await sleep(policy.browser.scroll_step_wait_ms);
    const rel = `screenshots/tiles/${String(i + 1).padStart(2, '0')}.png`;
    const at = new Date().toISOString();
    const ok = await shot(rel, 'screenshot_tile', {}, { tile_index: i + 1, scroll_y: y, viewport_height: d.vh });
    tiles.push({ index: i + 1, y, path: ok ? rel : null, at });
  }
  await bounded(page.evaluate(() => window.scrollTo(0, 0)), 3000, 'scroll').catch(() => undefined);
  const covered = tiles.length * d.vh;
  const truncated = covered < d.h || infinite;
  const reason = infinite ? 'infinite/virtualised content: bounded sample, NOT the entire page'
    : fullMp > policy.capture.full_image_megapixels_max ? `full page ${fullMp.toFixed(1)} MP exceeds ${policy.capture.full_image_megapixels_max} MP budget` : 'time budget';
  await writer.writeArtifact('screenshots/tiles/index.json', JSON.stringify({ page_width: d.w, page_height: d.h, viewport_height: d.vh, tiles, truncated, reason }, null, 2), {
    type: 'screenshot_full_or_tiles', observedStart: tiles[0]?.at ?? null, observedEnd: new Date().toISOString(),
    creationMethod: 'viewport tiles at recorded scroll positions', completeness: truncated ? 'truncated' : 'complete',
    limitations: [reason, 'tiles are separate observations at different times'],
  });
  if (truncated) limitations.push(`page coverage truncated: ${reason}`);
  log('tiles_captured', { tiles: tiles.length, truncated, reason });
}

async function captureElements(page: Page, args: BrowserCaptureArgs, remaining: () => number, log: (a: string, d?: Record<string, unknown>) => void): Promise<void> {
  const { policy, writer } = args;
  let total = 0;
  const frames = [page.mainFrame(), ...page.frames().filter((f) => f !== page.mainFrame()).slice(0, 5)];
  for (const frame of frames) {
    if (total >= policy.bounds.max_element_captures || remaining() < 4000) break;
    let candidates;
    try {
      candidates = await findElementCandidates(frame, policy.bounds.max_element_captures - total, Math.min(4000, remaining()));
    } catch (err) {
      log('element_search_failed', { frame_url: frame.url(), error: (err as Error).message.slice(0, 200) });
      continue;
    }
    for (const c of candidates) {
      if (total >= policy.bounds.max_element_captures || remaining() < 3000) break;
      total += 1;
      const rel = `elements/${String(total).padStart(2, '0')}-${c.kind}.png`;
      const start = new Date().toISOString();
      const meta = { kind: c.kind, locator: c.selector, frame_url: frame.url(), bbox_at_discovery: c.bbox, context: c.context, note: c.note ?? null };
      try {
        const loc = frame.locator(c.selector).first();
        const shotMs = Math.max(500, Math.min(4000, remaining()));
        const buf = await bounded(loc.screenshot({ type: 'png', timeout: shotMs, animations: 'allow' }), shotMs + 1000, 'locator.screenshot');
        const box = await bounded(loc.boundingBox(), 2000, 'boundingBox').catch(() => null);
        const check = checkPng(buf, policy.bounds.max_image_decode_megapixels);
        if (!check.valid) throw new Error(`invalid element image: ${check.error}`);
        await writer.writeArtifact(rel, buf, {
          type: 'element_crop', observedStart: start, observedEnd: new Date().toISOString(),
          creationMethod: 'Playwright locator.screenshot() (live element; separate observation from page screenshots)',
          completeness: 'complete', limitations: [...check.warnings, ...(c.kind === 'canvas' || c.note?.startsWith('canvas') ? ['canvas: rendered pixels only; DOM extraction not possible'] : [])],
          metadata: { ...meta, bbox: box, width: check.width, height: check.height },
        });
      } catch (err) {
        writer.recordMissing({ type: 'element_crop', observedStart: start, observedEnd: new Date().toISOString(), creationMethod: 'locator.screenshot()', completeness: 'failed', limitations: [], error: (err as Error).message.slice(0, 200), metadata: meta });
      }
    }
  }
  log('elements_captured', { count: total });
}
