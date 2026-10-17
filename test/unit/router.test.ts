import { describe, expect, it } from 'vitest';
import { classifyBrowser, classifyHttp, decideAfterBrowser, decideAfterHttp, type BrowserObservation, type HttpObservation, type RouterJob } from '../../src/router/router.js';
import { detectChallenge, detectJsShell, parseRetryAfter, classifyNetError } from '../../src/router/signals.js';
import { canRunStage, attemptSecondsFor } from '../../src/router/budget.js';
import { evaluateRequired, processingStateFor, type ManifestEntry } from '../../src/acquisition/contract.js';
import { testPolicy } from '../helpers.js';

const policy = testPolicy();
const rand = () => 0.5;

const job = (over: Partial<RouterJob> = {}): RouterJob => ({
  profile: 'browser_evidence', stage: 'http', urgent: false, classification: null, scope: {},
  http_attempts: 1, browser_attempts: 0, active_seconds_used: 0, alternate_used: false, ...over,
});

const httpObs = (over: Partial<HttpObservation> = {}): HttpObservation => ({
  status: 200, contentType: 'text/html', bodyText: '<html><body>' + 'content '.repeat(100) + '</body></html>', bodyBytes: 900, netError: null,
  challenge: { challenge: false, signals: [] }, authSignals: [], jsShellSignals: [], visibleTextLength: 800, retryAfterSeconds: null, ...over,
});

const brObs = (over: Partial<BrowserObservation> = {}): BrowserObservation => ({
  netError: null, status: 200, challenge: { challenge: false, signals: [] }, challengeResolvedDuringWait: false, authSignals: [],
  contentAppeared: true, navigationTimedOut: false, rendererCrashed: false, renderingIncompatibilitySignals: [], validScreenshots: 2,
  requiredSatisfied: true, missingRequired: [], visibleTextLength: 900, retryAfterSeconds: null, ...over,
});

describe('challenge and content signals (§8)', () => {
  it('recognises cf-mitigated: challenge', () => {
    expect(detectChallenge({ headers: { 'cf-mitigated': 'challenge' }, html: '<p>x</p>' }).challenge).toBe(true);
  });
  it('does not treat a Cloudflare server header alone as blocking', () => {
    expect(detectChallenge({ headers: { server: 'cloudflare', 'cf-ray': 'abc' }, html: '<title>Shop</title><p>' + 'x'.repeat(1000) + '</p>' }).challenge).toBe(false);
  });
  it('ignores a CAPTCHA widget embedded in a rich page but flags it on a near-empty page', () => {
    const widget = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>';
    expect(detectChallenge({ html: `${widget}<form>${'<p>real content here</p>'.repeat(60)}</form>` }).challenge).toBe(false);
    expect(detectChallenge({ html: `${widget}<p>verify</p>` }).challenge).toBe(true);
  });
  it('detects a JS application shell', () => {
    expect(detectJsShell('<div id="root"></div><script src="a.js"></script>').length).toBeGreaterThan(0);
    expect(detectJsShell(`<p>${'word '.repeat(200)}</p>`)).toEqual([]);
  });
  it('parses Retry-After seconds and dates', () => {
    expect(parseRetryAfter('120')).toBe(120);
    expect(parseRetryAfter(new Date(Date.now() + 60_000).toUTCString())).toBeGreaterThan(50);
    expect(parseRetryAfter('soon')).toBeNull();
  });
  it('maps browser network errors', () => {
    expect(classifyNetError('net::ERR_NAME_NOT_RESOLVED')).toBe('dns');
    expect(classifyNetError('net::ERR_CERT_AUTHORITY_INVALID')).toBe('tls');
    expect(classifyNetError('net::ERR_TUNNEL_CONNECTION_FAILED')).toBe('proxy_tunnel');
    expect(classifyNetError('destination_denied')).toBe('proxy_denied');
    expect(classifyNetError('Timeout 30000ms exceeded')).toBe('timeout');
  });
});

describe('HTTP routing', () => {
  it('HTTP 200 challenge is a challenge outcome, never successful data', () => {
    const c = classifyHttp(httpObs({ status: 200, challenge: { challenge: true, signals: ['title:cloudflare'] } }));
    expect(c.outcome).toBe('CHALLENGE_PAGE_CAPTURED');
  });
  it('API returning HTML is incomplete, not data', () => {
    expect(classifyHttp(httpObs({ expectedJson: true })).classification).toBe('api_returned_html');
  });
  it('a 403 without challenge evidence is an access denial, not bot detection', () => {
    expect(classifyHttp(httpObs({ status: 403 })).classification).toBe('access_denied');
  });
  it('browser evidence still requires the browser after usable HTML', () => {
    const d = decideAfterHttp(job(), classifyHttp(httpObs()), 2, policy, rand);
    expect(d).toMatchObject({ kind: 'continue', stage: 'browser_primary' });
  });
  it('data_triage completes from HTTP alone and never escalates to the browser', () => {
    expect(decideAfterHttp(job({ profile: 'data_triage' }), classifyHttp(httpObs()), 2, policy, rand)).toMatchObject({ kind: 'finish', state: 'COMPLETE' });
    const shell = classifyHttp(httpObs({ jsShellSignals: ['empty_mount_node'], visibleTextLength: 10 }));
    expect(decideAfterHttp(job({ profile: 'data_triage' }), shell, 2, policy, rand)).toMatchObject({ kind: 'finish', state: 'PARTIAL' });
  });
  it('429 honours Retry-After as a deferral without holding a slot', () => {
    const d = decideAfterHttp(job(), classifyHttp(httpObs({ status: 429, retryAfterSeconds: 120 })), 1, policy, rand);
    expect(d).toMatchObject({ kind: 'continue', state: 'DEFERRED', delaySeconds: 120, domainBackoffSeconds: 120 });
  });
  it('DNS failure is not retried against every engine', () => {
    const c = classifyHttp(httpObs({ status: null, netError: { kind: 'dns', message: 'ENOTFOUND' } }));
    expect(decideAfterHttp(job(), c, 1, policy, rand)).toMatchObject({ kind: 'finish', state: 'FAILED_FINAL', outcome: 'DNS_FAILURE' });
  });
  it('egress policy denial goes to manual review', () => {
    const c = classifyHttp(httpObs({ status: null, netError: { kind: 'proxy_denied', message: 'x', egressError: 'destination_denied' } }));
    expect(decideAfterHttp(job(), c, 1, policy, rand)).toMatchObject({ kind: 'finish', state: 'MANUAL_REVIEW' });
  });
  it('an HTTP timeout is not proof the browser visit fails', () => {
    const c = classifyHttp(httpObs({ status: null, netError: { kind: 'timeout', message: 'timeout' } }));
    expect(decideAfterHttp(job(), c, 15, policy, rand)).toMatchObject({ kind: 'continue', stage: 'browser_primary' });
  });
  it('TLS failure on a data-triage domain seed spawns the separate HTTP scheme candidate', () => {
    const c = classifyHttp(httpObs({ status: null, netError: { kind: 'tls', message: 'CERT_HAS_EXPIRED' } }));
    expect(decideAfterHttp(job({ profile: 'data_triage' }), c, 1, policy, rand)).toMatchObject({ kind: 'finish', outcome: 'TLS_FAILURE', spawnSchemeFallback: true });
  });
});

describe('browser routing', () => {
  it('content captured with the full contract is COMPLETE', () => {
    expect(decideAfterBrowser(job({ stage: 'browser_primary', browser_attempts: 1 }), classifyBrowser(brObs()), brObs(), 20, policy, rand)).toMatchObject({ kind: 'finish', state: 'COMPLETE' });
  });
  it('navigation timeout with a usable page is salvaged as PARTIAL', () => {
    const o = brObs({ navigationTimedOut: true, requiredSatisfied: false, missingRequired: ['har'] });
    const c = classifyBrowser(o);
    expect(c.classification).toBe('navigation_timeout_salvaged');
    expect(decideAfterBrowser(job({ stage: 'browser_primary', browser_attempts: 1 }), c, o, 60, policy, rand)).toMatchObject({ kind: 'finish', state: 'PARTIAL' });
  });
  it('unresolved challenge gets one alternate engine, then manual review', () => {
    const o = brObs({ status: 403, challenge: { challenge: true, signals: ['header:cf-mitigated=challenge'] } });
    const c = classifyBrowser(o);
    expect(c.outcome).toBe('CHALLENGE_PAGE_CAPTURED');
    expect(decideAfterBrowser(job({ stage: 'browser_primary', browser_attempts: 1, http_attempts: 1 }), c, o, 30, policy, rand)).toMatchObject({ kind: 'continue', stage: 'browser_alternate' });
    expect(decideAfterBrowser(job({ stage: 'browser_alternate', browser_attempts: 2, http_attempts: 1, alternate_used: true }), c, o, 30, policy, rand)).toMatchObject({ kind: 'finish', state: 'MANUAL_REVIEW' });
  });
  it('a saved error screenshot never turns ACCESS_BLOCKED into COMPLETE', () => {
    const o = brObs({ status: 403 });
    const c = classifyBrowser(o);
    expect(c.outcome).toBe('ACCESS_BLOCKED');
    expect(processingStateFor(c.outcome, true, true)).toBeNull();
    const d = decideAfterBrowser(job({ stage: 'browser_alternate', browser_attempts: 2, alternate_used: true }), c, o, 30, policy, rand);
    expect(d).toMatchObject({ kind: 'finish', state: 'FAILED_FINAL', outcome: 'ACCESS_BLOCKED' });
  });
  it('rendering incompatibility selects Firefox once instead of an extra unconditional tier', () => {
    const o = brObs({ renderingIncompatibilitySignals: ['page_text:browser_unsupported'], visibleTextLength: 100 });
    expect(decideAfterBrowser(job({ stage: 'browser_primary', browser_attempts: 1 }), classifyBrowser(o), o, 20, policy, rand)).toMatchObject({ stage: 'browser_alternate' });
  });
});

describe('shared budget prevents retry multiplication (§8)', () => {
  it('caps attempts across phases', () => {
    expect(canRunStage(job({ http_attempts: 2, browser_attempts: 2 }), 'browser_primary', policy)).toBe(false);
    expect(canRunStage(job({ http_attempts: 2, browser_attempts: 1 }), 'browser_primary', policy)).toBe(true);
    expect(canRunStage(job({ http_attempts: 2 }), 'http', policy)).toBe(false);
    expect(canRunStage(job({ browser_attempts: 1, alternate_used: true }), 'browser_alternate', policy)).toBe(false);
  });
  it('caps cumulative active seconds and per-attempt time', () => {
    expect(canRunStage(job({ active_seconds_used: 175 }), 'browser_primary', policy)).toBe(false);
    expect(attemptSecondsFor(job({ active_seconds_used: 150 }), 'browser_primary', policy)).toBe(30);
    expect(attemptSecondsFor(job(), 'browser_alternate', policy)).toBe(90);
  });
  it('no decision path escalates beyond the budget', () => {
    const exhausted = job({ stage: 'browser_primary', http_attempts: 2, browser_attempts: 2, active_seconds_used: 170 });
    const kinds = ['timeout', 'refused', 'reset'] as const;
    for (const kind of kinds) {
      const o = brObs({ netError: { kind, message: kind }, contentAppeared: false, validScreenshots: 0 });
      expect(decideAfterBrowser(exhausted, classifyBrowser(o), o, 5, policy, rand).kind).toBe('finish');
    }
  });
});

describe('required artifact contract', () => {
  const e = (type: ManifestEntry['type'], completeness: ManifestEntry['completeness'] = 'complete', path: string | null = 'x'): ManifestEntry => ({
    type, path, sizeBytes: 1, sha256: path ? 'h' : null, observedStart: null, observedEnd: null, creationMethod: 't', completeness, limitations: [],
  });
  it('requires actual validated files; failures do not satisfy', () => {
    const req = ['screenshot_viewport', 'rendered_dom', 'har', 'manifest'];
    expect(evaluateRequired(req, [e('screenshot_settled'), e('rendered_dom'), e('har', 'truncated')]).satisfied).toBe(true);
    expect(evaluateRequired(req, [e('screenshot_settled', 'failed', null), e('rendered_dom'), e('har')]).missing).toEqual(['screenshot_viewport']);
    expect(evaluateRequired(req, [e('screenshot_settled'), e('rendered_dom', 'truncated'), e('har')]).missing).toEqual(['rendered_dom']);
  });
});
