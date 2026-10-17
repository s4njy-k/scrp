/**
 * Failure-specific acquisition router (blueprint §8). Pure functions: given the
 * observation of one attempt and the job's budget, decide outcome and next
 * step. Never escalates beyond the shared budget; never runs every engine
 * against the same confirmed error.
 */
import type { Policy } from '../config/policy.js';
import type { AcquisitionOutcome, JobStage } from '../acquisition/contract.js';
import type { RouterDecision } from '../queue/types.js';
import { canRunStage, type BudgetState } from './budget.js';
import type { NetErrorKind } from './signals.js';

export interface RouterJob extends BudgetState {
  profile: 'data_triage' | 'browser_evidence';
  stage: JobStage;
  urgent: boolean;
  /** Classification recorded by an earlier attempt of this job (e.g. HTTP triage result). */
  classification: string | null;
  scope: { scheme_fallback_target_ids?: number[] };
}

export type Classification =
  | 'static_html_usable' | 'non_html_document' | 'js_shell' | 'empty_response' | 'api_returned_html'
  | 'challenge' | 'auth_required' | 'access_denied' | 'rate_limited'
  | 'not_found' | 'server_error' | 'timeout' | 'connection_reset' | 'connection_refused'
  | 'dns_failure' | 'tls_failure' | 'egress_denied'
  | 'content_captured' | 'content_incomplete' | 'navigation_timeout_salvaged'
  | 'rendering_incompatibility' | 'renderer_crash' | 'infrastructure_error';

export interface Classified {
  classification: Classification;
  outcome: AcquisitionOutcome;
  signals: string[];
  retryAfterSeconds?: number | null;
}

/** Backoff with jitter for a selected retry (timeouts/resets/5xx). */
export function backoffSeconds(attemptCount: number, base = 20, cap = 300, rand = Math.random): number {
  const exp = Math.min(cap, base * 2 ** Math.max(0, attemptCount - 1));
  return Math.round(exp / 2 + rand() * (exp / 2));
}

export interface HttpObservation {
  status: number | null;
  contentType: string | null;
  bodyText: string | null;
  bodyBytes: number;
  netError: { kind: NetErrorKind; message: string; egressError?: string | null } | null;
  challenge: { challenge: boolean; signals: string[] };
  authSignals: string[];
  jsShellSignals: string[];
  visibleTextLength: number;
  expectedJson?: boolean;
  retryAfterSeconds: number | null;
}

export function classifyHttp(o: HttpObservation): Classified {
  if (o.netError) {
    const e = o.netError;
    if (e.egressError === 'destination_denied' || e.egressError === 'port_denied' || e.egressError === 'scheme_denied' || e.kind === 'proxy_denied') {
      return { classification: 'egress_denied', outcome: 'ACCESS_BLOCKED', signals: [`egress:${e.egressError ?? e.kind}`] };
    }
    if (e.kind === 'dns') return { classification: 'dns_failure', outcome: 'DNS_FAILURE', signals: [e.message] };
    if (e.kind === 'tls') return { classification: 'tls_failure', outcome: 'TLS_FAILURE', signals: [e.message] };
    if (e.kind === 'timeout') return { classification: 'timeout', outcome: 'ORIGIN_UNAVAILABLE', signals: [e.message] };
    if (e.kind === 'refused') return { classification: 'connection_refused', outcome: 'ORIGIN_UNAVAILABLE', signals: [e.message] };
    return { classification: 'connection_reset', outcome: 'ORIGIN_UNAVAILABLE', signals: [e.message] };
  }
  const status = o.status ?? 0;
  const isHtml = /html|xml/i.test(o.contentType ?? '') || /^\s*<(!doctype|html)/i.test(o.bodyText ?? '');
  if (o.challenge.challenge) return { classification: 'challenge', outcome: 'CHALLENGE_PAGE_CAPTURED', signals: o.challenge.signals };
  if (o.expectedJson && isHtml) return { classification: 'api_returned_html', outcome: 'CONTENT_INCOMPLETE', signals: ['expected_json_got_html'] };
  if (status === 429) return { classification: 'rate_limited', outcome: 'ACCESS_BLOCKED', signals: ['status:429'], retryAfterSeconds: o.retryAfterSeconds };
  if (status === 401 || (o.authSignals.length > 0 && status >= 400)) return { classification: 'auth_required', outcome: 'AUTH_REQUIRED', signals: o.authSignals };
  if (status === 403 || status === 451) return { classification: 'access_denied', outcome: 'ACCESS_BLOCKED', signals: [`status:${status}`] };
  if (status === 404 || status === 410) return { classification: 'not_found', outcome: 'NOT_FOUND', signals: [`status:${status}`] };
  if (status >= 500) return { classification: 'server_error', outcome: 'ORIGIN_UNAVAILABLE', signals: [`status:${status}`] };
  if (status >= 400) return { classification: 'access_denied', outcome: 'ACCESS_BLOCKED', signals: [`status:${status}`] };
  if (o.bodyBytes === 0) return { classification: 'empty_response', outcome: 'CONTENT_INCOMPLETE', signals: ['empty_body'] };
  if (!isHtml) return { classification: 'non_html_document', outcome: 'CONTENT_CAPTURED', signals: [`content_type:${o.contentType ?? 'unknown'}`] };
  if (o.authSignals.length > 0 && o.visibleTextLength < 1500) return { classification: 'auth_required', outcome: 'AUTH_REQUIRED', signals: o.authSignals };
  if (o.jsShellSignals.length > 0) return { classification: 'js_shell', outcome: 'CONTENT_INCOMPLETE', signals: o.jsShellSignals };
  return { classification: 'static_html_usable', outcome: 'CONTENT_CAPTURED', signals: [`text_length:${o.visibleTextLength}`] };
}

function finish(state: 'COMPLETE' | 'PARTIAL' | 'FAILED_FINAL' | 'MANUAL_REVIEW', c: Classified, reason: string, spawnSchemeFallback = false): RouterDecision {
  return { kind: 'finish', state, outcome: c.outcome, reason: `${c.classification}: ${reason}`, spawnSchemeFallback };
}

function next(stage: JobStage, c: Classified, reason: string, delaySeconds = 0, extra: Partial<Extract<RouterDecision, { kind: 'continue' }>> = {}): RouterDecision {
  return { kind: 'continue', stage, state: delaySeconds > 0 ? 'DEFERRED' : 'QUEUED', delaySeconds, outcome: c.outcome, reason: `${c.classification}: ${reason}`, ...extra };
}

/** Budget after the attempt being decided (attempt counters were charged at lease time). */
function after(job: RouterJob, spentSeconds: number): BudgetState {
  return { ...job, active_seconds_used: job.active_seconds_used + spentSeconds };
}

/** Exhausted infrastructure attempts are not evidence that the origin is offline. */
function exhausted(c: Classified, what: string): RouterDecision {
  return finish('FAILED_FINAL', c, `${what}; attempt/time budget exhausted`);
}

export function decideAfterHttp(job: RouterJob, c: Classified, spentSeconds: number, policy: Policy, rand = Math.random): RouterDecision {
  const b = after(job, spentSeconds);
  const evidence = job.profile === 'browser_evidence';
  // data_triage never escalates to the browser: it may finish without browser artifacts (§7).
  const canBrowser = evidence && canRunStage(b, 'browser_primary', policy);
  const canHttp = canRunStage(b, 'http', policy);
  const toBrowser = (why: string, delay = 0, extra = {}) =>
    canBrowser ? next('browser_primary', c, why, delay, extra) : exhausted(c, `${why} but no browser budget`);

  switch (c.classification) {
    case 'static_html_usable':
    case 'non_html_document':
      // Data can be complete; browser evidence still needs the browser (§7).
      return evidence ? toBrowser('HTML/data retrieved; browser evidence still required') : finish('COMPLETE', c, 'HTTP outcome recorded');
    case 'js_shell':
    case 'empty_response':
    case 'api_returned_html':
      return canBrowser ? toBrowser('content requires rendering') : finish('PARTIAL', c, 'rendering needed but profile is data_triage');
    case 'challenge':
      // Preserve the challenge body; allow a bounded ordinary browser completion.
      return canBrowser ? next('browser_primary', c, 'challenge response; bounded ordinary browser visit') : finish('MANUAL_REVIEW', c, 'challenge unresolved; no browser budget');
    case 'rate_limited': {
      const wait = Math.min(Math.max(c.retryAfterSeconds ?? 60, policy.limits.per_domain_delay_seconds), 3600);
      const stage: JobStage = evidence ? 'browser_primary' : 'http';
      if (!canRunStage(b, stage, policy)) return finish('FAILED_FINAL', c, '429 with attempt budget exhausted');
      // Defer rather than sleep in an occupied slot; Retry-After overrides ordinary delay.
      return next(stage, c, `429; deferred ${wait}s per Retry-After`, wait, { domainBackoffSeconds: wait });
    }
    case 'auth_required':
      return evidence && canBrowser ? toBrowser('login/auth signals; capture the auth wall as evidence') : finish('MANUAL_REVIEW', c, 'authentication required; operator-assisted session needed');
    case 'access_denied':
      // Not every 403 is bot detection: one justified browser visit for evidence/rendering.
      return canBrowser ? toBrowser('HTTP denial may be client-specific; one browser visit') : finish('FAILED_FINAL', c, 'access denied');
    case 'not_found':
      return evidence && canBrowser ? toBrowser('capture the not-found page once as evidence') : finish('FAILED_FINAL', c, 'origin returned not-found for the exact path');
    case 'dns_failure':
      // Same resolver path for every engine: do not retry the confirmed error in-window.
      return finish('FAILED_FINAL', c, 'name did not resolve via the egress gateway');
    case 'egress_denied':
      return finish('MANUAL_REVIEW', c, 'destination denied by egress policy (non-public address or port)');
    case 'tls_failure':
      // Node and Chromium differ (e.g. AIA intermediate fetching): try the browser once for evidence.
      return evidence && canBrowser ? toBrowser('HTTP client TLS failure; browser verifies chains differently') : finish('FAILED_FINAL', c, 'TLS failure preserved; relaxed-TLS inspection only by explicit operator request', true);
    case 'timeout':
    case 'connection_reset':
    case 'connection_refused':
    case 'server_error': {
      if (evidence && canBrowser) return toBrowser('HTTP failure is not proof the browser visit fails', backoffSeconds(job.http_attempts, 20, 300, rand));
      if (canHttp) return next('http', c, 'one selected retry with backoff', backoffSeconds(job.http_attempts, 20, 300, rand));
      return finish('FAILED_FINAL', c, 'origin unavailable within budget', c.classification === 'connection_refused');
    }
    default:
      return canBrowser && evidence ? toBrowser('unclassified HTTP result') : finish('MANUAL_REVIEW', c, 'unclassified HTTP result');
  }
}

export interface BrowserObservation {
  netError: { kind: NetErrorKind; message: string; egressError?: string | null } | null;
  status: number | null;
  challenge: { challenge: boolean; signals: string[] };
  challengeResolvedDuringWait: boolean;
  authSignals: string[];
  contentAppeared: boolean;
  navigationTimedOut: boolean;
  rendererCrashed: boolean;
  renderingIncompatibilitySignals: string[];
  validScreenshots: number;
  requiredSatisfied: boolean;
  missingRequired: string[];
  visibleTextLength: number;
  retryAfterSeconds: number | null;
}

export function classifyBrowser(o: BrowserObservation): Classified {
  if (o.rendererCrashed) return { classification: 'renderer_crash', outcome: o.contentAppeared ? 'CONTENT_INCOMPLETE' : 'INFRASTRUCTURE_DEFERRED', signals: ['renderer_crashed'] };
  if (o.netError && !o.contentAppeared) {
    const http = classifyHttp({
      status: null, contentType: null, bodyText: null, bodyBytes: 0, netError: o.netError,
      challenge: { challenge: false, signals: [] }, authSignals: [], jsShellSignals: [], visibleTextLength: 0, retryAfterSeconds: null,
    });
    if (http.classification === 'timeout' && o.validScreenshots > 0) {
      return { classification: 'navigation_timeout_salvaged', outcome: 'CONTENT_INCOMPLETE', signals: ['navigation_timeout', 'screenshot_salvaged'] };
    }
    return http;
  }
  if (o.challenge.challenge && !o.challengeResolvedDuringWait) return { classification: 'challenge', outcome: 'CHALLENGE_PAGE_CAPTURED', signals: o.challenge.signals };
  const status = o.status ?? 200;
  if (status === 429) return { classification: 'rate_limited', outcome: 'ACCESS_BLOCKED', signals: ['status:429'], retryAfterSeconds: o.retryAfterSeconds };
  if (status === 401) return { classification: 'auth_required', outcome: 'AUTH_REQUIRED', signals: o.authSignals.length ? o.authSignals : ['status:401'] };
  if (status === 403 || status === 451) return { classification: 'access_denied', outcome: 'ACCESS_BLOCKED', signals: [`status:${status}`] };
  if (status === 404 || status === 410) return { classification: 'not_found', outcome: 'NOT_FOUND', signals: [`status:${status}`] };
  if (status >= 500 && o.visibleTextLength < 200) return { classification: 'server_error', outcome: 'ORIGIN_UNAVAILABLE', signals: [`status:${status}`] };
  if (o.renderingIncompatibilitySignals.length > 0 && o.visibleTextLength < 2000) {
    return { classification: 'rendering_incompatibility', outcome: 'CONTENT_INCOMPLETE', signals: o.renderingIncompatibilitySignals };
  }
  if (o.authSignals.length > 0 && o.visibleTextLength < 1500) return { classification: 'auth_required', outcome: 'AUTH_REQUIRED', signals: o.authSignals };
  if (!o.contentAppeared) return { classification: 'content_incomplete', outcome: 'CONTENT_INCOMPLETE', signals: ['no_renderable_content'] };
  if (o.navigationTimedOut) return { classification: 'navigation_timeout_salvaged', outcome: 'CONTENT_INCOMPLETE', signals: ['navigation_timeout', ...o.missingRequired.map((m) => `missing:${m}`)] };
  if (!o.requiredSatisfied) return { classification: 'content_incomplete', outcome: 'CONTENT_INCOMPLETE', signals: o.missingRequired.map((m) => `missing:${m}`) };
  return { classification: 'content_captured', outcome: 'CONTENT_CAPTURED', signals: [`text_length:${o.visibleTextLength}`] };
}

export function decideAfterBrowser(job: RouterJob, c: Classified, o: BrowserObservation, spentSeconds: number, policy: Policy, rand = Math.random): RouterDecision {
  const b = after(job, spentSeconds);
  const alternateStage: JobStage | null = policy.browser.alternate_engine === 'firefox' ? 'browser_alternate'
    : policy.browser.alternate_engine === 'scrapling' ? 'scrapling' : null;
  const canAlternate = alternateStage !== null && job.stage === 'browser_primary' && canRunStage(b, alternateStage, policy);
  const canRetryPrimary = canRunStage(b, 'browser_primary', policy);
  const useful = o.validScreenshots > 0;

  switch (c.classification) {
    case 'content_captured':
      return finish('COMPLETE', c, 'required artifact contract satisfied');
    case 'content_incomplete':
    case 'navigation_timeout_salvaged':
      if (!useful && canRetryPrimary && job.stage === 'browser_primary') return next('browser_primary', c, 'no usable evidence; one retry', backoffSeconds(job.browser_attempts, 15, 120, rand));
      return useful ? finish('PARTIAL', c, `useful evidence preserved; missing ${o.missingRequired.join(',') || 'completeness'}`) : exhausted(c, 'no renderable content');
    case 'rendering_incompatibility':
      // One alternate engine instead of an additional unconditional tier (§4, §8).
      if (canAlternate) return next(alternateStage!, c, 'Chromium rendering incompatibility; one alternate engine attempt');
      return useful ? finish('PARTIAL', c, 'rendering incompatibility; evidence of the observed state preserved') : exhausted(c, 'rendering incompatibility');
    case 'renderer_crash':
      if (canRetryPrimary && job.stage === 'browser_primary') return next('browser_primary', c, 'renderer crashed; process recycled; one retry', 15);
      if (canAlternate) return next(alternateStage!, c, 'repeated renderer crash; alternate engine');
      return useful ? finish('PARTIAL', c, 'renderer crashed after partial evidence') : finish('FAILED_FINAL', { ...c, outcome: 'INFRASTRUCTURE_DEFERRED' }, 'renderer crash; budget exhausted');
    case 'challenge':
      // Bounded ordinary completion already attempted inside the visit.
      if (canAlternate) return next(alternateStage!, c, 'unresolved challenge; one selected alternate profile');
      return finish('MANUAL_REVIEW', c, 'unresolved challenge preserved; operator-assisted or deferred capture needed');
    case 'auth_required':
      return finish('MANUAL_REVIEW', c, 'authentication wall captured; generic recipes never log in');
    case 'access_denied': {
      const httpAlsoDenied = job.classification?.startsWith('access_denied') ?? false;
      if (canAlternate && !httpAlsoDenied) return next(alternateStage!, c, 'browser-specific denial; one justified alternative');
      return finish('FAILED_FINAL', c, 'classified access limitation; denial page preserved');
    }
    case 'rate_limited': {
      const wait = Math.min(Math.max(c.retryAfterSeconds ?? 60, policy.limits.per_domain_delay_seconds), 3600);
      if (!canRunStage(b, job.stage, policy)) return finish('FAILED_FINAL', c, '429 with browser budget exhausted');
      return next(job.stage, c, `429; deferred ${wait}s without holding a browser slot`, wait, { domainBackoffSeconds: wait });
    }
    case 'not_found':
      return finish('FAILED_FINAL', c, 'not-found page preserved for the exact supplied location');
    case 'dns_failure':
      return finish('FAILED_FINAL', c, 'name did not resolve via the egress gateway');
    case 'egress_denied':
      return finish('MANUAL_REVIEW', c, 'destination denied by egress policy');
    case 'tls_failure':
      return finish('FAILED_FINAL', c, 'browser TLS failure preserved; global TLS default unchanged', true);
    case 'timeout':
    case 'connection_reset':
    case 'connection_refused':
    case 'server_error':
      if (canRetryPrimary && job.stage === 'browser_primary') return next('browser_primary', c, 'one selected retry with backoff and jitter', backoffSeconds(job.browser_attempts, 20, 300, rand));
      return useful ? finish('PARTIAL', c, 'origin failure after partial evidence') : finish('FAILED_FINAL', c, 'origin unavailable within budget', c.classification === 'connection_refused');
    default:
      return useful ? finish('PARTIAL', c, 'unclassified browser result with evidence') : finish('MANUAL_REVIEW', c, 'unclassified browser result');
  }
}

/** Infrastructure failure before/while contacting the target (browser connect, gateway down). */
export function decideInfrastructure(job: RouterJob, spentSeconds: number, policy: Policy, reason: string): RouterDecision {
  const b = after(job, spentSeconds);
  const c: Classified = { classification: 'infrastructure_error', outcome: 'INFRASTRUCTURE_DEFERRED', signals: [reason] };
  if (canRunStage(b, job.stage, policy)) return next(job.stage, c, `infrastructure failure: ${reason}`, 60);
  return finish('FAILED_FINAL', c, `infrastructure failure with budget exhausted: ${reason}`);
}
