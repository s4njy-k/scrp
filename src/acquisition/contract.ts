/**
 * The job/result contract shared by every acquisition adapter (Crawlee/Playwright
 * driver, HTTP triage, optional Scrapling worker). Blueprint §7 and §12.
 */

export const PROCESSING_STATES = [
  'QUEUED', 'LEASED', 'CAPTURING', 'FINALISING', 'COMPLETE', 'PARTIAL', 'DEFERRED', 'MANUAL_REVIEW', 'FAILED_FINAL',
] as const;
export type ProcessingState = (typeof PROCESSING_STATES)[number];

export const ACQUISITION_OUTCOMES = [
  'CONTENT_CAPTURED', 'CONTENT_INCOMPLETE', 'CHALLENGE_PAGE_CAPTURED', 'ACCESS_BLOCKED', 'AUTH_REQUIRED',
  'DNS_FAILURE', 'TLS_FAILURE', 'NOT_FOUND', 'ORIGIN_UNAVAILABLE', 'INFRASTRUCTURE_DEFERRED',
] as const;
export type AcquisitionOutcome = (typeof ACQUISITION_OUTCOMES)[number];

export type JobStage = 'http' | 'browser_primary' | 'browser_alternate' | 'scrapling' | 'done';

/**
 * Artifact types an attempt can produce. `required_artifacts` on a job is a
 * subset of these. An artifact counts towards the contract only when its file
 * exists, hashed, validated and marked complete (or an explicitly accepted
 * partial/truncated state for that type, see SATISFIABLE_WHEN_PARTIAL).
 */
export const ARTIFACT_TYPES = {
  http_response_record: 'HTTP outcome record: status, headers, redirect chain, timing, errors',
  raw_html: 'Raw HTTP response body of the top-level document (not the rendered DOM)',
  http_body: 'Raw HTTP response body of a non-HTML top-level resource',
  screenshot_viewport: 'At least one validated viewport PNG of the observed page state',
  screenshot_early: 'First viewport PNG once a renderable target or challenge state existed',
  screenshot_settled: 'Viewport PNG after bounded content-readiness checks',
  screenshot_full_or_tiles: 'Full-page PNG, or bounded viewport tiles with positions when over budget',
  screenshot_tile: 'One viewport tile of a long/virtualised page',
  element_crop: 'Element screenshot with locator, frame URL, bounding box and context',
  rendered_dom: 'Serialised rendered DOM of the main frame',
  frame_dom: 'Serialised rendered DOM of an accessible subframe',
  rendered_text: 'Rendered visible text of the main frame',
  network_events: 'Streamed request/response/failure/websocket/service-worker event JSONL',
  har: 'HAR file produced by the browser context (metadata; bodies stored separately)',
  response_body: 'A retained network response body within size limits',
  action_log: 'Ordered log of navigations, waits, scrolls and permitted interactions',
  console_log: 'Bounded console/page-error messages',
  session_state: 'Restricted cookie/storage state for session continuity (never in general exports)',
  attempt_metadata: 'Engine/build, user agent, locale, timezone, viewport, egress and settings',
  manifest: 'Manifest listing every artifact with hash, size, interval, method and completeness',
} as const;
export type ArtifactType = keyof typeof ARTIFACT_TYPES;

export const KNOWN_ARTIFACT_TYPES: ReadonlySet<string> = new Set(Object.keys(ARTIFACT_TYPES));

export const PROFILE_DEFAULT_REQUIRED: Record<'data_triage' | 'browser_evidence', string[]> = {
  data_triage: ['http_response_record'],
  browser_evidence: ['screenshot_viewport', 'rendered_dom', 'rendered_text', 'network_events', 'har', 'manifest'],
};

/** Interactions a job may permit. Generic recipes never submit forms, log in, pay or upload (§8). */
export const ALLOWED_INTERACTIONS: ReadonlySet<string> = new Set([
  'scroll',            // lazy-load scrolling
  'expand',            // accordion/details expansion
  'dismiss_dialog',    // non-submitting close of cookie/consent overlays (creates a modified observation)
  'non_submitting_click',
]);

export type Completeness = 'complete' | 'partial' | 'truncated' | 'failed' | 'omitted';

export interface ManifestEntry {
  type: ArtifactType;
  /** Relative to the attempt directory. Null when the artifact failed: files are never invented. */
  path: string | null;
  sizeBytes: number | null;
  sha256: string | null;
  observedStart: string | null;
  observedEnd: string | null;
  creationMethod: string;
  completeness: Completeness;
  limitations: string[];
  restricted?: boolean;
  derivedFrom?: string | null;
  isDerivative?: boolean;
  error?: string | null;
  metadata?: Record<string, unknown>;
}

export interface AttemptManifest {
  manifestVersion: 1;
  attemptId: string;
  jobId: number;
  attemptNo: number;
  kind: 'http' | 'browser';
  engine: string;
  adapter: string;
  vantage: string;
  requestedUrl: string;
  finalUrl: string | null;
  startedAt: string;
  endedAt: string;
  outcome: AcquisitionOutcome;
  classification: string;
  requiredArtifacts: string[];
  requiredSatisfied: boolean;
  missingRequired: string[];
  limitations: string[];
  artifacts: ManifestEntry[];
}

/** Types whose truncated form still satisfies the contract when the truncation is recorded. */
const SATISFIABLE_WHEN_PARTIAL: ReadonlySet<string> = new Set(['network_events', 'har', 'screenshot_full_or_tiles']);

const SATISFIED_BY: Record<string, string[]> = {
  screenshot_viewport: ['screenshot_viewport', 'screenshot_early', 'screenshot_settled'],
  screenshot_full_or_tiles: ['screenshot_full_or_tiles'],
};

export function evaluateRequired(required: readonly string[], entries: readonly ManifestEntry[]): { satisfied: boolean; missing: string[] } {
  const missing: string[] = [];
  for (const req of required) {
    if (req === 'manifest') continue; // the manifest is written last and always exists for a committed attempt
    const acceptable = SATISFIED_BY[req] ?? [req];
    const ok = entries.some((e) => {
      if (!acceptable.includes(e.type) || !e.path || !e.sha256) return false;
      // Browser error pages and gateway refusal pages are preserved, but are not target evidence.
      if (e.metadata?.not_target_content === true) return false;
      if (e.completeness === 'complete') return true;
      return (e.completeness === 'truncated' || e.completeness === 'partial') && SATISFIABLE_WHEN_PARTIAL.has(req);
    });
    if (!ok) missing.push(req);
  }
  return { satisfied: missing.length === 0, missing };
}

/**
 * Processing state for a finished attempt (§12). COMPLETE requires a
 * content-captured attempt with the full required contract; a saved error or
 * challenge screenshot never turns an access-blocked outcome into COMPLETE.
 */
export function processingStateFor(outcome: AcquisitionOutcome, requiredSatisfied: boolean, hasUsefulEvidence: boolean): 'COMPLETE' | 'PARTIAL' | null {
  if (outcome === 'CONTENT_CAPTURED' && requiredSatisfied) return 'COMPLETE';
  if ((outcome === 'CONTENT_CAPTURED' || outcome === 'CONTENT_INCOMPLETE') && hasUsefulEvidence) return 'PARTIAL';
  return null; // router decides: retry, defer, manual review or final failure
}
