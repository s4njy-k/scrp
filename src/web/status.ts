/**
 * The three status fields that must never be conflated (checklist §7, §10;
 * blueprint v4 §22.3): acquisition result, investigative verdict and
 * external action status, plus the live stage of an open job.
 */

export type AcquisitionChip =
  | 'queued' | 'capturing' | 'content_captured' | 'partial' | 'challenge' | 'blocked' | 'auth_required' | 'timed_out'
  | 'dns_failure' | 'tls_failure' | 'not_found' | 'parked' | 'suspended' | 'unavailable' | 'infrastructure_deferred'
  | 'egress_denied' | 'manual_review' | 'failed';

export interface JobStatusInput {
  state: string;
  outcome: string | null;
  classification: string | null;
}

/** Map processing state + acquisition outcome + classification onto one explicit acquisition chip. */
export function acquisitionChip(j: JobStatusInput): AcquisitionChip {
  const c = (j.classification ?? '').split(':')[0]!.trim();
  if (j.state === 'QUEUED' && !j.outcome) return 'queued';
  if (['LEASED', 'CAPTURING', 'FINALISING'].includes(j.state)) return 'capturing';
  if (c === 'parked_domain') return 'parked';
  if (c === 'hosting_suspended') return 'suspended';
  if (c === 'egress_denied') return 'egress_denied';
  if (c === 'timeout' || c === 'navigation_timeout_salvaged') return j.state === 'PARTIAL' ? 'partial' : 'timed_out';
  switch (j.outcome) {
    case 'CONTENT_CAPTURED':
      return j.state === 'COMPLETE' ? 'content_captured' : j.state === 'PARTIAL' ? 'partial' : j.state === 'MANUAL_REVIEW' ? 'manual_review' : 'content_captured';
    case 'CONTENT_INCOMPLETE':
      return 'partial';
    case 'CHALLENGE_PAGE_CAPTURED':
      return 'challenge';
    case 'ACCESS_BLOCKED':
      return 'blocked';
    case 'AUTH_REQUIRED':
      return 'auth_required';
    case 'DNS_FAILURE':
      return 'dns_failure';
    case 'TLS_FAILURE':
      return 'tls_failure';
    case 'NOT_FOUND':
      return 'not_found';
    case 'ORIGIN_UNAVAILABLE':
      return 'unavailable';
    case 'INFRASTRUCTURE_DEFERRED':
      return 'infrastructure_deferred';
    default:
      if (j.state === 'DEFERRED' || j.state === 'QUEUED') return 'queued';
      if (j.state === 'MANUAL_REVIEW') return 'manual_review';
      return 'failed';
  }
}

export type LiveStage = 'queued' | 'capturing' | 'first_image_ready' | 'finishing_evidence' | 'extracting' | 'ready_for_review' | 'deferred' | 'failed';

export function liveStage(j: { state: string; progress_stage: string | null; extraction_state: string | null; has_first_image: boolean }): LiveStage {
  if (j.state === 'QUEUED') return 'queued';
  if (j.state === 'DEFERRED') return 'deferred';
  if (j.state === 'LEASED' || j.state === 'CAPTURING') return j.has_first_image || j.progress_stage === 'first_image_ready' ? 'first_image_ready' : 'capturing';
  if (j.state === 'FINALISING') return 'finishing_evidence';
  if (j.state === 'FAILED_FINAL') return 'failed';
  if (j.extraction_state === 'pending' || j.extraction_state === 'running') return 'extracting';
  return 'ready_for_review';
}

export const VERDICTS = ['unreviewed', 'suspicious', 'likely_malicious', 'benign', 'false_positive', 'inconclusive'] as const;
export type Verdict = (typeof VERDICTS)[number];

export const ACTION_STATES = ['none', 'draft', 'in_review', 'approved', 'issued', 'acknowledged', 'complied', 'partially_complied', 'rejected', 'no_response', 'disputed', 'withdrawn', 'closed'] as const;
