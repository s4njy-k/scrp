import type { AcquisitionOutcome, JobStage, ProcessingState } from '../acquisition/contract.js';

export interface JobRow {
  id: number;
  target_id: number;
  parent_job_id: number | null;
  profile: 'data_triage' | 'browser_evidence';
  window_key: string;
  registrable_domain: string;
  priority: number;
  urgent: boolean;
  required_artifacts: string[];
  capture_variant: string;
  scope: { scheme_fallback_target_ids?: number[]; child_pages_max?: number; follow_external_redirects?: boolean; relaxed_tls?: boolean } & Record<string, unknown>;
  allowed_interactions: string[];
  retention_class: string;
  case_ref: string | null;
  deadline: Date | null;
  state: ProcessingState;
  stage: JobStage;
  outcome: AcquisitionOutcome | null;
  outcome_reason: string | null;
  classification: string | null;
  http_attempts: number;
  browser_attempts: number;
  active_seconds_used: number;
  alternate_used: boolean;
  next_eligible_at: Date;
  lease_owner: string | null;
  lease_token: number | null;
  lease_expires_at: Date | null;
  current_attempt_id: string | null;
}

export interface TargetRow {
  id: number;
  input_kind: string;
  url: string;
  scheme: string;
  hostname_ascii: string;
  hostname_unicode: string;
  port: number | null;
  path_and_query: string;
  fragment: string | null;
  registrable_domain: string;
  is_ip_literal: boolean;
  nonstandard_port: boolean;
}

export interface Lease {
  job: JobRow;
  target: TargetRow;
  token: number;
  workerId: string;
  stage: JobStage;
  permitSlot: number | null;
  attemptId: string;
  attemptNo: number;
  attemptSeconds: number;
  leasedAt: Date;
}

export type RouterDecision =
  | {
      kind: 'finish';
      state: 'COMPLETE' | 'PARTIAL' | 'FAILED_FINAL' | 'MANUAL_REVIEW';
      outcome: AcquisitionOutcome;
      reason: string;
      spawnSchemeFallback?: boolean;
    }
  | {
      kind: 'continue';
      /** Next stage to run; may equal the current stage for a retry. */
      stage: JobStage;
      delaySeconds: number;
      outcome: AcquisitionOutcome | null;
      reason: string;
      /** DEFERRED for scheduled retries (429, backoff), QUEUED for immediate escalation. */
      state: 'QUEUED' | 'DEFERRED';
      /** Extra per-domain pacing (429 Retry-After, rate reduction). */
      domainBackoffSeconds?: number;
    };
