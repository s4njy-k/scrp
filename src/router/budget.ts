/**
 * Coordinator-owned acquisition budget (blueprint §8). Shared by every adapter
 * so nested library retries or engine changes cannot multiply attempts.
 */
import type { Policy } from '../config/policy.js';
import type { JobStage } from '../acquisition/contract.js';

export interface BudgetState {
  http_attempts: number;
  browser_attempts: number;
  active_seconds_used: number;
  alternate_used: boolean;
}

export interface Remaining {
  http: number;
  browser: number;
  total: number;
  seconds: number;
}

export function remainingBudget(job: BudgetState, policy: Policy): Remaining {
  const l = policy.limits;
  return {
    http: Math.max(0, l.http_attempts_max - job.http_attempts),
    browser: Math.max(0, l.browser_attempts_max - job.browser_attempts),
    total: Math.max(0, l.acquisition_attempts_max - job.http_attempts - job.browser_attempts),
    seconds: Math.max(0, l.active_acquisition_seconds_max - job.active_seconds_used),
  };
}

/** Minimum useful active time for a stage: below this an attempt cannot even finalise. */
function minimumSecondsFor(stage: JobStage, policy: Policy): number {
  if (stage === 'http') return Math.min(5, policy.limits.http_attempt_seconds);
  return policy.limits.finalisation_reserve_seconds + 10;
}

export function canRunStage(job: BudgetState, stage: JobStage, policy: Policy): boolean {
  const r = remainingBudget(job, policy);
  if (stage === 'done') return false;
  if (r.total <= 0 || r.seconds < minimumSecondsFor(stage, policy)) return false;
  if (stage === 'http') return r.http > 0;
  if (stage === 'browser_alternate' || stage === 'scrapling') {
    return r.browser > 0 && !job.alternate_used && policy.limits.alternate_browser_slots_max > 0;
  }
  return r.browser > 0;
}

/**
 * Wall-clock cap for one attempt: the stage cap, never more than what is left
 * of the cumulative active-acquisition budget. Navigation, interaction and
 * screenshot timeouts all draw from this single deadline.
 */
export function attemptSecondsFor(job: BudgetState, stage: JobStage, policy: Policy): number {
  const l = policy.limits;
  const stageCap = stage === 'http' ? l.http_attempt_seconds
    : stage === 'browser_primary' ? l.primary_browser_seconds
    : l.alternate_browser_seconds;
  return Math.max(0, Math.min(stageCap, remainingBudget(job, policy).seconds));
}

export function stageKind(stage: JobStage): 'http' | 'browser' {
  return stage === 'http' ? 'http' : 'browser';
}

export function isAlternateStage(stage: JobStage): boolean {
  return stage === 'browser_alternate' || stage === 'scrapling';
}
