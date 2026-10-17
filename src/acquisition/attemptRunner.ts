/**
 * Runs one leased attempt end to end for any adapter: heartbeat with fencing,
 * immutable attempt directory, manifest with contract evaluation, router
 * decision and idempotent commit. Infrastructure failures are recorded as
 * interrupted attempts; nothing is silently dropped (§12).
 */
import type { Policy } from '../config/policy.js';
import { MiB } from '../config/policy.js';
import type { Pool } from '../db/pool.js';
import { logger } from '../observability/logger.js';
import { commitAttempt, renewLease, setLeasedState, type DomainEdgeInput } from '../queue/queue.js';
import type { Lease, RouterDecision } from '../queue/types.js';
import { decideInfrastructure, type Classified, type RouterJob } from '../router/router.js';
import { AttemptWriter } from '../storage/artifactStore.js';
import { evaluateRequired, processingStateFor, type ManifestEntry } from './contract.js';

export interface CaptureContext {
  writer: AttemptWriter;
  deadline: number;
  signal: AbortSignal;
}

export interface CaptureOutcome {
  finalUrl: string | null;
  engineVersion: string | null;
  userAgent: string | null;
  settings: Record<string, unknown>;
  edges: DomainEdgeInput[];
  limitations: string[];
  sessionId?: string | null;
  extractionApplicable: boolean;
  /** Classify and route once the manifest's hashed entries are known. */
  decide: (contract: { satisfied: boolean; missing: string[]; entries: ManifestEntry[] }) => { classified: Classified; decision: RouterDecision; useful: boolean };
}

export interface RunAttemptArgs {
  pool: Pool;
  policy: Policy;
  lease: Lease;
  artifactRoot: string;
  kind: 'http' | 'browser';
  engine: string;
  adapter: string;
  vantage: string;
  capture: (ctx: CaptureContext) => Promise<CaptureOutcome>;
}

export function routerJobFromLease(lease: Lease): RouterJob {
  const j = lease.job;
  return {
    profile: j.profile, stage: lease.stage, urgent: j.urgent, classification: j.classification, scope: j.scope,
    http_attempts: j.http_attempts, browser_attempts: j.browser_attempts, active_seconds_used: j.active_seconds_used, alternate_used: j.alternate_used,
  };
}

/** Upgrade a router decision with the contract-aware processing state (§12). */
function applyContract(decision: RouterDecision, classified: Classified, satisfied: boolean, useful: boolean): RouterDecision {
  if (decision.kind !== 'finish') return decision;
  const state = processingStateFor(classified.outcome, satisfied, useful);
  if (decision.state === 'COMPLETE' && state !== 'COMPLETE') {
    return { ...decision, state: useful ? 'PARTIAL' : 'FAILED_FINAL', reason: `${decision.reason}; required artifact contract not met` };
  }
  return decision;
}

export async function runLeasedAttempt(args: RunAttemptArgs): Promise<{ decision: RouterDecision; ownershipHeld: boolean }> {
  const { pool, policy, lease } = args;
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const deadline = started + lease.attemptSeconds * 1000;
  const controller = new AbortController();
  let leaseLost = false;

  const heartbeat = setInterval(() => {
    renewLease(pool, lease, policy.queue.lease_seconds)
      .then((ok) => {
        if (!ok && !leaseLost) {
          leaseLost = true;
          logger.warn({ job: lease.job.id, token: lease.token }, 'lease lost: stopping target activity');
          controller.abort(new Error('lease_lost'));
        }
      })
      .catch((err: Error) => logger.warn({ err: err.message, job: lease.job.id }, 'heartbeat failed (will retry)'));
  }, policy.queue.heartbeat_seconds * 1000);
  heartbeat.unref();

  const writer = new AttemptWriter(args.artifactRoot, lease.attemptId, Math.floor(policy.capture.attempt_artifacts_mib_max * MiB));
  const job = routerJobFromLease(lease);
  const requestedUrl = lease.target.url;
  let finalised = false;

  try {
    await writer.init();
    await setLeasedState(pool, lease, 'CAPTURING');
    const outcome = await args.capture({ writer, deadline, signal: controller.signal });
    await setLeasedState(pool, lease, 'FINALISING');

    let decided: ReturnType<CaptureOutcome['decide']> | null = null;
    const location = leaseLost ? 'incomplete' : 'captures';
    const fin = await writer.finalise((entries) => {
      const contract = evaluateRequired(lease.job.required_artifacts, entries);
      decided = outcome.decide({ ...contract, entries });
      const limitations = [...outcome.limitations, ...writer.budgetEvents];
      return {
        attemptId: lease.attemptId, jobId: lease.job.id, attemptNo: lease.attemptNo, kind: args.kind, engine: args.engine,
        adapter: args.adapter, vantage: args.vantage, requestedUrl, finalUrl: outcome.finalUrl, startedAt, endedAt: new Date().toISOString(),
        outcome: decided.classified.outcome, classification: decided.classified.classification,
        requiredArtifacts: lease.job.required_artifacts, requiredSatisfied: contract.satisfied && decided.classified.outcome === 'CONTENT_CAPTURED',
        missingRequired: contract.missing, limitations,
      };
    }, location);
    finalised = true;
    const d = decided as unknown as ReturnType<CaptureOutcome['decide']>;
    const decision = applyContract(d.decision, d.classified, fin.manifest.requiredSatisfied, d.useful);
    const activeSeconds = (Date.now() - started) / 1000;
    const res = await commitAttempt(pool, policy, lease, {
      status: 'committed', manifest: fin.manifest, manifestSha256: fin.manifestSha256, artifactDir: fin.relativeDir,
      totalBytes: fin.totalBytes, activeSeconds, engineVersion: outcome.engineVersion, userAgent: outcome.userAgent,
      settings: { ...outcome.settings, classification_signals: d.classified.signals }, error: null, edges: outcome.edges,
      sessionId: outcome.sessionId ?? null, decision, extractionApplicable: outcome.extractionApplicable,
    });
    logger.info({ job: lease.job.id, attempt: lease.attemptId, stage: lease.stage, outcome: d.classified.outcome, classification: d.classified.classification, decision: decision.kind === 'finish' ? decision.state : `${decision.state}:${decision.stage}`, seconds: activeSeconds.toFixed(1), ownership: res.ownershipHeld }, 'attempt committed');
    return { decision, ownershipHeld: res.ownershipHeld };
  } catch (err) {
    // Infrastructure failure (browser connection, disk, database). Preserve what exists.
    const message = (err as Error).message ?? String(err);
    if (finalised) {
      // Directory is already immutable in captures/; the reconciler commits it from its manifest.
      logger.error({ job: lease.job.id, attempt: lease.attemptId, err: message.slice(0, 500) }, 'commit failed after finalisation; reconciler will commit from manifest');
      throw err;
    }
    logger.error({ job: lease.job.id, attempt: lease.attemptId, err: message.slice(0, 500) }, 'attempt failed with infrastructure error');
    const activeSeconds = (Date.now() - started) / 1000;
    const decision = decideInfrastructure(job, activeSeconds, policy, message.slice(0, 200));
    let fin: Awaited<ReturnType<AttemptWriter['finalise']>> | null = null;
    try {
      await writer.settle(2000);
      fin = await writer.finalise((entries) => ({
        attemptId: lease.attemptId, jobId: lease.job.id, attemptNo: lease.attemptNo, kind: args.kind, engine: args.engine,
        adapter: args.adapter, vantage: args.vantage, requestedUrl, finalUrl: null, startedAt, endedAt: new Date().toISOString(),
        outcome: 'INFRASTRUCTURE_DEFERRED', classification: 'infrastructure_error', requiredArtifacts: lease.job.required_artifacts,
        requiredSatisfied: false, missingRequired: evaluateRequired(lease.job.required_artifacts, entries).missing,
        limitations: [`infrastructure error: ${message.slice(0, 300)}`],
      }), 'incomplete');
    } catch (finErr) {
      logger.error({ err: (finErr as Error).message, attempt: lease.attemptId }, 'could not finalise interrupted attempt; reconciler will salvage tmp directory');
    }
    try {
      const res = await commitAttempt(pool, policy, lease, {
        status: 'interrupted', manifest: fin?.manifest ?? null, manifestSha256: fin?.manifestSha256 ?? null, artifactDir: fin?.relativeDir ?? null,
        totalBytes: fin?.totalBytes ?? 0, activeSeconds, engineVersion: null, userAgent: null, settings: {}, error: message.slice(0, 1000),
        edges: [], decision, extractionApplicable: false,
      });
      return { decision, ownershipHeld: res.ownershipHeld };
    } catch (commitErr) {
      // Database unavailable: the lease expires and the reclaimer records the interruption.
      logger.error({ err: (commitErr as Error).message, attempt: lease.attemptId }, 'commit failed; lease will be reclaimed');
      throw commitErr;
    }
  } finally {
    clearInterval(heartbeat);
  }
}
