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
import { commitAttempt, recordAttemptProgress, recordFirstImage, renewLease, setLeasedState, type DomainEdgeInput } from '../queue/queue.js';
import { buildManifestContext } from '../evidence/manifestContext.js';
import type { Lease, RouterDecision } from '../queue/types.js';
import { decideInfrastructure, type Classified, type RouterJob } from '../router/router.js';
import { AttemptWriter } from '../storage/artifactStore.js';
import { evaluateRequired, processingStateFor, type ManifestEntry } from './contract.js';

/** How far past its deadline an attempt may run before it is abandoned as an infrastructure failure. */
export const HARD_DEADLINE_GRACE_MS = 20_000;
/**
 * After the hard deadline, how long to wait for the abandoned capture's own
 * (bounded) cleanup before finalising. Its finally block closes the context,
 * which makes Playwright flush the HAR straight into the attempt directory;
 * finalising underneath that would hash a moving target or recreate tmp/<id>.
 */
export const CAPTURE_CLEANUP_WAIT_MS = 30_000;

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
  /** Test hook; defaults to HARD_DEADLINE_GRACE_MS. */
  hardDeadlineGraceMs?: number;
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
  // First validated viewport image: analysts can see it while the attempt is still finalising (checklist §10).
  let firstImageReported = false;
  writer.onArtifact = (rel, entry, data) => {
    if (firstImageReported || entry.completeness !== 'complete' || entry.metadata?.not_target_content === true) return;
    if (!['screenshot_early', 'screenshot_settled', 'screenshot_viewport'].includes(entry.type)) return;
    firstImageReported = true;
    void recordFirstImage(pool, lease.attemptId, rel, data).catch((err: Error) => logger.debug({ err: err.message }, 'first-image progress not recorded'));
  };
  const job = routerJobFromLease(lease);
  const requestedUrl = lease.target.url;
  let finalised = false;
  // The capture promise outlives a hard-deadline rejection; finalisation must wait for it.
  let capturePromise: Promise<CaptureOutcome> | null = null;
  let captureSettled = false;

  try {
    await writer.init();
    // Fencing before the first target contact: a lease already lost is never used.
    if (!(await setLeasedState(pool, lease, 'CAPTURING'))) {
      leaseLost = true;
      controller.abort(new Error('lease_lost'));
      throw new Error('lease lost before target contact');
    }
    void recordAttemptProgress(pool, lease.attemptId, 'capturing').catch(() => undefined);
    // Backstop: even if a library call ignores its own timeout, the attempt cannot
    // exceed its deadline by more than a short grace period. The abandoned capture
    // is aborted and its bounded cleanup is awaited (below) before finalising.
    const hardMs = deadline - Date.now() + (args.hardDeadlineGraceMs ?? HARD_DEADLINE_GRACE_MS);
    let hardTimer: NodeJS.Timeout | undefined;
    capturePromise = args.capture({ writer, deadline, signal: controller.signal });
    void capturePromise.then(() => { captureSettled = true; }, () => { captureSettled = true; });
    const outcome = await Promise.race([
      capturePromise,
      new Promise<never>((_, reject) => {
        hardTimer = setTimeout(() => {
          controller.abort(new Error('attempt_hard_deadline'));
          reject(new Error(`attempt exceeded its hard deadline (${Math.round(hardMs / 1000)} s)`));
        }, Math.max(args.hardDeadlineGraceMs === undefined ? 1000 : 1, hardMs));
      }),
    ]).finally(() => clearTimeout(hardTimer));
    await setLeasedState(pool, lease, 'FINALISING');
    void recordAttemptProgress(pool, lease.attemptId, 'finalising').catch(() => undefined);

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
        ...buildManifestContext({
          lease, engine: args.engine, adapter: args.adapter, vantage: args.vantage, startedAt,
          engineVersion: outcome.engineVersion, userAgent: outcome.userAgent, settings: outcome.settings, edges: outcome.edges,
        }),
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
      verifiedAtCommit: fin.verifiedAtCommit, reverifyMismatches: fin.reverifyMismatches,
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
    const extraLimitations: string[] = [];
    if (capturePromise && !captureSettled) {
      // Abandoned by the hard deadline (aborted, pages closed): let its bounded
      // cleanup finish so the HAR flush and stream ends land before hashing.
      let waitTimer: NodeJS.Timeout | undefined;
      await Promise.race([
        capturePromise.catch(() => undefined),
        new Promise<void>((resolve) => { waitTimer = setTimeout(resolve, CAPTURE_CLEANUP_WAIT_MS); }),
      ]).finally(() => clearTimeout(waitTimer));
      if (!captureSettled) {
        extraLimitations.push(`capture cleanup still running ${CAPTURE_CLEANUP_WAIT_MS / 1000} s after the hard deadline; files written later are not part of this manifest`);
        logger.error({ job: lease.job.id, attempt: lease.attemptId }, 'capture did not finish cleanup after hard deadline; finalising anyway');
      }
    }
    try {
      await writer.settle(2000);
      fin = await writer.finalise((entries) => ({
        attemptId: lease.attemptId, jobId: lease.job.id, attemptNo: lease.attemptNo, kind: args.kind, engine: args.engine,
        adapter: args.adapter, vantage: args.vantage, requestedUrl, finalUrl: null, startedAt, endedAt: new Date().toISOString(),
        outcome: 'INFRASTRUCTURE_DEFERRED', classification: 'infrastructure_error', requiredArtifacts: lease.job.required_artifacts,
        requiredSatisfied: false, missingRequired: evaluateRequired(lease.job.required_artifacts, entries).missing,
        limitations: [`infrastructure error: ${message.slice(0, 300)}`, ...extraLimitations],
        ...buildManifestContext({ lease, engine: args.engine, adapter: args.adapter, vantage: args.vantage, startedAt, engineVersion: null, userAgent: null, settings: {}, edges: [] }),
      }), 'incomplete');
    } catch (finErr) {
      logger.error({ err: (finErr as Error).message, attempt: lease.attemptId }, 'could not finalise interrupted attempt; reconciler will salvage tmp directory');
    }
    try {
      const res = await commitAttempt(pool, policy, lease, {
        status: 'interrupted', manifest: fin?.manifest ?? null, manifestSha256: fin?.manifestSha256 ?? null, artifactDir: fin?.relativeDir ?? null,
        totalBytes: fin?.totalBytes ?? 0, activeSeconds, engineVersion: null, userAgent: null, settings: {}, error: message.slice(0, 1000),
        edges: [], decision, extractionApplicable: false, verifiedAtCommit: fin?.verifiedAtCommit ?? [], reverifyMismatches: fin?.reverifyMismatches ?? [],
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
