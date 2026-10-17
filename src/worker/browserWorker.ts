/**
 * Browser driver worker: Crawlee AutoscaledPool orchestration with explicit
 * Playwright context ownership (blueprint §1, §13).
 *
 * Crawlee's AutoscaledPool provides resource-aware concurrency (CPU/memory
 * snapshots) under a HARD cap; PostgreSQL global permits enforce the
 * cross-replica/cross-engine browser limit. PlaywrightCrawler's built-in
 * request queue and browser lifecycle are deliberately not used: the job
 * ledger is PostgreSQL and every context must be owned and finalised by the
 * evidence contract.
 */
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { hostname } from 'node:os';
import { AutoscaledPool, Configuration } from '@crawlee/core';
import type { BrowserContextOptions } from 'playwright-core';
import type { Policy } from '../config/policy.js';
import type { Pool } from '../db/pool.js';
import { logger } from '../observability/logger.js';
import { leaseNext, readAdmission, releaseUnstarted } from '../queue/queue.js';
import type { Lease } from '../queue/types.js';
import { runLeasedAttempt, routerJobFromLease } from '../acquisition/attemptRunner.js';
import { captureWithBrowser } from '../capture/browserCapture.js';
import { classifyBrowser, decideAfterBrowser } from '../router/router.js';
import type { EgressConfig } from '../acquisition/egress.js';
import type { JobStage } from '../acquisition/contract.js';
import { BrowserPool, type BrowserLease, type Engine } from './browserPool.js';

export interface BrowserWorkerOptions {
  pool: Pool;
  policy: Policy;
  egress: EgressConfig;
  browsers: BrowserPool;
  artifactRoot: string;
  workerId?: string;
  /** Per-replica hard cap; global permits still bound the whole deployment. */
  maxConcurrency?: number;
  memoryMbytes?: number;
}

export function engineForStage(stage: JobStage, policy: Policy): Engine {
  return stage === 'browser_alternate' && policy.browser.alternate_engine === 'firefox' ? 'firefox' : 'chromium';
}

export class BrowserWorker {
  readonly workerId: string;
  private autoscaled: AutoscaledPool | null = null;
  private stopping = false;
  /**
   * Crawlee re-runs a task immediately (setImmediate) after one finishes. When
   * work is due but cannot be leased (permits busy, domain locked, pacing), back
   * off instead of spinning against PostgreSQL.
   */
  private idleUntil = 0;
  lastProgressAt = Date.now();
  activeLeases = new Map<string, Lease>();

  constructor(private readonly o: BrowserWorkerOptions) {
    this.workerId = o.workerId ?? `browser-worker:${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;
  }

  private stages(): JobStage[] {
    return this.o.policy.browser.alternate_engine === 'firefox' ? ['browser_primary', 'browser_alternate'] : ['browser_primary'];
  }

  private async hasDueWork(): Promise<boolean> {
    if (this.stopping || Date.now() < this.idleUntil) return false;
    try {
      const adm = await readAdmission(this.o.pool);
      if (adm.paused) return false;
      const { rows } = await this.o.pool.query<{ due: boolean }>(
        `SELECT EXISTS (SELECT 1 FROM jobs WHERE state IN ('QUEUED','DEFERRED') AND stage = ANY($1::job_stage[]) AND next_eligible_at <= now()
           AND ($2::boolean = false OR urgent)) AS due`,
        [this.stages(), adm.low_priority_paused],
      );
      this.lastProgressAt = Date.now();
      return rows[0]?.due ?? false;
    } catch (err) {
      // The loop is alive; only the database is not. Do not let the watchdog restart us for that.
      this.lastProgressAt = Date.now();
      this.idleUntil = Date.now() + 5000;
      logger.warn({ err: (err as Error).message }, 'database unavailable; acquisition paused');
      return false;
    }
  }

  /** Restricted storage state of the previous attempt of the same job/engine (session continuity). */
  private async previousStorageState(lease: Lease, engine: Engine): Promise<BrowserContextOptions['storageState'] | undefined> {
    const { rows } = await this.o.pool.query<{ artifact_dir: string; relative_path: string }>(
      `SELECT a.artifact_dir, ar.relative_path FROM attempts a JOIN artifacts ar ON ar.attempt_id = a.id
        WHERE a.job_id = $1 AND a.engine = $2 AND a.status = 'committed' AND ar.artifact_type = 'session_state' AND ar.relative_path IS NOT NULL
        ORDER BY a.attempt_no DESC LIMIT 1`,
      [lease.job.id, engine],
    );
    const r = rows[0];
    if (!r) return undefined;
    try {
      return JSON.parse(await readFile(join(this.o.artifactRoot, r.artifact_dir, r.relative_path), 'utf8')) as BrowserContextOptions['storageState'];
    } catch {
      return undefined;
    }
  }

  async runOne(): Promise<void> {
    const { pool, policy } = this.o;
    const lease = await leaseNext(pool, policy, {
      workerId: this.workerId, stages: this.stages(), needsBrowserPermit: true, engine: 'playwright', adapter: 'playwright', vantage: this.o.egress.vantage,
    });
    if (!lease) {
      this.idleUntil = Date.now() + 2000;
      return;
    }
    this.activeLeases.set(lease.attemptId, lease);
    const engine = engineForStage(lease.stage, policy);
    let browserLease: BrowserLease | null = null;
    try {
      let storageState: BrowserContextOptions['storageState'] | undefined;
      const sessionId = randomUUID();
      try {
        browserLease = await this.o.browsers.acquire(engine);
        await pool.query(`UPDATE attempts SET engine = $2 WHERE id = $1`, [lease.attemptId, engine]);
        storageState = await this.previousStorageState(lease, engine);
        await pool.query(
          `INSERT INTO sessions (id, target_id, job_id, engine, vantage, locale, timezone, viewport) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [sessionId, lease.target.id, lease.job.id, engine, this.o.egress.vantage, policy.browser.locale, policy.browser.timezone, policy.capture.viewport],
        );
      } catch (err) {
        // No target contact happened: refund the budget and retry later.
        logger.error({ err: (err as Error).message, engine }, 'preparation failed before target contact; releasing lease unstarted');
        await releaseUnstarted(pool, lease, `preparation failed: ${(err as Error).message.slice(0, 200)}`, 60).catch((e: Error) =>
          logger.error({ err: e.message }, 'could not release lease; it will be reclaimed on expiry'));
        return;
      }
      const browser = browserLease.browser;
      let crashed = false;
      await runLeasedAttempt({
        pool, policy, lease, artifactRoot: this.o.artifactRoot, kind: 'browser', engine, adapter: 'playwright', vantage: this.o.egress.vantage,
        capture: async ({ writer, deadline, signal }) => {
          const r = await captureWithBrowser({
            browser, engine, url: lease.target.url, policy, writer, deadline, signal,
            allowedInteractions: lease.job.allowed_interactions, captureVariant: lease.job.capture_variant,
            relaxedTls: lease.job.scope.relaxed_tls === true, egress: this.o.egress, storageState,
            isolation: { mode: this.o.browsers.cfg.mode, chromiumSandbox: this.o.browsers.cfg.chromiumSandbox },
          });
          crashed = r.observation.rendererCrashed || !browser.isConnected();
          await pool.query('UPDATE sessions SET user_agent = $2 WHERE id = $1', [sessionId, r.userAgent]).catch(() => undefined);
          return {
            finalUrl: r.finalUrl, engineVersion: r.engineVersion, userAgent: r.userAgent, settings: r.settings, edges: r.edges,
            limitations: r.limitations, sessionId, extractionApplicable: r.observation.validScreenshots > 0 || r.observation.contentAppeared,
            decide: ({ satisfied, missing }) => {
              const obs = { ...r.observation, requiredSatisfied: satisfied, missingRequired: missing };
              const classified = classifyBrowser(obs);
              const spent = (Date.now() - lease.leasedAt.getTime()) / 1000;
              return { classified, decision: decideAfterBrowser(routerJobFromLease(lease), classified, obs, spent, policy), useful: obs.validScreenshots > 0 };
            },
          };
        },
      });
      // Retire (not kill) the shared browser: another capture may still be using it.
      if (crashed) this.o.browsers.discard(engine, 'renderer_crash_or_disconnect');
      // In local mode the browser shares this process tree; in connect mode memory is bounded by the engine container.
      const rssMib = process.memoryUsage().rss / 1024 / 1024;
      if (this.o.browsers.cfg.mode === 'local' && rssMib > policy.browser.recycle_above_rss_mib) {
        logger.warn({ rss_mib: Math.round(rssMib) }, 'driver RSS above threshold; retiring browsers');
        this.o.browsers.retireAll('rss_above_threshold');
      }
    } finally {
      browserLease?.release();
      this.activeLeases.delete(lease.attemptId);
      this.lastProgressAt = Date.now();
    }
  }

  async run(): Promise<void> {
    const config = new Configuration({
      persistStorage: false,
      purgeOnStart: false,
      ...(this.o.memoryMbytes ? { memoryMbytes: this.o.memoryMbytes } : {}),
    });
    const max = Math.max(1, Math.min(this.o.maxConcurrency ?? this.o.policy.limits.browser_slots_global, this.o.policy.limits.browser_slots_global));
    this.autoscaled = new AutoscaledPool({
      minConcurrency: 1,
      maxConcurrency: max, // HARD cap: autoscaling never exceeds the policy
      desiredConcurrency: 1,
      maybeRunIntervalSecs: 2,
      autoscaleIntervalSecs: 10,
      // Scale down on CPU saturation / memory pressure measured by Crawlee's Snapshotter.
      systemStatusOptions: { maxMemoryOverloadedRatio: 0.2, maxCpuOverloadedRatio: 0.4, maxEventLoopOverloadedRatio: 0.6 },
      snapshotterOptions: { maxUsedMemoryRatio: 0.8 },
      runTaskFunction: async () => {
        try {
          await this.runOne();
        } catch (err) {
          logger.error({ err: (err as Error).message }, 'browser task failed');
        }
      },
      isTaskReadyFunction: async () => this.hasDueWork(),
      isFinishedFunction: async () => this.stopping,
    }, config);
    logger.info({ worker: this.workerId, max_concurrency: max, stages: this.stages() }, 'browser worker started');
    await this.autoscaled.run();
  }

  /** Graceful: no new leases; AutoscaledPool resolves once in-flight visits finish their own bounded deadline. */
  async stop(): Promise<void> {
    this.stopping = true;
  }

  async abort(): Promise<void> {
    this.stopping = true;
    if (this.autoscaled) await this.autoscaled.abort().catch(() => undefined);
  }
}
