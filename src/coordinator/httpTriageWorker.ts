/**
 * HTTP triage loop inside the coordinator: Crawlee AutoscaledPool hard-capped
 * at http_concurrency_global, sharing the PostgreSQL ledger and budget with
 * the browser path. No nested library retries: the router owns retries.
 */
import { randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { AutoscaledPool, Configuration } from '@crawlee/core';
import type { Policy } from '../config/policy.js';
import type { Pool } from '../db/pool.js';
import { logger } from '../observability/logger.js';
import { leaseNext, readAdmission } from '../queue/queue.js';
import { runLeasedAttempt, routerJobFromLease } from '../acquisition/attemptRunner.js';
import { runHttpTriage } from '../acquisition/httpTriage.js';
import { createDispatcher, type EgressConfig } from '../acquisition/egress.js';
import { classifyHttp, decideAfterHttp } from '../router/router.js';

export class HttpTriageWorker {
  readonly workerId = `http-triage:${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;
  private autoscaled: AutoscaledPool | null = null;
  private stopping = false;
  /** Back off when due work cannot be leased (per-domain lock/pacing) instead of spinning. */
  private idleUntil = 0;
  lastProgressAt = Date.now();

  constructor(private readonly o: { pool: Pool; policy: Policy; egress: EgressConfig; artifactRoot: string }) {}

  private async hasDueWork(): Promise<boolean> {
    if (this.stopping || Date.now() < this.idleUntil) return false;
    try {
      const adm = await readAdmission(this.o.pool);
      if (adm.paused) return false;
      const { rows } = await this.o.pool.query<{ due: boolean }>(
        `SELECT EXISTS (SELECT 1 FROM jobs WHERE state IN ('QUEUED','DEFERRED') AND stage = 'http' AND next_eligible_at <= now()
           AND ($1::boolean = false OR urgent)) AS due`,
        [adm.low_priority_paused],
      );
      this.lastProgressAt = Date.now();
      return rows[0]?.due ?? false;
    } catch {
      this.lastProgressAt = Date.now();
      this.idleUntil = Date.now() + 5000;
      return false;
    }
  }

  async runOne(): Promise<void> {
    const { pool, policy, egress } = this.o;
    const lease = await leaseNext(pool, policy, {
      workerId: this.workerId, stages: ['http'], needsBrowserPermit: false, engine: 'undici', adapter: 'http-triage', vantage: egress.vantage,
    });
    if (!lease) {
      this.idleUntil = Date.now() + 1000;
      return;
    }
    const relaxedTls = lease.job.scope.relaxed_tls === true;
    const dispatcher = createDispatcher(egress, { relaxedTls, connectTimeoutMs: Math.min(10_000, policy.limits.http_attempt_seconds * 1000) });
    try {
      await runLeasedAttempt({
        pool, policy, lease, artifactRoot: this.o.artifactRoot, kind: 'http', engine: 'undici', adapter: 'http-triage', vantage: egress.vantage,
        capture: async ({ writer, deadline }) => {
          const r = await runHttpTriage({ url: lease.target.url, policy, writer, dispatcher, egress, deadline });
          return {
            finalUrl: r.finalUrl, engineVersion: `undici (node ${process.versions.node})`, userAgent: policy.http.user_agent,
            settings: { relaxed_tls: relaxedTls, hops: r.hops.length }, edges: r.edges, limitations: r.limitations,
            extractionApplicable: r.bodySaved,
            decide: () => {
              const classified = classifyHttp(r.observation);
              const spent = (Date.now() - lease.leasedAt.getTime()) / 1000;
              const decision = decideAfterHttp(routerJobFromLease(lease), classified, spent, policy);
              return { classified, decision, useful: r.bodySaved || r.observation.status !== null };
            },
          };
        },
      });
    } finally {
      await dispatcher.close().catch(() => undefined);
      this.lastProgressAt = Date.now();
    }
  }

  async run(): Promise<void> {
    const config = new Configuration({ persistStorage: false, purgeOnStart: false });
    this.autoscaled = new AutoscaledPool({
      minConcurrency: 1,
      maxConcurrency: this.o.policy.limits.http_concurrency_global,
      desiredConcurrency: Math.min(2, this.o.policy.limits.http_concurrency_global),
      maybeRunIntervalSecs: 1,
      runTaskFunction: async () => {
        try {
          await this.runOne();
        } catch (err) {
          logger.error({ err: (err as Error).message }, 'http triage task failed');
        }
      },
      isTaskReadyFunction: async () => this.hasDueWork(),
      isFinishedFunction: async () => this.stopping,
    }, config);
    logger.info({ worker: this.workerId, max_concurrency: this.o.policy.limits.http_concurrency_global }, 'http triage started');
    await this.autoscaled.run();
  }

  stop(): void {
    this.stopping = true;
  }
}
