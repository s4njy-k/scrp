/**
 * Browser driver worker service. Joins the control network (PostgreSQL) and
 * the private acquisition network (browser-engine control connection only).
 * It exposes no page-reachable listener: its health endpoint binds loopback.
 */
import type { Policy } from '../config/policy.js';
import type { Pool } from '../db/pool.js';
import { egressConfigFromEnv } from '../acquisition/egress.js';
import { logger } from '../observability/logger.js';
import { recordHeartbeat, startHealthServer, startWatchdog, type HealthSource } from '../observability/health.js';
import { BrowserPool, browserPoolConfigFromEnv } from './browserPool.js';
import { BrowserWorker } from './browserWorker.js';

export async function runBrowserWorker(pool: Pool, policy: Policy, root: string): Promise<void> {
  const egress = egressConfigFromEnv();
  const browsers = new BrowserPool(browserPoolConfigFromEnv(), policy, egress);
  const worker = new BrowserWorker({
    pool, policy, egress, browsers, artifactRoot: root,
    maxConcurrency: process.env.WORKER_MAX_CONCURRENCY ? Number(process.env.WORKER_MAX_CONCURRENCY) : undefined,
    memoryMbytes: process.env.WORKER_MEMORY_MBYTES ? Number(process.env.WORKER_MEMORY_MBYTES) : undefined,
  });
  const startedAt = new Date();
  const source: HealthSource = {
    role: 'browser-worker', workerId: worker.workerId, lastProgressAt: () => worker.lastProgressAt,
    details: () => ({ active_leases: worker.activeLeases.size }),
  };
  const health = startHealthServer(Number(process.env.HEALTH_PORT ?? 8081), [source], pool, 5 * 60_000);
  // A visit is bounded by the policy; far beyond lease duration means the process is stuck.
  startWatchdog([source], Math.max(10 * 60_000, policy.queue.lease_seconds * 5 * 1000));
  const hb = setInterval(() => { recordHeartbeat(pool, source, startedAt).catch(() => undefined); }, 10_000);
  hb.unref();

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'browser worker draining');
    const drain = worker.stop();
    setTimeout(() => process.exit(0), 90_000).unref(); // in-flight visits finish within their own deadline
    await drain;
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));

  await worker.run();
  await browsers.closeAll();
  clearInterval(hb);
  health.close();
  await pool.end();
}
