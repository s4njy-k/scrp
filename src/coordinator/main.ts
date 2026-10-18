/**
 * Coordinator service: import/export, scheduling support, HTTP triage,
 * reconciliation, admission control, extraction and daily status export.
 * It is on the control network (PostgreSQL) and reaches targets only through
 * the egress gateway.
 */
import { hostname } from 'node:os';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { Policy } from '../config/policy.js';
import type { Pool } from '../db/pool.js';
import { migrate, syncPermitSlots } from '../db/migrate.js';
import { logger } from '../observability/logger.js';
import { recordHeartbeat, startHealthServer, startWatchdog, type HealthSource } from '../observability/health.js';
import { egressConfigFromEnv, gatewayHealthy } from '../acquisition/egress.js';
import { HttpTriageWorker } from './httpTriageWorker.js';
import { reconcile } from './reconciler.js';
import { evaluateAdmission } from './admission.js';
import { applyRetention } from './retention.js';
import { claimNextExtraction, resetStaleExtractions, runExtraction } from '../extraction/runner.js';
import { writeExport } from '../export/exporter.js';
import { sealPending } from '../evidence/custody.js';

export async function ensureArtifactLayout(root: string): Promise<void> {
  for (const d of ['tmp', 'captures', 'incomplete', 'derived', 'exports', 'reports', 'packages', 'uploads']) await mkdir(join(root, d), { recursive: true, mode: 0o750 });
}

export async function runCoordinator(pool: Pool, policy: Policy, root: string): Promise<void> {
  const egress = egressConfigFromEnv();
  if (process.env.MIGRATE_ON_START !== 'false') await migrate(pool);
  await syncPermitSlots(pool, policy.limits.browser_slots_global);
  await ensureArtifactLayout(root);
  await resetStaleExtractions(pool);
  await reconcile(pool, policy, root);

  const triage = new HttpTriageWorker({ pool, policy, egress, artifactRoot: root });
  let loopProgress = Date.now();
  const startedAt = new Date();
  const workerId = `coordinator:${hostname()}:${process.pid}`;
  const sources: HealthSource[] = [
    { role: 'coordinator', workerId, lastProgressAt: () => loopProgress },
    { role: 'http-triage', workerId: triage.workerId, lastProgressAt: () => triage.lastProgressAt },
  ];
  const health = startHealthServer(Number(process.env.HEALTH_PORT ?? 8081), sources, pool, 5 * 60_000);
  startWatchdog(sources, 15 * 60_000);

  let stopping = false;
  const every = (ms: number, name: string, fn: () => Promise<unknown>) => {
    let running = false;
    const t = setInterval(() => {
      if (running || stopping) return;
      running = true;
      // Progress means "the loop is alive", even when a task fails because the database
      // is down: the watchdog must only restart a genuinely stalled process.
      fn().catch((err: Error) => logger.error({ task: name, err: err.message }, 'coordinator task failed'))
        .finally(() => { running = false; loopProgress = Date.now(); });
    }, ms);
    t.unref();
    return t;
  };

  const timers = [
    every(30_000, 'reconcile', () => reconcile(pool, policy, root)),
    // Seal committed audit events into the custody hash chain within seconds.
    every(2_000, 'custody-seal', async () => { while ((await sealPending(pool)) >= 1000) { /* drain backlog */ } }),
    every(30_000, 'admission', async () => evaluateAdmission(pool, policy, root, await gatewayHealthy(egress))),
    every(10_000, 'heartbeat', async () => { for (const s of sources) await recordHeartbeat(pool, s, startedAt); }),
    every(3_600_000, 'retention', () => applyRetention(pool, policy, root, { deleteEnabled: process.env.RETENTION_DELETE_ENABLED === 'true' })),
    every(300_000, 'daily-export', async () => {
      const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
      const done = await pool.query(`SELECT 1 FROM exports WHERE export_date = $1 AND format = 'jsonl'`, [yesterday]);
      if (!done.rowCount) await writeExport(pool, root, yesterday, 'jsonl');
    }),
  ];
  await evaluateAdmission(pool, policy, root, await gatewayHealthy(egress)).catch((err: Error) => logger.error({ err: err.message }, 'initial admission check failed'));

  // Extraction loop: sequential, never holds a browser permit; OCR serialised inside.
  const extractionLoop = (async () => {
    while (!stopping) {
      try {
        const a = await claimNextExtraction(pool);
        loopProgress = Date.now();
        if (!a) {
          await new Promise((r) => setTimeout(r, 3000));
          continue;
        }
        await runExtraction(pool, policy, root, a).catch(async (err: Error) => {
          logger.error({ attempt: a.id, err: err.message }, 'extraction failed');
          await pool.query(`UPDATE attempts SET extraction_state = 'failed' WHERE id = $1`, [a.id]);
        });
      } catch (err) {
        loopProgress = Date.now();
        logger.error({ err: (err as Error).message }, 'extraction loop error (database?)');
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  })();

  const shutdown = async (signal: string) => {
    if (stopping) return;
    stopping = true;
    logger.info({ signal }, 'coordinator shutting down');
    triage.stop();
    timers.forEach(clearInterval);
    health.close();
    setTimeout(() => process.exit(0), 25_000).unref();
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));

  await Promise.all([triage.run(), extractionLoop]);
  await pool.end();
}
