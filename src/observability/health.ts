/**
 * Liveness endpoint and in-process watchdog (blueprint §16). A liveness check
 * is not an acquisition check, and a Docker healthcheck alone does not restart
 * a running container: the watchdog exits a demonstrably stuck process so the
 * Compose restart policy replaces it; leases are recovered by fencing.
 */
import { createServer, type Server } from 'node:http';
import type { Pool } from '../db/pool.js';
import { logger } from './logger.js';

export interface HealthSource {
  role: string;
  workerId: string;
  lastProgressAt: () => number;
  details?: () => Record<string, unknown>;
}

export function startHealthServer(port: number, sources: HealthSource[], pool: Pool | null, staleMs: number): Server {
  const server = createServer(async (req, res) => {
    if (req.url !== '/healthz') {
      res.writeHead(404).end();
      return;
    }
    const now = Date.now();
    const parts = sources.map((s) => ({ role: s.role, worker: s.workerId, progress_age_ms: now - s.lastProgressAt(), ...(s.details?.() ?? {}) }));
    let db = 'unknown';
    if (pool) {
      try {
        await pool.query('SELECT 1');
        db = 'ok';
      } catch {
        db = 'unreachable';
      }
    }
    const stale = parts.some((p) => p.progress_age_ms > staleMs);
    const ok = !stale && db !== 'unreachable';
    res.writeHead(ok ? 200 : 503, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok, db, parts, note: 'liveness only; not evidence that acquisition succeeds' }));
  });
  // Bound to loopback inside the container: used by the Docker healthcheck only.
  server.listen(port, process.env.HEALTH_BIND ?? '127.0.0.1');
  return server;
}

export function startWatchdog(sources: HealthSource[], exitAfterMs: number): NodeJS.Timeout {
  const t = setInterval(() => {
    const now = Date.now();
    for (const s of sources) {
      if (now - s.lastProgressAt() > exitAfterMs) {
        logger.fatal({ role: s.role, worker: s.workerId, stalled_ms: now - s.lastProgressAt() }, 'watchdog: worker stalled; exiting for restart (leases recover via fencing)');
        process.exit(70);
      }
    }
  }, 15_000);
  t.unref();
  return t;
}

export async function recordHeartbeat(pool: Pool, s: HealthSource, startedAt: Date): Promise<void> {
  await pool.query(
    `INSERT INTO worker_heartbeats (worker_id, role, started_at, last_seen_at, details) VALUES ($1,$2,$3,now(),$4)
     ON CONFLICT (worker_id) DO UPDATE SET last_seen_at = now(), details = EXCLUDED.details`,
    [s.workerId, s.role, startedAt, { ...(s.details?.() ?? {}), rss_mib: Math.round(process.memoryUsage().rss / 1048576) }],
  );
}
