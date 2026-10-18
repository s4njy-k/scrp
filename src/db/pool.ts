import { readFileSync } from 'node:fs';
import pg from 'pg';
import { logger } from '../observability/logger.js';

const { Pool } = pg;
export type Pool = pg.Pool;
export type PoolClient = pg.PoolClient;

// Return bigint columns (bigserial ids, counts) as JS numbers; ids stay far below 2^53.
pg.types.setTypeParser(20, (v: string) => Number(v));

/**
 * Connection settings: DATABASE_URL, or PGHOST/PGPORT/PGUSER/PGDATABASE with the
 * password read from PGPASSWORD_FILE (a Compose secret) so it never appears in
 * the environment, `docker inspect` output or logs.
 */
function connectionConfig(connectionString: string | undefined): pg.PoolConfig {
  if (connectionString) return { connectionString };
  const host = process.env.PGHOST;
  if (!host) throw new Error('DATABASE_URL or PGHOST/PGUSER/PGDATABASE (+ PGPASSWORD_FILE) must be set');
  const passwordFile = process.env.PGPASSWORD_FILE;
  return {
    host,
    port: Number(process.env.PGPORT ?? 5432),
    user: process.env.PGUSER,
    database: process.env.PGDATABASE,
    password: passwordFile ? readFileSync(passwordFile, 'utf8').trim() : process.env.PGPASSWORD,
  };
}

export function createPool(connectionString = process.env.DATABASE_URL, max = 5): Pool {
  const pool = new Pool({
    ...connectionConfig(connectionString),
    max,
    // Keep transactions short (§12): bound statement and idle-in-transaction time.
    statement_timeout: 30_000,
    idle_in_transaction_session_timeout: 30_000,
    connectionTimeoutMillis: 10_000,
    application_name: `cyber-web-collector:${process.env.COLLECTOR_ROLE ?? 'cli'}`,
  });
  pool.on('error', (err) => logger.error({ err: err.message }, 'idle PostgreSQL client error'));
  return pool;
}

export async function withTransaction<T>(pool: Pool, fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

export type Queryable = Pick<pg.PoolClient, 'query'>;

export interface AuditRefs {
  jobId?: number | null;
  attemptId?: string | null;
  /** 'user' for authenticated analysts, 'operator' for CLI actions, 'service' otherwise. */
  actorKind?: 'service' | 'user' | 'operator';
  caseRef?: string | null;
  objectType?: string | null;
  objectId?: string | number | null;
  outcome?: string | null;
  requestId?: string | null;
}

/**
 * Append an event to the audit log. Every event is later sealed into the
 * tamper-evident custody chain (src/evidence/custody.ts); rows are append-only.
 */
export async function audit(
  db: Queryable,
  actor: string,
  eventType: string,
  details: Record<string, unknown> = {},
  refs: AuditRefs = {},
): Promise<void> {
  await db.query(
    `INSERT INTO audit_events (actor, event_type, job_id, attempt_id, details, actor_kind, case_ref, object_type, object_id, outcome, request_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [actor, eventType, refs.jobId ?? null, refs.attemptId ?? null, details, refs.actorKind ?? 'service', refs.caseRef ?? null,
     refs.objectType ?? null, refs.objectId === undefined || refs.objectId === null ? null : String(refs.objectId), refs.outcome ?? null, refs.requestId ?? null],
  );
}
