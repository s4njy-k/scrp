import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import type { Pool } from './pool.js';
import { logger } from '../observability/logger.js';

export const MIGRATIONS_DIR = fileURLToPath(new URL('../../db/migrations/', import.meta.url));

/**
 * Forward-only, checksum-verified migrations. Each file runs in its own
 * transaction under an advisory lock so concurrent starts cannot race.
 * Rollback is by release (docs/rollback.md), never by destructive teardown.
 */
export async function migrate(pool: Pool, dir = MIGRATIONS_DIR): Promise<string[]> {
  const files = readdirSync(dir).filter((f) => /^\d{4}_.+\.sql$/.test(f)).sort();
  const client = await pool.connect();
  const applied: string[] = [];
  try {
    await client.query('SELECT pg_advisory_lock(727274001)');
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
    const { rows } = await client.query<{ version: string; sha256: string }>('SELECT version, sha256 FROM schema_migrations');
    const done = new Map(rows.map((r) => [r.version, r.sha256]));
    for (const file of files) {
      const sql = readFileSync(join(dir, file), 'utf8');
      const sha = createHash('sha256').update(sql).digest('hex');
      const prior = done.get(file);
      if (prior) {
        if (prior !== sha) throw new Error(`Applied migration ${file} has changed on disk (checksum mismatch); refusing to continue`);
        continue;
      }
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (version, sha256) VALUES ($1, $2)', [file, sha]);
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`Migration ${file} failed: ${(err as Error).message}`);
      }
      applied.push(file);
      logger.info({ migration: file }, 'applied migration');
    }
    return applied;
  } finally {
    await client.query('SELECT pg_advisory_unlock(727274001)').catch(() => undefined);
    client.release();
  }
}

/** Make global_permits match the policy's slot count without disturbing held permits. */
export async function syncPermitSlots(pool: Pool, slots: number): Promise<void> {
  await pool.query(
    `INSERT INTO global_permits (slot) SELECT g FROM generate_series(1, $1::int) g ON CONFLICT (slot) DO NOTHING`,
    [slots],
  );
  // Excess slots are removed only when free; a held slot drains naturally and is removed next sync.
  await pool.query(
    `DELETE FROM global_permits WHERE slot > $1 AND (holder_job_id IS NULL OR expires_at < now())`,
    [slots],
  );
}
