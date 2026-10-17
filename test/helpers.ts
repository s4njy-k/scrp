import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadPolicy, PolicySchema, type Policy } from '../src/config/policy.js';
import { createPool, type Pool } from '../src/db/pool.js';
import { migrate, syncPermitSlots } from '../src/db/migrate.js';

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? '';
export const hasDb = TEST_DATABASE_URL.length > 0;
export const BROWSERS_AVAILABLE = Boolean(process.env.PLAYWRIGHT_BROWSERS_PATH);
/** Local fixture tests run the browser in-process (development profile); the sandbox is off as root or when CI's kernel forbids it. */
export const TEST_CHROMIUM_SANDBOX = process.env.CHROMIUM_SANDBOX !== 'false' && process.getuid?.() !== 0;

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };

function merge<T>(base: T, over: DeepPartial<T> | undefined): T {
  if (!over) return base;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [k, v] of Object.entries(over)) {
    const b = (base as Record<string, unknown>)[k];
    out[k] = v && typeof v === 'object' && !Array.isArray(v) && b && typeof b === 'object' ? merge(b, v as DeepPartial<typeof b>) : v;
  }
  return out as T;
}

/** Default policy with test-friendly overrides, validated by the real schema. */
export function testPolicy(over?: DeepPartial<Policy>): Policy {
  return PolicySchema.parse(merge(loadPolicy(), over));
}

export async function freshDb(policy: Policy): Promise<Pool> {
  if (!hasDb) throw new Error('TEST_DATABASE_URL not set');
  const pool = createPool(TEST_DATABASE_URL, 10);
  await pool.query('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
  await migrate(pool);
  await syncPermitSlots(pool, policy.limits.browser_slots_global);
  return pool;
}

export async function tempRoot(): Promise<{ root: string; cleanup: () => Promise<void> }> {
  const root = await mkdtemp(join(tmpdir(), 'cwc-test-'));
  for (const d of ['tmp', 'captures', 'incomplete', 'derived', 'exports']) {
    await (await import('node:fs/promises')).mkdir(join(root, d), { recursive: true });
  }
  return { root, cleanup: () => rm(root, { recursive: true, force: true }) };
}
