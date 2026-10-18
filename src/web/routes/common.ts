/** Shared helpers for route modules: validation, audit attribution and dependencies. */
import type { z } from 'zod';
import type { Policy } from '../../config/policy.js';
import { audit, type AuditRefs, type Pool, type Queryable } from '../../db/pool.js';
import { badRequest, type Ctx } from '../http.js';

export interface RouteDeps {
  pool: Pool;
  policy: Policy;
  root: string;
}

export function parseBody<T extends z.ZodType>(schema: T, body: unknown): z.infer<T> {
  const r = schema.safeParse(body);
  if (!r.success) {
    throw badRequest('validation_failed', 'request body failed validation', r.error.issues.slice(0, 20).map((i) => ({ path: i.path.join('.'), message: i.message })));
  }
  return r.data;
}

/** Audit an action performed through the API, attributed to the signed-in user and request. */
export async function auditCtx(db: Queryable, ctx: Ctx, eventType: string, details: Record<string, unknown> = {}, refs: Omit<AuditRefs, 'actorKind' | 'requestId'> = {}): Promise<void> {
  const purpose = ctx.req.headers['x-purpose'];
  await audit(db, ctx.user?.username ?? `anonymous@${ctx.ip}`, eventType, {
    ...details,
    ...(typeof purpose === 'string' && purpose.trim() ? { purpose: purpose.trim().slice(0, 300) } : {}),
    session: ctx.user?.sessionId ?? null,
  }, { ...refs, actorKind: ctx.user ? 'user' : 'service', requestId: ctx.requestId });
}

/** Expected-version check for optimistic concurrency: body.expected_version or If-Match: "<n>". */
export function expectedVersion(ctx: Ctx, body: { expected_version?: number } | null | undefined): number | null {
  if (body && typeof body.expected_version === 'number') return body.expected_version;
  const h = ctx.req.headers['if-match'];
  if (typeof h === 'string') {
    const n = Number(h.replace(/"/g, ''));
    if (Number.isInteger(n)) return n;
  }
  return null;
}
