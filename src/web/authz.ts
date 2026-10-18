/**
 * Object-level authorisation (checklist §7 "least-privilege RBAC/ABAC and
 * object-level authorisation"; blueprint v4 §27.1 "all reads enforce case
 * scope, not just hide content in front-end widgets").
 *
 * Global roles say WHAT a user may do; case membership says ON WHICH OBJECTS.
 * A job (and its target, attempts, artifacts and findings) is visible when the
 * user is a member of any case linked to it through the job's case_ref or any
 * of its seeds. Administrators see every case; every evidence read is audited.
 * Objects outside scope answer 404, so identifiers cannot be probed (IDOR).
 */
import type { Queryable } from '../db/pool.js';
import { forbidden, notFound, type AuthedUser, type Role } from './http.js';

export type CaseRole = 'owner' | 'investigator' | 'viewer';
const CASE_ROLE_RANK: Record<CaseRole, number> = { viewer: 1, investigator: 2, owner: 3 };

export function hasRole(user: AuthedUser, ...roles: Role[]): boolean {
  return roles.some((r) => user.roles.includes(r));
}

export function requireRole(user: AuthedUser, ...roles: Role[]): void {
  if (!hasRole(user, ...roles)) throw forbidden(`requires one of the roles: ${roles.join(', ')}`);
}

export function seesAllCases(user: AuthedUser): boolean {
  return user.roles.includes('admin');
}

/**
 * SQL predicate: the job aliased `jobAlias` is visible to the user whose id is
 * bound at `$userParam`, or `$allParam` (boolean) grants everything.
 */
export function jobVisibleSql(jobAlias: string, userParam: number, allParam: number): string {
  return `($${allParam}::boolean OR EXISTS (
    SELECT 1 FROM job_case_links l JOIN cases c ON c.case_ref = l.case_ref JOIN case_members m ON m.case_id = c.id
     WHERE l.job_id = ${jobAlias}.id AND m.user_id = $${userParam}::uuid))`;
}

/** Highest case role the user holds on any case linked to the job (null when none). */
async function jobCaseRole(db: Queryable, user: AuthedUser, jobId: number): Promise<CaseRole | null> {
  const { rows } = await db.query<{ case_role: CaseRole }>(
    `SELECT m.case_role FROM job_case_links l JOIN cases c ON c.case_ref = l.case_ref JOIN case_members m ON m.case_id = c.id
      WHERE l.job_id = $1 AND m.user_id = $2`,
    [jobId, user.id],
  );
  let best: CaseRole | null = null;
  for (const r of rows) if (!best || CASE_ROLE_RANK[r.case_role] > CASE_ROLE_RANK[best]) best = r.case_role;
  return best;
}

export async function assertJobAccess(db: Queryable, user: AuthedUser, jobId: number, min: CaseRole = 'viewer'): Promise<void> {
  const exists = await db.query('SELECT 1 FROM jobs WHERE id = $1', [jobId]);
  if (!exists.rowCount) throw notFound('job not found');
  if (seesAllCases(user)) return;
  const role = await jobCaseRole(db, user, jobId);
  if (!role) throw notFound('job not found');
  if (CASE_ROLE_RANK[role] < CASE_ROLE_RANK[min]) throw forbidden(`requires case role ${min} or higher`);
}

export async function assertAttemptAccess(db: Queryable, user: AuthedUser, attemptId: string, min: CaseRole = 'viewer'): Promise<{ jobId: number }> {
  const r = await db.query<{ job_id: number }>('SELECT job_id FROM attempts WHERE id = $1', [attemptId]);
  if (!r.rows[0]) throw notFound('capture not found');
  try {
    await assertJobAccess(db, user, r.rows[0].job_id, min);
  } catch (err) {
    if ((err as { status?: number }).status === 404) throw notFound('capture not found');
    throw err;
  }
  return { jobId: r.rows[0].job_id };
}

export async function assertTargetAccess(db: Queryable, user: AuthedUser, targetId: number, min: CaseRole = 'viewer'): Promise<void> {
  const exists = await db.query('SELECT 1 FROM targets WHERE id = $1', [targetId]);
  if (!exists.rowCount) throw notFound('target not found');
  if (seesAllCases(user)) return;
  const { rows } = await db.query<{ case_role: CaseRole }>(
    `SELECT m.case_role FROM jobs j JOIN job_case_links l ON l.job_id = j.id JOIN cases c ON c.case_ref = l.case_ref
       JOIN case_members m ON m.case_id = c.id WHERE j.target_id = $1 AND m.user_id = $2`,
    [targetId, user.id],
  );
  if (rows.length === 0) throw notFound('target not found');
  const best = Math.max(...rows.map((r) => CASE_ROLE_RANK[r.case_role]));
  if (best < CASE_ROLE_RANK[min]) throw forbidden(`requires case role ${min} or higher`);
}

export interface CaseRow {
  id: string;
  case_ref: string;
  title: string;
  status: string;
  sensitivity: string;
  version: number;
}

export async function assertCaseAccess(db: Queryable, user: AuthedUser, caseId: string, min: CaseRole = 'viewer'): Promise<{ caseRow: CaseRow; role: CaseRole | 'admin' }> {
  const c = await db.query<CaseRow>('SELECT id, case_ref, title, status, sensitivity, version FROM cases WHERE id = $1', [caseId]);
  if (!c.rows[0]) throw notFound('case not found');
  const m = await db.query<{ case_role: CaseRole }>('SELECT case_role FROM case_members WHERE case_id = $1 AND user_id = $2', [caseId, user.id]);
  const role = m.rows[0]?.case_role ?? null;
  if (!role) {
    if (seesAllCases(user)) return { caseRow: c.rows[0], role: 'admin' };
    throw notFound('case not found');
  }
  if (CASE_ROLE_RANK[role] < CASE_ROLE_RANK[min] && !seesAllCases(user)) throw forbidden(`requires case role ${min} or higher`);
  return { caseRow: c.rows[0], role };
}

export async function caseByRef(db: Queryable, caseRef: string): Promise<CaseRow | null> {
  return (await db.query<CaseRow>('SELECT id, case_ref, title, status, sensitivity, version FROM cases WHERE case_ref = $1', [caseRef])).rows[0] ?? null;
}

/** Case references linked to a job (for audit attribution). */
export async function jobCaseRefs(db: Queryable, jobId: number): Promise<string[]> {
  return (await db.query<{ case_ref: string }>('SELECT DISTINCT case_ref FROM job_case_links WHERE job_id = $1 ORDER BY case_ref', [jobId])).rows.map((r) => r.case_ref);
}

/** Mask restricted reference numbers for display ("NCRP 3112…7781"). */
export function maskRef(ref: string): string {
  if (ref.length <= 6) return '•'.repeat(ref.length);
  return `${ref.slice(0, 4)}…${ref.slice(-4)}`;
}
