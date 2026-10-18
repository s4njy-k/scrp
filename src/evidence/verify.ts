/**
 * "Verify Evidence" (checklist §1, §11; blueprint v4 §24.4): recompute every
 * artifact hash from the bytes on disk, compare with the attempt manifest and
 * with the ledger, flag missing/corrupted files, and export a verification
 * report that is itself hashed and recorded in the custody chain.
 */
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { AttemptManifest } from '../acquisition/contract.js';
import { audit, type Pool } from '../db/pool.js';
import { assertSafeRelative, sha256File } from '../storage/artifactStore.js';
import { canonicalJson } from './canonical.js';
import { formatIst } from './time.js';

export type ArtifactCheck = {
  artifact_id: number | null;
  type: string;
  path: string;
  expected_sha256: string | null;
  actual_sha256: string | null;
  status: 'ok' | 'missing' | 'mismatch' | 'ledger_mismatch' | 'not_in_ledger';
  derivative: boolean;
};

export interface AttemptVerification {
  attempt_id: string;
  job_id: number;
  artifact_dir: string | null;
  manifest: { path: string; ledger_sha256: string | null; actual_sha256: string | null; status: 'ok' | 'missing' | 'mismatch' | 'no_directory' };
  artifacts: ArtifactCheck[];
  failed_entries_recorded: number;
  ok: boolean;
}

interface LedgerArtifact {
  id: number;
  artifact_type: string;
  relative_path: string | null;
  sha256: string | null;
  is_derivative: boolean;
  metadata: Record<string, unknown>;
}

async function hashOrNull(path: string): Promise<string | null> {
  try {
    return (await sha256File(path)).sha256;
  } catch {
    return null;
  }
}

export async function verifyAttempt(pool: Pool, root: string, attemptId: string): Promise<AttemptVerification> {
  const a = (await pool.query<{ id: string; job_id: number; artifact_dir: string | null; manifest_sha256: string | null }>(
    'SELECT id, job_id, artifact_dir, manifest_sha256 FROM attempts WHERE id = $1', [attemptId],
  )).rows[0];
  if (!a) throw new Error(`attempt ${attemptId} not found`);
  const ledger = (await pool.query<LedgerArtifact>(
    'SELECT id, artifact_type, relative_path, sha256, is_derivative, metadata FROM artifacts WHERE attempt_id = $1 ORDER BY id', [attemptId],
  )).rows;
  const result: AttemptVerification = {
    attempt_id: a.id, job_id: a.job_id, artifact_dir: a.artifact_dir,
    manifest: { path: 'manifest.json', ledger_sha256: a.manifest_sha256, actual_sha256: null, status: 'no_directory' },
    artifacts: [], failed_entries_recorded: ledger.filter((l) => !l.relative_path).length, ok: false,
  };
  if (!a.artifact_dir) return result;
  assertSafeRelative(a.artifact_dir);
  const dir = join(root, a.artifact_dir);
  const manifestSha = await hashOrNull(join(dir, 'manifest.json'));
  result.manifest.actual_sha256 = manifestSha;
  result.manifest.status = manifestSha === null ? 'missing' : manifestSha === a.manifest_sha256 ? 'ok' : 'mismatch';

  let manifest: AttemptManifest | null = null;
  if (manifestSha) {
    try {
      manifest = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')) as AttemptManifest;
    } catch {
      manifest = null;
    }
  }
  const ledgerByPath = new Map(ledger.filter((l) => !l.is_derivative && l.relative_path).map((l) => [l.relative_path!, l]));
  const seen = new Set<string>();
  for (const e of manifest?.artifacts ?? []) {
    if (!e.path || !e.sha256) continue;
    seen.add(e.path);
    const actual = await hashOrNull(join(dir, e.path));
    const row = ledgerByPath.get(e.path);
    let status: ArtifactCheck['status'] = actual === null ? 'missing' : actual !== e.sha256 ? 'mismatch' : 'ok';
    if (status === 'ok' && !row) status = 'not_in_ledger';
    else if (status === 'ok' && row && row.sha256 !== e.sha256) status = 'ledger_mismatch';
    result.artifacts.push({ artifact_id: row?.id ?? null, type: e.type, path: e.path, expected_sha256: e.sha256, actual_sha256: actual, status, derivative: false });
  }
  // Ledger rows that the manifest does not describe (or when the manifest is unreadable).
  for (const [path, row] of ledgerByPath) {
    if (seen.has(path)) continue;
    const actual = await hashOrNull(join(dir, path));
    result.artifacts.push({
      artifact_id: row.id, type: row.artifact_type, path, expected_sha256: row.sha256, actual_sha256: actual,
      status: actual === null ? 'missing' : actual === row.sha256 ? (manifest ? 'ledger_mismatch' : 'ok') : 'mismatch', derivative: false,
    });
  }
  // Derivatives (thumbnails, extraction output) are verified too, against their own recorded hashes.
  for (const row of ledger.filter((l) => l.is_derivative && l.relative_path)) {
    const rel = row.relative_path!;
    assertSafeRelative(rel);
    const abs = row.metadata?.root_relative === true ? join(root, rel) : join(dir, rel);
    const actual = await hashOrNull(abs);
    result.artifacts.push({
      artifact_id: row.id, type: row.artifact_type, path: rel, expected_sha256: row.sha256, actual_sha256: actual,
      status: actual === null ? 'missing' : actual === row.sha256 ? 'ok' : 'mismatch', derivative: true,
    });
  }
  result.ok = result.manifest.status === 'ok' && manifest !== null && result.artifacts.every((c) => c.status === 'ok');

  for (const c of result.artifacts) {
    if (c.artifact_id === null) continue;
    const state = c.status === 'ok' ? 'verified' : c.status === 'missing' ? 'missing' : 'mismatch';
    await pool.query('UPDATE artifacts SET verification_state = $2, last_verified_at = now() WHERE id = $1', [c.artifact_id, state]);
  }
  return result;
}

export interface VerificationReport {
  format: 'cyber-web-collector/verification-report@1';
  run_id: string;
  scope: 'attempt' | 'job' | 'case';
  object_id: string;
  requested_by: string;
  started_at_utc: string;
  finished_at_utc: string;
  finished_at_ist: string;
  result: 'pass' | 'fail';
  counts: { attempts: number; artifacts_checked: number; ok: number; missing: number; mismatch: number; ledger_mismatch: number; manifest_failures: number };
  attempts: AttemptVerification[];
  statement: string;
}

async function attemptsForScope(pool: Pool, scope: 'attempt' | 'job' | 'case', objectId: string): Promise<string[]> {
  if (scope === 'attempt') return objectId.split(',').map((x) => x.trim()).filter(Boolean);
  if (scope === 'job') {
    return (await pool.query<{ id: string }>('SELECT id FROM attempts WHERE job_id = $1 AND artifact_dir IS NOT NULL ORDER BY attempt_no', [Number(objectId)])).rows.map((r) => r.id);
  }
  return (await pool.query<{ id: string }>(
    `SELECT DISTINCT a.id, a.started_at FROM attempts a JOIN jobs j ON j.id = a.job_id
      WHERE a.artifact_dir IS NOT NULL AND (j.case_ref = $1 OR EXISTS (
        SELECT 1 FROM job_sources js JOIN source_records s ON s.id = js.source_record_id WHERE js.job_id = j.id AND s.case_ref = $1))
      ORDER BY a.started_at`,
    [objectId],
  )).rows.map((r) => r.id);
}

/** Verify a scope, export the report under ARTIFACT_ROOT/reports/verification/, record it and audit it. */
export async function runVerification(pool: Pool, root: string, scope: 'attempt' | 'job' | 'case', objectId: string, requestedBy: string,
  opts: { actorKind?: 'user' | 'operator' | 'service'; requestId?: string | null; caseRef?: string | null } = {}): Promise<VerificationReport & { report_path: string; report_sha256: string }> {
  const runId = randomUUID();
  const startedAt = new Date().toISOString();
  await pool.query('INSERT INTO verification_runs (id, scope, object_id, requested_by, started_at) VALUES ($1,$2,$3,$4,$5)', [runId, scope, objectId, requestedBy, startedAt]);
  const ids = await attemptsForScope(pool, scope, objectId);
  const attempts: AttemptVerification[] = [];
  for (const id of ids.slice(0, 5000)) attempts.push(await verifyAttempt(pool, root, id));
  const all = attempts.flatMap((a) => a.artifacts);
  const counts = {
    attempts: attempts.length,
    artifacts_checked: all.length,
    ok: all.filter((c) => c.status === 'ok').length,
    missing: all.filter((c) => c.status === 'missing').length,
    mismatch: all.filter((c) => c.status === 'mismatch').length,
    ledger_mismatch: all.filter((c) => c.status === 'ledger_mismatch' || c.status === 'not_in_ledger').length,
    manifest_failures: attempts.filter((a) => a.manifest.status !== 'ok').length,
  };
  const pass = attempts.length > 0 && attempts.every((a) => a.ok);
  const finishedAt = new Date().toISOString();
  const report: VerificationReport = {
    format: 'cyber-web-collector/verification-report@1', run_id: runId, scope, object_id: objectId, requested_by: requestedBy,
    started_at_utc: startedAt, finished_at_utc: finishedAt, finished_at_ist: formatIst(finishedAt), result: pass ? 'pass' : 'fail', counts, attempts,
    statement: attempts.length === 0
      ? 'No committed attempt directories were found for this scope; nothing could be verified.'
      : 'SHA-256 values were recomputed from the stored bytes and compared with each attempt manifest and with the ledger. Integrity verification does not by itself establish authenticity, lawful acquisition or admissibility.',
  };
  const text = `${canonicalJson(report)}\n`;
  const rel = `reports/verification/${runId}.json`;
  await mkdir(join(root, 'reports', 'verification'), { recursive: true });
  await writeFile(join(root, rel), text, { mode: 0o640, flag: 'wx' });
  const sha = createHash('sha256').update(text).digest('hex');
  await pool.query(
    `UPDATE verification_runs SET finished_at = $2, result = $3, counts = $4, report_path = $5, report_sha256 = $6 WHERE id = $1`,
    [runId, finishedAt, report.result, counts, rel, sha],
  );
  await audit(pool, requestedBy, 'evidence_verified', { run_id: runId, scope, result: report.result, counts, report_path: rel, report_sha256: sha },
    { actorKind: opts.actorKind ?? 'operator', objectType: scope, objectId, outcome: report.result, requestId: opts.requestId ?? null, caseRef: opts.caseRef ?? (scope === 'case' ? objectId : null) });
  return { ...report, report_path: rel, report_sha256: sha };
}
