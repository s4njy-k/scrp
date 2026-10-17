/**
 * Crash reconciliation (blueprint §12): the filesystem and database are not
 * one transaction. On start-up and periodically:
 *  - expired leases are reclaimed (interrupted attempt recorded, job requeued
 *    or ended as infrastructure-deferred);
 *  - final directories whose attempt row is still pending (crash between
 *    rename and commit) are verified against their manifest and recorded;
 *  - temporary directories with no live lease are salvaged into incomplete/
 *    with a manifest of whatever was saved, and the attempt marked interrupted;
 *  - pending attempt rows with no directory anywhere are marked interrupted;
 *  - unknown directories are reported, never deleted.
 */
import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { Policy } from '../config/policy.js';
import { audit, withTransaction, type Pool } from '../db/pool.js';
import { logger } from '../observability/logger.js';
import { reclaimExpiredLeases } from '../queue/queue.js';
import { ATTEMPT_ID_RE, AttemptWriter, findAttemptDirs, sha256File } from '../storage/artifactStore.js';
import type { AttemptManifest, ManifestEntry } from '../acquisition/contract.js';

export interface ReconcileReport {
  leasesReclaimed: number;
  orphanFinalRecovered: number;
  orphanFinalUnknown: number;
  tmpSalvaged: number;
  pendingWithoutDirectory: number;
  hashMismatches: number;
}

async function verifyManifest(root: string, relDir: string): Promise<{ manifest: AttemptManifest; mismatches: string[] } | null> {
  try {
    const manifest = JSON.parse(await readFile(join(root, relDir, 'manifest.json'), 'utf8')) as AttemptManifest;
    const mismatches: string[] = [];
    for (const a of manifest.artifacts) {
      if (!a.path || !a.sha256) continue;
      try {
        const { sha256 } = await sha256File(join(root, relDir, a.path));
        if (sha256 !== a.sha256) mismatches.push(a.path);
      } catch {
        mismatches.push(a.path);
      }
    }
    return { manifest, mismatches };
  } catch {
    return null;
  }
}

async function recordRecoveredAttempt(pool: Pool, attemptId: string, relDir: string, manifest: AttemptManifest, mismatches: string[], manifestSha: string, status: 'recovered' | 'interrupted'): Promise<void> {
  await withTransaction(pool, async (client) => {
    const upd = await client.query(
      `UPDATE attempts SET status = $2, artifact_dir = $3, manifest_sha256 = $4, outcome = $5, classification = $6,
          required_satisfied = $7, missing_required = $8, ended_at = COALESCE(ended_at, $9::timestamptz),
          error = COALESCE(error, $10), extraction_state = CASE WHEN $2 = 'recovered' THEN 'pending' ELSE 'not_applicable' END
        WHERE id = $1 AND status IN ('pending', 'interrupted')`,
      [attemptId, status, relDir, manifestSha, manifest.outcome, manifest.classification, manifest.requiredSatisfied, manifest.missingRequired, manifest.endedAt,
       status === 'recovered' ? 'recovered after crash between directory rename and database commit' : 'interrupted; partial artifacts salvaged'],
    );
    if (upd.rowCount !== 1) return;
    await client.query('DELETE FROM artifacts WHERE attempt_id = $1 AND NOT is_derivative', [attemptId]);
    for (const a of manifest.artifacts) {
      const bad = a.path ? mismatches.includes(a.path) : false;
      await client.query(
        `INSERT INTO artifacts (attempt_id, artifact_type, relative_path, size_bytes, sha256, observed_start, observed_end, creation_method, completeness, limitations, restricted, error, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [attemptId, a.type, a.path, a.sizeBytes, a.sha256, a.observedStart, a.observedEnd, a.creationMethod, bad ? 'failed' : a.completeness,
         bad ? [...a.limitations, 'hash mismatch at reconciliation'] : a.limitations, a.restricted ?? false, bad ? 'hash mismatch at reconciliation' : a.error ?? null, a.metadata ?? {}],
      );
    }
    await audit(client, 'reconciler', status === 'recovered' ? 'orphan_final_directory_recovered' : 'tmp_directory_salvaged', { dir: relDir, mismatches }, { jobId: manifest.jobId, attemptId });
  });
}

export async function reconcile(pool: Pool, policy: Policy, root: string): Promise<ReconcileReport> {
  const report: ReconcileReport = { leasesReclaimed: 0, orphanFinalRecovered: 0, orphanFinalUnknown: 0, tmpSalvaged: 0, pendingWithoutDirectory: 0, hashMismatches: 0 };
  if (policy.queue.reclaim_expired_leases) report.leasesReclaimed = await reclaimExpiredLeases(pool, policy);

  // 1. Final directories (captures/ and incomplete/) whose attempt is not recorded as committed.
  for (const location of ['captures', 'incomplete'] as const) {
    const dirs = await findAttemptDirs(root, location);
    if (dirs.length === 0) continue;
    const { rows } = await pool.query<{ id: string; status: string; artifact_dir: string | null }>(
      'SELECT id, status, artifact_dir FROM attempts WHERE id = ANY($1::uuid[])', [dirs.map((d) => d.attemptId)],
    );
    const byId = new Map(rows.map((r) => [r.id, r]));
    for (const d of dirs) {
      const row = byId.get(d.attemptId);
      if (row && row.artifact_dir === d.relativeDir) continue;
      if (!row) {
        report.orphanFinalUnknown += 1;
        await audit(pool, 'reconciler', 'orphan_directory_without_attempt_row', { dir: d.relativeDir });
        continue;
      }
      if (row.status !== 'pending' && row.status !== 'interrupted') continue;
      const v = await verifyManifest(root, d.relativeDir);
      if (!v) {
        await audit(pool, 'reconciler', 'orphan_directory_manifest_unreadable', { dir: d.relativeDir }, { attemptId: d.attemptId });
        continue;
      }
      report.hashMismatches += v.mismatches.length;
      const { sha256 } = await sha256File(join(root, d.relativeDir, 'manifest.json'));
      await recordRecoveredAttempt(pool, d.attemptId, d.relativeDir, v.manifest, v.mismatches, sha256, location === 'captures' ? 'recovered' : 'interrupted');
      report.orphanFinalRecovered += 1;
    }
  }

  // 2. Temporary directories with no live lease: salvage into incomplete/.
  let tmpNames: string[] = [];
  try {
    tmpNames = await readdir(join(root, 'tmp'));
  } catch { /* none yet */ }
  const attemptTmp = tmpNames.filter((n) => ATTEMPT_ID_RE.test(n));
  if (attemptTmp.length) {
    const { rows } = await pool.query<{ id: string; status: string; job_id: number; attempt_no: number; kind: 'http' | 'browser'; engine: string; adapter: string; vantage: string; started_at: Date; lease_live: boolean; url: string; required: string[] }>(
      `SELECT a.id, a.status, a.job_id, a.attempt_no, a.kind, a.engine, a.adapter, a.vantage, a.started_at, t.url, j.required_artifacts AS required,
              (j.current_attempt_id = a.id AND j.lease_token = a.lease_token AND j.lease_expires_at > now()) AS lease_live
         FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN targets t ON t.id = j.target_id WHERE a.id = ANY($1::uuid[])`,
      [attemptTmp],
    );
    const byId = new Map(rows.map((r) => [r.id, r]));
    for (const name of attemptTmp) {
      const row = byId.get(name);
      if (row?.lease_live) continue; // still being written by a live worker
      const st = await stat(join(root, 'tmp', name)).catch(() => null);
      if (!st) continue;
      // Grace period for a just-started attempt whose lease row is not visible yet.
      if (!row && Date.now() - st.mtimeMs < policy.queue.lease_seconds * 1000) continue;
      const writer = new AttemptWriter(root, name, Number.MAX_SAFE_INTEGER);
      const files = await listFiles(join(root, 'tmp', name));
      for (const rel of files) {
        if (rel === 'manifest.json') continue;
        writer.registerExternalFile(rel, {
          type: guessType(rel), observedStart: null, observedEnd: null, creationMethod: 'salvaged by reconciler after interruption',
          completeness: 'partial', limitations: ['attempt interrupted before finalisation; file may be incomplete'],
          restricted: rel.startsWith('session/') || rel.endsWith('.har'),
        });
      }
      const fin = await writer.finalise((entries: ManifestEntry[]) => ({
        attemptId: name, jobId: row?.job_id ?? -1, attemptNo: row?.attempt_no ?? -1, kind: row?.kind ?? 'browser', engine: row?.engine ?? 'unknown',
        adapter: row?.adapter ?? 'unknown', vantage: row?.vantage ?? 'unknown', requestedUrl: row?.url ?? 'unknown', finalUrl: null,
        startedAt: (row?.started_at ?? new Date(st.mtimeMs)).toISOString(), endedAt: new Date().toISOString(),
        outcome: 'INFRASTRUCTURE_DEFERRED', classification: 'interrupted_salvaged', requiredArtifacts: row?.required ?? [],
        requiredSatisfied: false, missingRequired: row?.required ?? [], limitations: [`salvaged ${entries.length} file(s) from an interrupted attempt`],
      }), 'incomplete');
      if (row) await recordRecoveredAttempt(pool, name, fin.relativeDir, fin.manifest, [], fin.manifestSha256, 'interrupted');
      else await audit(pool, 'reconciler', 'tmp_directory_without_attempt_row_salvaged', { dir: fin.relativeDir });
      report.tmpSalvaged += 1;
    }
  }

  // 3. Interrupted/pending attempt rows with no directory anywhere and no live lease.
  const stale = await pool.query(
    `UPDATE attempts a SET status = 'interrupted', error = COALESCE(a.error, 'no artifact directory found at reconciliation'), ended_at = COALESCE(a.ended_at, now())
      FROM jobs j WHERE j.id = a.job_id AND a.status = 'pending' AND a.artifact_dir IS NULL
        AND NOT (j.current_attempt_id = a.id AND j.lease_expires_at > now())
        AND a.started_at < now() - make_interval(secs => $1)`,
    [policy.queue.lease_seconds * 2],
  );
  report.pendingWithoutDirectory = stale.rowCount ?? 0;
  if (Object.values(report).some((v) => v > 0)) logger.info(report, 'reconciliation');
  return report;
}

async function listFiles(dir: string, prefix = ''): Promise<string[]> {
  const out: string[] = [];
  for (const ent of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const rel = prefix ? `${prefix}/${ent.name}` : ent.name;
    if (ent.isDirectory()) out.push(...(await listFiles(join(dir, ent.name), rel)));
    else if (ent.isFile() && /^[a-z0-9][a-z0-9_./-]*$/.test(rel)) out.push(rel);
  }
  return out;
}

function guessType(rel: string): ManifestEntry['type'] {
  if (rel.startsWith('screenshots/tiles/') && rel.endsWith('.png')) return 'screenshot_tile';
  if (rel.includes('early')) return 'screenshot_early';
  if (rel.includes('settled')) return 'screenshot_settled';
  if (rel.includes('full-page')) return 'screenshot_full_or_tiles';
  if (rel.startsWith('elements/')) return 'element_crop';
  if (rel === 'dom/rendered.html') return 'rendered_dom';
  if (rel === 'dom/rendered.txt') return 'rendered_text';
  if (rel.startsWith('dom/frames/')) return 'frame_dom';
  if (rel === 'network/events.jsonl') return 'network_events';
  if (rel.endsWith('.har')) return 'har';
  if (rel.startsWith('bodies/')) return 'response_body';
  if (rel === 'http/response.json') return 'http_response_record';
  if (rel === 'http/body.html') return 'raw_html';
  if (rel.startsWith('session/')) return 'session_state';
  if (rel.startsWith('logs/action')) return 'action_log';
  if (rel.startsWith('logs/console')) return 'console_log';
  return 'attempt_metadata';
}
