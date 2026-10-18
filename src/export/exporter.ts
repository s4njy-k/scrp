/**
 * Daily JSONL/CSV status export (blueprint §16). Restricted artifacts
 * (cookies, HAR) are referenced by type only and never inlined; ordinary
 * exports carry no captured credentials. The three assessments stay separate:
 * acquisition completeness, extraction quality and fraud assessment.
 */
import { createHash } from 'node:crypto';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { audit, type Pool } from '../db/pool.js';

export interface ExportRow {
  job_id: number;
  parent_job_id: number | null;
  target_url: string;
  registrable_domain: string;
  profile: string;
  window_key: string;
  case_ref: string | null;
  source_refs: string[];
  state: string;
  outcome: string | null;
  outcome_reason: string | null;
  http_attempts: number;
  browser_attempts: number;
  active_seconds_used: number;
  attempts: {
    attempt_id: string; attempt_no: number; kind: string; engine: string; status: string; outcome: string | null;
    classification: string | null; required_satisfied: boolean | null; missing_required: string[] | null;
    artifact_dir: string | null; manifest_sha256: string | null; started_at: string; ended_at: string | null;
  }[];
  identifiers: { field_type: string; normalised_value: string | null; method: string; validation_state: string; display_context: string; attempt_id: string }[];
  field_status: Record<string, string>;
  findings: { assessment: string; rationale: string; created_by: string }[];
}

export async function buildExportRows(pool: Pool, date: string): Promise<ExportRow[]> {
  const { rows } = await pool.query<ExportRow>(
    `SELECT j.id AS job_id, j.parent_job_id, t.url AS target_url, j.registrable_domain, j.profile, j.window_key, j.case_ref,
            COALESCE((SELECT array_agg(DISTINCT s.source_ref) FILTER (WHERE s.source_ref IS NOT NULL)
                        FROM job_sources js JOIN source_records s ON s.id = js.source_record_id WHERE js.job_id = j.id), ARRAY[]::text[]) AS source_refs,
            j.state, j.outcome, j.outcome_reason, j.http_attempts, j.browser_attempts, j.active_seconds_used,
            COALESCE((SELECT json_agg(json_build_object('attempt_id', a.id, 'attempt_no', a.attempt_no, 'kind', a.kind, 'engine', a.engine,
                        'status', a.status, 'outcome', a.outcome, 'classification', a.classification, 'required_satisfied', a.required_satisfied,
                        'missing_required', a.missing_required, 'artifact_dir', a.artifact_dir, 'manifest_sha256', a.manifest_sha256,
                        'started_at', a.started_at, 'ended_at', a.ended_at) ORDER BY a.attempt_no) FROM attempts a WHERE a.job_id = j.id), '[]'::json) AS attempts,
            COALESCE((SELECT json_agg(json_build_object('field_type', i.field_type, 'normalised_value', i.normalised_value, 'method', i.method,
                        'validation_state', i.validation_state, 'display_context', i.display_context, 'attempt_id', i.attempt_id))
                        FROM identifiers i WHERE i.job_id = j.id), '[]'::json) AS identifiers,
            COALESCE((SELECT json_object_agg(f.field_type, f.status) FROM identifier_field_status f
                        WHERE f.attempt_id = (SELECT a2.id FROM attempts a2 WHERE a2.job_id = j.id AND a2.extraction_state = 'done' ORDER BY a2.attempt_no DESC LIMIT 1)), '{}'::json) AS field_status,
            COALESCE((SELECT json_agg(json_build_object('assessment', f.assessment, 'rationale', f.rationale, 'created_by', f.created_by))
                        FROM findings f WHERE f.job_id = j.id), '[]'::json) AS findings
       FROM jobs j JOIN targets t ON t.id = j.target_id
      WHERE j.updated_at::date = $1::date OR j.created_at::date = $1::date
      ORDER BY j.id`,
    [date],
  );
  return rows;
}

export function csvCell(v: unknown): string {
  const s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join(';') : typeof v === 'object' ? JSON.stringify(v) : String(v);
  // Neutralise spreadsheet formula injection from untrusted page-derived text.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function toCsv(rows: ExportRow[]): string {
  const cols = ['job_id', 'parent_job_id', 'target_url', 'registrable_domain', 'profile', 'window_key', 'case_ref', 'source_refs', 'state', 'outcome',
    'outcome_reason', 'http_attempts', 'browser_attempts', 'active_seconds_used', 'attempt_count', 'last_artifact_dir', 'identifier_count', 'fraud_assessment'] as const;
  const lines = [cols.join(',')];
  for (const r of rows) {
    const rec: Record<string, unknown> = { ...r, attempt_count: r.attempts.length, last_artifact_dir: r.attempts.at(-1)?.artifact_dir ?? null,
      identifier_count: r.identifiers.length, fraud_assessment: r.findings.at(-1)?.assessment ?? 'unknown' };
    lines.push(cols.map((c) => csvCell(rec[c])).join(','));
  }
  return `${lines.join('\n')}\n`;
}

export async function writeExport(pool: Pool, root: string, date: string, format: 'jsonl' | 'csv'): Promise<{ relativePath: string; sha256: string; rows: number }> {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('date must be YYYY-MM-DD');
  const rows = await buildExportRows(pool, date);
  const body = format === 'jsonl' ? rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : '') : toCsv(rows);
  const sha256 = createHash('sha256').update(body).digest('hex');
  const relativePath = `exports/${date}/status-${date}-${sha256.slice(0, 12)}.${format}`;
  const abs = join(root, relativePath);
  await mkdir(join(root, 'exports', date), { recursive: true });
  await writeFile(`${abs}.tmp`, body, { mode: 0o640 });
  await rename(`${abs}.tmp`, abs);
  await pool.query('INSERT INTO exports (export_date, format, relative_path, sha256, row_count) VALUES ($1,$2,$3,$4,$5)', [date, format, relativePath, sha256, rows.length]);
  await audit(pool, 'exporter', 'export_written', { date, format, relativePath, sha256, rows: rows.length });
  return { relativePath, sha256, rows: rows.length };
}
