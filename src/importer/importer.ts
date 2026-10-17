/**
 * CSV/JSONL importer (blueprint §6).
 *
 * Each record supplies a domain, subdomain or exact URL plus source/case
 * reference and priority, and may override the task contract fields
 * (required_artifacts, capture profile, scope, deadline, allowed interactions,
 * retention class). Every input line becomes a source_record, including
 * rejected ones (with the reason), so nothing silently disappears.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { parse as parseCsv } from 'csv-parse/sync';
import { z } from 'zod';
import type { Policy } from '../config/policy.js';
import { audit, withTransaction, type Pool, type PoolClient } from '../db/pool.js';
import { parseTargetInput, type TargetCandidate } from './url.js';
import { KNOWN_ARTIFACT_TYPES, PROFILE_DEFAULT_REQUIRED, ALLOWED_INTERACTIONS } from '../acquisition/contract.js';

export const ImportRecordSchema = z
  .object({
    target: z.string().min(1),
    kind: z.enum(['url', 'domain', 'subdomain']).optional(),
    source_ref: z.string().max(500).optional(),
    case_ref: z.string().max(200).optional(),
    priority: z.coerce.number().int().min(-1000).max(1000).optional(),
    profile: z.enum(['data_triage', 'browser_evidence']).optional(),
    urgent: z
      .union([z.boolean(), z.enum(['true', 'false', '1', '0', 'yes', 'no', ''])])
      .transform((v) => v === true || v === 'true' || v === '1' || v === 'yes')
      .optional(),
    deadline: z.string().datetime({ offset: true }).optional(),
    required_artifacts: z.union([z.array(z.string()), z.string()]).optional(),
    allowed_interactions: z.union([z.array(z.string()), z.string()]).optional(),
    retention_class: z.string().optional(),
    capture_variant: z.enum(['desktop', 'mobile']).optional(),
    child_pages_max: z.coerce.number().int().min(0).optional(),
  })
  .passthrough();

export type ImportRecord = z.infer<typeof ImportRecordSchema>;

export interface ImportOptions {
  defaultProfile: 'data_triage' | 'browser_evidence';
  windowKey: string;
  importedBy: string;
  format?: 'csv' | 'jsonl';
}

export interface ImportSummary {
  batchId: number;
  lines: number;
  accepted: number;
  rejected: number;
  targetsCreated: number;
  jobsCreated: number;
  jobsMerged: number;
  rejections: { line: number; reason: string }[];
}

const TARGET_COLUMNS = ['target', 'url', 'domain', 'subdomain'] as const;

function splitList(v: string[] | string | undefined): string[] | undefined {
  if (v === undefined) return undefined;
  const list = Array.isArray(v) ? v : v.split(/[;|]/);
  const cleaned = list.map((s) => s.trim()).filter(Boolean);
  return cleaned.length ? cleaned : undefined;
}

/** Normalise CSV/JSONL rows: accept url/domain/subdomain columns as aliases of target. */
function normaliseRow(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...row };
  if (out.target === undefined || out.target === '') {
    for (const col of TARGET_COLUMNS) {
      const v = row[col];
      if (typeof v === 'string' && v.trim()) {
        out.target = v;
        if (col !== 'url' && col !== 'target' && out.kind === undefined) out.kind = col;
        if (col === 'url' && out.kind === undefined) out.kind = 'url';
        break;
      }
    }
  }
  for (const [k, v] of Object.entries(out)) {
    if (v === '') delete out[k];
  }
  return out;
}

export function readRecords(text: string, format: 'csv' | 'jsonl'): { line: number; raw: Record<string, unknown> | null; error?: string }[] {
  if (format === 'csv') {
    const rows = parseCsv(text, {
      columns: (header: string[]) => header.map((h) => h.trim().toLowerCase()),
      skip_empty_lines: true,
      bom: true,
      relax_column_count: true,
      info: true,
    }) as { record: Record<string, unknown>; info: { lines: number } }[];
    return rows.map((r) => ({ line: r.info.lines, raw: r.record }));
  }
  const out: { line: number; raw: Record<string, unknown> | null; error?: string }[] = [];
  text.split(/\r?\n/).forEach((lineText, idx) => {
    if (!lineText.trim()) return;
    try {
      const parsed: unknown = JSON.parse(lineText);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        out.push({ line: idx + 1, raw: null, error: 'jsonl_line_not_object' });
      } else {
        out.push({ line: idx + 1, raw: parsed as Record<string, unknown> });
      }
    } catch {
      out.push({ line: idx + 1, raw: null, error: 'jsonl_parse_error' });
    }
  });
  return out;
}

async function upsertTarget(client: PoolClient, c: TargetCandidate): Promise<{ id: number; created: boolean }> {
  const ins = await client.query<{ id: number }>(
    `INSERT INTO targets (input_kind, candidate_of_input, candidate_scheme, url, scheme, hostname_ascii,
        hostname_unicode, port, path_and_query, fragment, registrable_domain, is_ip_literal, nonstandard_port, dedup_key)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     ON CONFLICT (dedup_key) DO NOTHING RETURNING id`,
    [c.inputKind, c.candidateOfInput, c.candidateScheme, c.url, c.scheme, c.hostnameAscii, c.hostnameUnicode,
     c.port, c.pathAndQuery, c.fragment, c.registrableDomain, c.isIpLiteral, c.nonstandardPort, c.dedupKey],
  );
  if (ins.rows[0]) return { id: ins.rows[0].id, created: true };
  const sel = await client.query<{ id: number }>('SELECT id FROM targets WHERE dedup_key = $1', [c.dedupKey]);
  return { id: sel.rows[0]!.id, created: false };
}

export function initialStage(profile: string, urgent: boolean, policy: Policy): 'http' | 'browser_primary' {
  if (profile === 'data_triage') return 'http';
  // Urgent complaint URLs go directly to browser evidence (§7).
  if (urgent || policy.limits.http_attempts_max === 0) return 'browser_primary';
  return 'http';
}

export async function importFile(pool: Pool, policy: Policy, filePath: string, opts: ImportOptions): Promise<ImportSummary> {
  const bytes = readFileSync(filePath);
  const format = opts.format ?? (filePath.toLowerCase().endsWith('.jsonl') || filePath.toLowerCase().endsWith('.ndjson') ? 'jsonl' : 'csv');
  return importText(pool, policy, bytes.toString('utf8'), {
    ...opts,
    format,
    filename: basename(filePath),
    sha256: createHash('sha256').update(bytes).digest('hex'),
  });
}

export async function importText(
  pool: Pool,
  policy: Policy,
  text: string,
  opts: ImportOptions & { filename: string; sha256?: string; format: 'csv' | 'jsonl' },
): Promise<ImportSummary> {
  const records = readRecords(text, opts.format);
  const sha = opts.sha256 ?? createHash('sha256').update(text).digest('hex');

  return withTransaction(pool, async (client) => {
    const batch = await client.query<{ id: number }>(
      `INSERT INTO import_batches (filename, file_sha256, format, default_profile, imported_by)
       VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [opts.filename, sha, opts.format, opts.defaultProfile, opts.importedBy],
    );
    const batchId = batch.rows[0]!.id;
    const summary: ImportSummary = { batchId, lines: records.length, accepted: 0, rejected: 0, targetsCreated: 0, jobsCreated: 0, jobsMerged: 0, rejections: [] };

    const rejectLine = async (line: number, raw: Record<string, unknown>, original: string, reason: string, rec?: Partial<ImportRecord>) => {
      await client.query(
        `INSERT INTO source_records (import_batch_id, line_number, original_input, source_ref, case_ref, priority, raw_record, rejected, rejection_reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,true,$8)`,
        [batchId, line, original, rec?.source_ref ?? null, rec?.case_ref ?? null, rec?.priority ?? 0, raw, reason],
      );
      summary.rejected += 1;
      summary.rejections.push({ line, reason });
    };

    for (const { line, raw, error } of records) {
      if (!raw) {
        await rejectLine(line, {}, '', error ?? 'unreadable_record');
        continue;
      }
      const normalised = normaliseRow(raw);
      const parsedRec = ImportRecordSchema.safeParse(normalised);
      const originalInput = typeof normalised.target === 'string' ? normalised.target : '';
      if (!parsedRec.success) {
        await rejectLine(line, raw, originalInput, `invalid_record:${parsedRec.error.issues.map((i) => i.path.join('.')).join(',')}`);
        continue;
      }
      const rec = parsedRec.data;
      const profile = rec.profile ?? opts.defaultProfile;
      const required = splitList(rec.required_artifacts) ?? PROFILE_DEFAULT_REQUIRED[profile];
      const unknownArtifact = required.find((a) => !KNOWN_ARTIFACT_TYPES.has(a));
      if (unknownArtifact) {
        await rejectLine(line, raw, originalInput, `unknown_required_artifact:${unknownArtifact}`, rec);
        continue;
      }
      if (profile === 'data_triage' && required.some((a) => a !== 'http_response_record' && a !== 'manifest')) {
        await rejectLine(line, raw, originalInput, 'data_triage_cannot_require_browser_artifacts', rec);
        continue;
      }
      const interactions = splitList(rec.allowed_interactions) ?? ['scroll'];
      const badInteraction = interactions.find((i) => !ALLOWED_INTERACTIONS.has(i));
      if (badInteraction) {
        await rejectLine(line, raw, originalInput, `interaction_not_permitted:${badInteraction}`, rec);
        continue;
      }
      const retentionClass = rec.retention_class ?? policy.retention.default_class;
      if (!(retentionClass in policy.retention.classes)) {
        await rejectLine(line, raw, originalInput, `unknown_retention_class:${retentionClass}`, rec);
        continue;
      }

      const parsed = parseTargetInput(rec.target, policy.scope, rec.kind ?? null);
      if (!parsed.ok) {
        await rejectLine(line, raw, originalInput, parsed.reason, rec);
        continue;
      }

      const src = await client.query<{ id: number }>(
        `INSERT INTO source_records (import_batch_id, line_number, original_input, source_ref, case_ref, priority, raw_record)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
        [batchId, line, rec.target, rec.source_ref ?? null, rec.case_ref ?? null, rec.priority ?? 0, raw],
      );
      const sourceId = src.rows[0]!.id;
      summary.accepted += 1;

      const targetIds: number[] = [];
      for (const cand of parsed.candidates) {
        const t = await upsertTarget(client, cand);
        if (t.created) summary.targetsCreated += 1;
        targetIds.push(t.id);
        await client.query(
          'INSERT INTO source_record_targets (source_record_id, target_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
          [sourceId, t.id],
        );
      }

      // Only the first scheme candidate is scheduled; later candidates are explicit,
      // separately recorded fallbacks created by the router on connection/TLS failure.
      const primary = parsed.candidates[0]!;
      const urgent = rec.urgent ?? false;
      const scope = {
        scheme_fallback_target_ids: targetIds.slice(1),
        child_pages_max: Math.min(rec.child_pages_max ?? policy.limits.child_pages_per_target_max, policy.limits.child_pages_per_target_max),
        follow_external_redirects: policy.scope.follow_external_redirects,
      };
      const jobIns = await client.query<{ id: number }>(
        `INSERT INTO jobs (target_id, profile, window_key, registrable_domain, priority, urgent, required_artifacts,
            capture_variant, scope, allowed_interactions, retention_class, case_ref, deadline, stage)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         ON CONFLICT (target_id, profile, capture_variant, window_key) WHERE parent_job_id IS NULL DO NOTHING
         RETURNING id`,
        [targetIds[0], profile, opts.windowKey, primary.registrableDomain, rec.priority ?? 0, urgent, required,
         rec.capture_variant ?? 'desktop', scope, interactions, retentionClass, rec.case_ref ?? null,
         rec.deadline ?? null, initialStage(profile, urgent, policy)],
      );
      let jobId: number;
      if (jobIns.rows[0]) {
        jobId = jobIns.rows[0].id;
        summary.jobsCreated += 1;
      } else {
        const existing = await client.query<{ id: number }>(
          `SELECT id FROM jobs WHERE target_id=$1 AND profile=$2 AND capture_variant=$3 AND window_key=$4 AND parent_job_id IS NULL`,
          [targetIds[0], profile, rec.capture_variant ?? 'desktop', opts.windowKey],
        );
        jobId = existing.rows[0]!.id;
        summary.jobsMerged += 1;
        // A merged seed may raise priority/urgency but never lowers it.
        await client.query(
          `UPDATE jobs SET priority = GREATEST(priority, $2), urgent = urgent OR $3, updated_at = now(),
              stage = CASE WHEN $3 AND state = 'QUEUED' AND stage = 'http' AND profile = 'browser_evidence'
                           THEN 'browser_primary'::job_stage ELSE stage END
           WHERE id = $1`,
          [jobId, rec.priority ?? 0, urgent],
        );
      }
      await client.query('INSERT INTO job_sources (job_id, source_record_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [jobId, sourceId]);
    }

    await client.query('UPDATE import_batches SET counts = $2 WHERE id = $1', [
      batchId,
      { lines: summary.lines, accepted: summary.accepted, rejected: summary.rejected, jobs_created: summary.jobsCreated, jobs_merged: summary.jobsMerged },
    ]);
    await audit(client, opts.importedBy, 'import_batch', { batch_id: batchId, filename: opts.filename, sha256: sha, ...summary, rejections: summary.rejections.slice(0, 50) });
    return summary;
  });
}
