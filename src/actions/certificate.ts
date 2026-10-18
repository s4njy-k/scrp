/**
 * BSA 2023 Section 63 certificate preparation (blueprint v4 §24.3; checklist §1).
 *
 * The platform produces:
 *  1. a NON-EDITABLE capture fact sheet (software/build, sources, capture steps,
 *     UTC/IST times, clock status, file inventory, limitations), hashed;
 *  2. a hash report listing every file and its SHA-256, hashed;
 *  3. an EDITABLE worksheet that mirrors the Schedule's Part A / Part B fields.
 *
 * It never signs, never ticks statutory declarations and never invents serial
 * numbers, IMEI/MAC/device ownership, operating-condition declarations or an
 * expert's credentials. Unknown fields stay blank. Field labels are transcribed
 * from the Schedule to the Act; a named person must record that they checked
 * the template against the official text before any worksheet is completed.
 * Platform documents are supporting material, not a determination of
 * admissibility.
 */
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { AttemptManifest } from '../acquisition/contract.js';
import type { Queryable } from '../db/pool.js';
import { canonicalJson } from '../evidence/canonical.js';
import { collectorVersion } from '../evidence/manifestContext.js';
import { formatIst } from '../evidence/time.js';
import { assertSafeRelative } from '../storage/artifactStore.js';

export const SCHEDULE_TEMPLATE_ID = 'bsa-2023-schedule-s63-4-c';
export const SCHEDULE_SOURCE = 'Bharatiya Sakshya Adhiniyam, 2023 (Act 47 of 2023), THE SCHEDULE — certificate under section 63(4)(c): https://www.indiacode.nic.in/indiacode/bitstream/123456789/20063/1/aa202347.pdf';

export const DEVICE_SOURCE_OPTIONS = ['Computer / Storage Media', 'DVR', 'Mobile', 'Flash Drive', 'CD/DVD', 'Server', 'Cloud', 'Other'] as const;
export const HASH_ALGORITHM_OPTIONS = ['SHA1', 'SHA256', 'MD5', 'Other'] as const;
export const CONTROL_OPTIONS = ['Owned', 'Maintained', 'Managed', 'Operated'] as const;

export interface WorksheetField {
  key: string;
  label: string;
  kind: 'text' | 'choice' | 'multi' | 'declaration' | 'date' | 'time';
  options?: readonly string[];
  /** Statutory declarations are affirmed only by the person signing; never pre-filled. */
  personal?: boolean;
}

const deviceFields = (prefix: string): WorksheetField[] => [
  { key: `${prefix}source_type`, label: 'Device or digital record source (tick as applicable)', kind: 'choice', options: DEVICE_SOURCE_OPTIONS },
  { key: `${prefix}source_other`, label: 'Other (specify)', kind: 'text' },
  { key: `${prefix}make_model`, label: 'Make & Model', kind: 'text' },
  { key: `${prefix}color`, label: 'Color', kind: 'text' },
  { key: `${prefix}serial_number`, label: 'Serial Number', kind: 'text' },
  { key: `${prefix}device_identifier`, label: 'IMEI/UIN/UID/MAC/Cloud ID (as applicable)', kind: 'text' },
  { key: `${prefix}other_information`, label: 'Any other relevant information about the device/digital record (specify)', kind: 'text' },
];

export const PART_A_FIELDS: WorksheetField[] = [
  { key: 'a_name', label: 'Name', kind: 'text', personal: true },
  { key: 'a_relation', label: 'Son/daughter/spouse of', kind: 'text', personal: true },
  { key: 'a_address', label: 'Residing/employed at', kind: 'text', personal: true },
  ...deviceFields('a_'),
  { key: 'a_declaration_lawful_control', label: 'Declaration: the device or digital record source was under lawful control for regularly creating, storing or processing information in the ordinary course of activities, was working properly (or any malfunction did not affect the record), and the information was regularly fed in the ordinary course — as worded in the Schedule', kind: 'declaration', personal: true },
  { key: 'a_control', label: 'The device or source of the digital record is (select): Owned / Maintained / Managed / Operated by me', kind: 'multi', options: CONTROL_OPTIONS, personal: true },
  { key: 'a_hash_values', label: 'HASH value(s) of the electronic/digital record(s)', kind: 'text' },
  { key: 'a_hash_algorithm', label: 'Algorithm used', kind: 'choice', options: HASH_ALGORITHM_OPTIONS },
  { key: 'a_hash_algorithm_other', label: 'Other algorithm (legally acceptable standard)', kind: 'text' },
  { key: 'a_signatory', label: 'Name and signature', kind: 'text', personal: true },
  { key: 'a_date', label: 'Date (DD/MM/YYYY)', kind: 'date', personal: true },
  { key: 'a_time', label: 'Time (IST, hh:mm, 24-hour)', kind: 'time', personal: true },
  { key: 'a_place', label: 'Place', kind: 'text', personal: true },
];

export const PART_B_FIELDS: WorksheetField[] = [
  { key: 'b_name', label: 'Name', kind: 'text', personal: true },
  { key: 'b_relation', label: 'Son/daughter/spouse of', kind: 'text', personal: true },
  { key: 'b_address', label: 'Residing/employed at', kind: 'text', personal: true },
  ...deviceFields('b_'),
  { key: 'b_hash_values', label: 'HASH value(s) of the electronic/digital record(s)', kind: 'text' },
  { key: 'b_hash_algorithm', label: 'Algorithm used', kind: 'choice', options: HASH_ALGORITHM_OPTIONS },
  { key: 'b_hash_algorithm_other', label: 'Other algorithm (legally acceptable standard)', kind: 'text' },
  { key: 'b_signatory', label: 'Name, designation and signature', kind: 'text', personal: true },
  { key: 'b_date', label: 'Date (DD/MM/YYYY)', kind: 'date', personal: true },
  { key: 'b_time', label: 'Time (IST, hh:mm, 24-hour)', kind: 'time', personal: true },
  { key: 'b_place', label: 'Place', kind: 'text', personal: true },
];

export function fieldsFor(part: 'A' | 'B' | 'A_and_B'): WorksheetField[] {
  return part === 'A' ? PART_A_FIELDS : part === 'B' ? PART_B_FIELDS : [...PART_A_FIELDS, ...PART_B_FIELDS];
}

export interface WorksheetValue {
  value: string | string[] | boolean | null;
  /** 'system_proposed' values come from computed facts (hashes) and must be confirmed by the signatory. */
  source: 'blank' | 'system_proposed' | 'entered';
  entered_by?: string;
  entered_at?: string;
  marked_unknown?: boolean;
}

/** Initial worksheet: everything blank except the computed hash reference and algorithm, marked as proposals. */
export function initialWorksheet(part: 'A' | 'B' | 'A_and_B', hashReportSha: string, fileCount: number): Record<string, WorksheetValue> {
  const out: Record<string, WorksheetValue> = {};
  for (const f of fieldsFor(part)) out[f.key] = { value: null, source: 'blank' };
  for (const p of part === 'A_and_B' ? ['a_', 'b_'] : part === 'A' ? ['a_'] : ['b_']) {
    out[`${p}hash_values`] = { value: `SHA-256 values of ${fileCount} file(s) are listed in the enclosed hash report (hash report SHA-256: ${hashReportSha})`, source: 'system_proposed' };
    out[`${p}hash_algorithm`] = { value: 'SHA256', source: 'system_proposed' };
  }
  return out;
}

/** Validate an edit: personal declarations cannot be system values; choices must be valid options. */
export function applyWorksheetEdits(part: 'A' | 'B' | 'A_and_B', current: Record<string, WorksheetValue>, edits: Record<string, { value: string | string[] | boolean | null; marked_unknown?: boolean }>, actor: string): Record<string, WorksheetValue> {
  const fields = new Map(fieldsFor(part).map((f) => [f.key, f]));
  const next = { ...current };
  for (const [k, e] of Object.entries(edits)) {
    const f = fields.get(k);
    if (!f) throw new Error(`unknown worksheet field: ${k}`);
    if (f.kind === 'choice' && e.value !== null && !(f.options ?? []).includes(String(e.value))) throw new Error(`${k}: not a permitted option`);
    if (f.kind === 'multi' && e.value !== null && (!Array.isArray(e.value) || e.value.some((v) => !(f.options ?? []).includes(v)))) throw new Error(`${k}: not permitted options`);
    if (f.kind === 'declaration' && e.value !== null && typeof e.value !== 'boolean') throw new Error(`${k}: declaration must be true/false, affirmed by the signatory`);
    if (f.kind === 'date' && e.value !== null && !/^\d{2}\/\d{2}\/\d{4}$/.test(String(e.value))) throw new Error(`${k}: use DD/MM/YYYY`);
    if (f.kind === 'time' && e.value !== null && !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(e.value))) throw new Error(`${k}: use hh:mm (24-hour IST)`);
    if (typeof e.value === 'string' && e.value.length > 4000) throw new Error(`${k}: too long`);
    next[k] = { value: e.value, source: e.value === null && !e.marked_unknown ? 'blank' : 'entered', entered_by: actor, entered_at: new Date().toISOString(), ...(e.marked_unknown ? { marked_unknown: true } : {}) };
  }
  return next;
}

/** Every field must be either entered or explicitly marked unknown/not applicable by a person before completion. */
export function worksheetGaps(part: 'A' | 'B' | 'A_and_B', ws: Record<string, WorksheetValue>): string[] {
  return fieldsFor(part).filter((f) => {
    const v = ws[f.key];
    if (!v) return true;
    if (v.source === 'system_proposed') return true; // must be confirmed (entered) by a person
    return v.source === 'blank' && !v.marked_unknown;
  }).map((f) => f.key);
}

export interface FactSheetResult {
  factSheetPath: string;
  factSheetSha256: string;
  hashReportPath: string;
  hashReportSha256: string;
  fileCount: number;
}

/** Build and store the non-editable fact sheet and hash report for the given attempts. */
export async function buildFactSheet(db: Queryable, root: string, certificateId: string, caseRef: string, attemptIds: string[]): Promise<FactSheetResult> {
  const attempts: Record<string, unknown>[] = [];
  const hashLines: string[] = [];
  let files = 0;
  for (const id of attemptIds) {
    const a = (await db.query<{ id: string; artifact_dir: string; manifest_sha256: string; started_at: Date; ended_at: Date | null; engine: string; engine_version: string | null; vantage: string; worker_id: string; outcome: string | null }>(
      'SELECT id, artifact_dir, manifest_sha256, started_at, ended_at, engine, engine_version, vantage, worker_id, outcome FROM attempts WHERE id = $1 AND artifact_dir IS NOT NULL', [id],
    )).rows[0];
    if (!a) throw new Error(`attempt ${id} has no committed directory`);
    assertSafeRelative(a.artifact_dir);
    const m = JSON.parse(await readFile(join(root, a.artifact_dir, 'manifest.json'), 'utf8')) as AttemptManifest & Record<string, unknown>;
    let steps: unknown = null;
    const actionLog = m.artifacts.find((x) => x.type === 'action_log' && x.path);
    if (actionLog?.path) steps = (JSON.parse(await readFile(join(root, a.artifact_dir, actionLog.path), 'utf8')) as { actions?: unknown[] }).actions?.slice(0, 200) ?? null;
    hashLines.push(`${a.manifest_sha256}  ${a.artifact_dir}/manifest.json`);
    files += 1;
    for (const e of m.artifacts) {
      if (e.path && e.sha256) {
        hashLines.push(`${e.sha256}  ${a.artifact_dir}/${e.path}`);
        files += 1;
      }
    }
    attempts.push({
      attempt_id: a.id, original_inputs: m.originalInputs ?? null, requested_url: m.requestedUrl, final_url: m.finalUrl,
      observed_from_utc: a.started_at.toISOString(), observed_from_ist: formatIst(a.started_at), observed_to_utc: a.ended_at?.toISOString() ?? null,
      engine: a.engine, engine_version: a.engine_version ?? (m.engineInfo as { version?: string } | undefined)?.version ?? null, capture_context: m.captureContext ?? null,
      network_vantage: m.networkVantage ?? { id: a.vantage }, clock: m.clock ?? null, collector_worker: a.worker_id, outcome: a.outcome,
      manifest_path: `${a.artifact_dir}/manifest.json`, manifest_sha256: a.manifest_sha256, limitations: m.limitations, capture_steps: steps,
      artifacts: m.artifacts.map((e) => ({ type: e.type, path: e.path, sha256: e.sha256, size_bytes: e.sizeBytes, observed_start: e.observedStart, observed_end: e.observedEnd, completeness: e.completeness, method: e.creationMethod, restricted: e.restricted ?? false })),
    });
  }
  const head = (await db.query<{ chain_pos: number; event_hash: string }>('SELECT chain_pos, event_hash FROM audit_events WHERE chain_pos IS NOT NULL ORDER BY chain_pos DESC LIMIT 1')).rows[0] ?? null;
  const now = new Date().toISOString();
  const factSheet = {
    format: 'cyber-web-collector/s63-fact-sheet@1', certificate_id: certificateId, case_ref: caseRef, prepared_at_utc: now, prepared_at_ist: formatIst(now),
    software: { name: 'cyber-web-collector', version: collectorVersion(), git_commit: process.env.GIT_COMMIT ?? null, node: process.version },
    template: { id: SCHEDULE_TEMPLATE_ID, source: SCHEDULE_SOURCE },
    custody_chain_head_at_preparation: head,
    attempts,
    limitations: [
      'Each capture records what one automated browser session observed from the stated network vantage at the stated time.',
      'It does not establish domain ownership, what other visitors saw, server-side behaviour that was not delivered, or legal admissibility.',
      'Statutory Part A/Part B particulars about persons and devices are NOT supplied by this system and must be completed by the responsible persons.',
    ],
  };
  const fsText = `${JSON.stringify(JSON.parse(canonicalJson(factSheet)), null, 2)}\n`;
  const hashText = `# Hash report — certificate ${certificateId} — case ${caseRef}\n# Algorithm: SHA-256 (computed over the stored bytes)\n# Prepared: ${now} UTC / ${formatIst(now)}\n${hashLines.join('\n')}\n`;
  const dir = `reports/certificates/${certificateId}`;
  await mkdir(join(root, dir), { recursive: true });
  await writeFile(join(root, dir, 'fact-sheet.json'), fsText, { mode: 0o440, flag: 'wx' });
  await writeFile(join(root, dir, 'hash-report.sha256.txt'), hashText, { mode: 0o440, flag: 'wx' });
  return {
    factSheetPath: `${dir}/fact-sheet.json`, factSheetSha256: createHash('sha256').update(fsText).digest('hex'),
    hashReportPath: `${dir}/hash-report.sha256.txt`, hashReportSha256: createHash('sha256').update(hashText).digest('hex'), fileCount: files,
  };
}
