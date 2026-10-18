/**
 * Post-commit extraction (blueprint §11). Runs in the coordinator after the
 * original artifacts are preserved, so it never holds a browser permit.
 * Source artifacts are re-hashed before use; derived outputs (QR, OCR,
 * identifiers) go to derived/<attempt-id>/ with their own manifest pointing at
 * source hashes. The immutable attempt directory is never modified.
 */
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Policy } from '../config/policy.js';
import { audit, withTransaction, type Pool } from '../db/pool.js';
import { logger } from '../observability/logger.js';
import { htmlToText } from '../router/signals.js';
import { sha256File } from '../storage/artifactStore.js';
import {
  ALL_FIELDS, confidenceFor, dedupeIdentifiers, domTemplateHash, EXTRACTOR_VERSION, extractBrandClaims, extractFromHtmlAttributes, extractFromText,
  SIGNAL_ONLY_FIELDS, valueKey, type FieldType, type Identifier,
} from './identifiers.js';
import { makeThumbnail } from './thumbnail.js';
import { recordRiskAssessment } from '../investigation/risk.js';
import { decodeQrFromPng } from './qr.js';
import { ocrAvailable, ocrImage } from './ocr.js';
import { parseTargetInput, type TargetCandidate } from '../importer/url.js';
import { upsertTarget } from '../importer/importer.js';

interface ArtifactRow {
  id: number;
  artifact_type: string;
  relative_path: string | null;
  sha256: string | null;
  metadata: Record<string, unknown>;
}

interface AttemptRow {
  id: string;
  job_id: number;
  kind: 'http' | 'browser';
  artifact_dir: string;
  outcome: string | null;
  target_id: number;
  parent_job_id: number | null;
  profile: string;
  final_url: string | null;
  target_url: string;
  registrable_domain: string;
  scope: Record<string, unknown>;
}

const RELEVANT_CHILD_LINK = /(contact|about|support|help|pay(ment)?|checkout|login|signin|sign-in|register|kyc|refund|customer|care|upi|bank|deposit|withdraw|recharge|invest|plans?|terms|privacy)/i;

export async function claimNextExtraction(pool: Pool): Promise<AttemptRow | null> {
  const { rows } = await pool.query<AttemptRow>(
    `WITH next AS (
       SELECT a.id FROM attempts a
        WHERE a.extraction_state = 'pending' AND a.status IN ('committed', 'committed_lease_lost', 'recovered') AND a.artifact_dir IS NOT NULL
        ORDER BY a.started_at LIMIT 1 FOR UPDATE SKIP LOCKED)
     UPDATE attempts a SET extraction_state = 'running' FROM next, jobs j, targets t
      WHERE a.id = next.id AND j.id = a.job_id AND t.id = j.target_id
      RETURNING a.id, a.job_id, a.kind, a.artifact_dir, a.outcome, j.target_id, j.parent_job_id, j.profile, j.scope,
                j.registrable_domain, t.url AS target_url, NULL::text AS final_url`,
  );
  return rows[0] ?? null;
}

export async function resetStaleExtractions(pool: Pool): Promise<number> {
  const r = await pool.query(`UPDATE attempts SET extraction_state = 'pending' WHERE extraction_state = 'running'`);
  return r.rowCount ?? 0;
}

export async function runExtraction(pool: Pool, policy: Policy, root: string, attempt: AttemptRow): Promise<void> {
  const failures: string[] = [];
  const { rows: artifacts } = await pool.query<ArtifactRow>(
    `SELECT id, artifact_type, relative_path, sha256, metadata FROM artifacts WHERE attempt_id = $1 AND relative_path IS NOT NULL AND NOT is_derivative ORDER BY id`,
    [attempt.id],
  );
  const dir = join(root, attempt.artifact_dir);
  let finalUrl: string | null = null;
  try {
    const manifest = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8')) as { finalUrl: string | null };
    finalUrl = manifest.finalUrl;
  } catch (err) {
    failures.push(`manifest unreadable: ${(err as Error).message}`);
  }
  const baseUrl = finalUrl ?? attempt.target_url;

  // Integrity check before deriving anything: hash the saved bytes again.
  const verified = new Map<number, Buffer>();
  const load = async (a: ArtifactRow): Promise<Buffer | null> => {
    if (verified.has(a.id)) return verified.get(a.id)!;
    try {
      const p = join(dir, a.relative_path!);
      const { sha256 } = await sha256File(p);
      if (sha256 !== a.sha256) {
        failures.push(`hash mismatch: ${a.relative_path}`);
        await audit(pool, 'extraction', 'artifact_hash_mismatch', { path: a.relative_path, expected: a.sha256, actual: sha256 }, { attemptId: attempt.id });
        return null;
      }
      const buf = await readFile(p);
      verified.set(a.id, buf);
      return buf;
    } catch (err) {
      failures.push(`unreadable ${a.relative_path}: ${(err as Error).message}`);
      return null;
    }
  };

  const ids: Identifier[] = [];
  const links = new Set<string>();
  const formActions = new Set<string>();
  const apiEndpoints = new Set<string>();
  const qrResults: Record<string, unknown>[] = [];
  const ocrResults: { source: string; sha256: string | null; text: string; engine: string }[] = [];

  for (const a of artifacts) {
    const t = a.artifact_type;
    if (!['rendered_text', 'rendered_dom', 'frame_dom', 'raw_html', 'response_body', 'http_body'].includes(t)) continue;
    const buf = await load(a);
    if (!buf) continue;
    const meta = a.metadata ?? {};
    const srcUrl = (meta.url as string | undefined) ?? (meta.frame_url as string | undefined) ?? baseUrl;
    const text = buf.toString('utf8');
    if (t === 'rendered_text') {
      ids.push(...extractFromText({ text, method: 'dom', displayContext: 'displayed', sourceUrl: baseUrl, artifactSha256: a.sha256 }));
      ids.push(...extractBrandClaims({ text, method: 'dom', displayContext: 'displayed', sourceUrl: baseUrl, artifactSha256: a.sha256 }));
    } else if (t === 'rendered_dom' || t === 'frame_dom' || t === 'raw_html') {
      if (t === 'rendered_dom') {
        const tpl = domTemplateHash(text);
        if (tpl) ids.push({ fieldType: 'dom_template_hash', rawValue: tpl, normalisedValue: tpl, method: 'dom', sourceUrl: baseUrl, frameUrl: null, locator: null, bbox: null, context: 'SHA-256 of the first 4000 DOM tag names', artifactSha256: a.sha256, validation: 'unvalidated', displayContext: 'resource_string', note: 'template signal only; site builders share templates' });
        const title = /<title[^>]*>([^<]{1,300})<\/title>/i.exec(text)?.[1];
        if (title) ids.push(...extractBrandClaims({ text: title, method: 'dom', displayContext: 'displayed', sourceUrl: baseUrl, artifactSha256: a.sha256 }));
      }
      const base = { displayContext: 'unknown' as const, sourceUrl: srcUrl, frameUrl: t === 'frame_dom' ? (meta.frame_url as string) : null, artifactSha256: a.sha256 };
      const attr = extractFromHtmlAttributes(text, srcUrl, base);
      ids.push(...attr.identifiers);
      attr.links.forEach((l) => links.add(l));
      attr.formActions.forEach((f) => formActions.add(f));
      // Frame/raw text is not known to be displayed; rendered main-frame text above is.
      if (t !== 'rendered_dom') ids.push(...extractFromText({ text: htmlToText(text), method: t === 'raw_html' && attempt.kind === 'http' ? 'http_body' : 'dom', ...base }));
      // Analytics/scripts embedded inline.
      ids.push(...extractFromText({ text: (text.match(/<script\b[\s\S]*?<\/script>/gi) ?? []).join('\n'), method: 'attribute', ...base, displayContext: 'resource_string' }).filter((i) => i.fieldType === 'analytics_id' || i.fieldType === 'upi_uri'));
    } else if (t === 'response_body') {
      const ct = String(meta.content_type ?? '');
      const isJson = /json/i.test(ct);
      ids.push(...extractFromText({ text, method: isJson ? 'json' : 'attribute', displayContext: 'resource_string', sourceUrl: srcUrl, artifactSha256: a.sha256 }));
    } else if (t === 'http_body') {
      ids.push(...extractFromText({ text, method: 'http_body', displayContext: 'unknown', sourceUrl: srcUrl, artifactSha256: a.sha256 }));
    }
  }

  // API endpoints observed in the page's ordinary flow (xhr/fetch).
  const events = artifacts.find((a) => a.artifact_type === 'network_events');
  if (events) {
    const buf = await load(events);
    if (buf) {
      for (const line of buf.toString('utf8').split('\n')) {
        if (!line.includes('"type":"request"')) continue;
        try {
          const e = JSON.parse(line) as { type: string; url: string; resource_type: string; method: string };
          if ((e.resource_type === 'xhr' || e.resource_type === 'fetch') && apiEndpoints.size < 200) {
            const u = new URL(e.url);
            apiEndpoints.add(`${e.method} ${u.origin}${u.pathname}`);
          }
        } catch { /* bounded, skip malformed */ }
      }
      for (const ep of apiEndpoints) {
        ids.push({ fieldType: 'api_endpoint', rawValue: ep, normalisedValue: ep, method: 'network', sourceUrl: baseUrl, frameUrl: null, locator: null, bbox: null, context: 'xhr/fetch request observed by the browser session', artifactSha256: events.sha256, validation: 'unvalidated', displayContext: 'resource_string' });
      }
    }
  }

  // QR decoding on preserved images (element crops first).
  if (policy.extraction.qr_enabled) {
    const images = artifacts
      .filter((a) => ['element_crop', 'screenshot_settled', 'screenshot_early', 'screenshot_tile'].includes(a.artifact_type))
      .sort((x, y) => (x.metadata?.kind === 'qr_candidate' ? -1 : 0) - (y.metadata?.kind === 'qr_candidate' ? -1 : 0));
    const seenPayloads = new Set<string>();
    for (const a of images.slice(0, 30)) {
      const buf = await load(a);
      if (!buf) continue;
      const qr = decodeQrFromPng(buf, policy.bounds.max_image_decode_megapixels);
      if (!qr) continue;
      qrResults.push({ source: a.relative_path, source_sha256: a.sha256, payload: qr.payload, bbox: qr.bbox, kind: a.metadata?.kind ?? a.artifact_type });
      if (seenPayloads.has(qr.payload)) continue;
      seenPayloads.add(qr.payload);
      const src = { text: qr.payload, method: 'qr' as const, displayContext: 'displayed' as const, sourceUrl: baseUrl, frameUrl: (a.metadata?.frame_url as string) ?? null, artifactSha256: a.sha256, locator: (a.metadata?.locator as string) ?? null, bbox: qr.bbox };
      ids.push({ fieldType: 'qr_payload', rawValue: qr.payload, normalisedValue: qr.payload, method: 'qr', sourceUrl: baseUrl, frameUrl: src.frameUrl, locator: src.locator, bbox: qr.bbox, context: `decoded from ${a.relative_path}`, artifactSha256: a.sha256, validation: 'unvalidated', displayContext: 'displayed' });
      ids.push(...extractFromText(src));
    }
  }

  // Selective OCR on element crops (one task at a time).
  if (policy.extraction.ocr_enabled && (await ocrAvailable())) {
    const crops = artifacts.filter((a) => a.artifact_type === 'element_crop' && ['payment_details', 'contact_block', 'qr_candidate', 'suspicious_claim'].includes(String(a.metadata?.kind)))
      .slice(0, policy.extraction.ocr_max_crops_per_attempt);
    for (const a of crops) {
      if (!(await load(a))) continue;
      try {
        const r = await ocrImage(join(dir, a.relative_path!), policy.extraction.ocr_timeout_seconds * 1000);
        ocrResults.push({ source: a.relative_path!, sha256: a.sha256, text: r.text, engine: r.engine });
        ids.push(...extractFromText({ text: r.text, method: 'ocr', displayContext: 'displayed', sourceUrl: baseUrl, frameUrl: (a.metadata?.frame_url as string) ?? null, artifactSha256: a.sha256, locator: (a.metadata?.locator as string) ?? null, fromOcr: true }));
      } catch (err) {
        failures.push(`ocr ${a.relative_path}: ${(err as Error).message}`);
      }
    }
  }

  const identifiers = dedupeIdentifiers(ids);
  // A QR code's decoded payee can differ from the payee shown in text: preserve both and flag the conflict.
  const qrPayees = new Set(identifiers.filter((i) => i.fieldType === 'upi_vpa' && i.method === 'qr').map((i) => valueKey(i)));
  const shownPayees = new Set(identifiers.filter((i) => i.fieldType === 'upi_vpa' && i.method !== 'qr' && i.displayContext === 'displayed').map((i) => valueKey(i)));
  const conflictsFor = (i: Identifier): { kind: string; detail: string }[] => {
    if (i.fieldType !== 'upi_vpa' || qrPayees.size === 0 || shownPayees.size === 0) return [];
    if (i.method === 'qr' && !shownPayees.has(valueKey(i))) return [{ kind: 'qr_vs_displayed_text', detail: `QR pays ${valueKey(i)}; page text shows ${[...shownPayees].slice(0, 3).join(', ')}` }];
    if (i.method !== 'qr' && i.displayContext === 'displayed' && !qrPayees.has(valueKey(i))) return [{ kind: 'qr_vs_displayed_text', detail: `page text shows ${valueKey(i)}; QR pays ${[...qrPayees].slice(0, 3).join(', ')}` }];
    return [];
  };
  const artifactIdBySha = new Map<string, number>();
  for (const a of artifacts) if (a.sha256 && !artifactIdBySha.has(a.sha256)) artifactIdBySha.set(a.sha256, a.id);
  const observed = new Set(identifiers.map((i) => i.fieldType));
  const hadSources = artifacts.some((a) => ['rendered_text', 'rendered_dom', 'raw_html', 'http_body'].includes(a.artifact_type) && verified.has(a.id));
  const fieldStatus = (f: FieldType): { status: string; detail: string | null } => {
    if (observed.has(f)) return { status: 'observed', detail: null };
    if (!hadSources) return { status: failures.length ? 'extraction_failed' : 'not_applicable', detail: failures.length ? failures.slice(0, 3).join('; ') : 'no text source in this attempt' };
    if (failures.length) return { status: 'extraction_failed', detail: `partial sources: ${failures.slice(0, 3).join('; ')}` };
    return { status: 'not_observed', detail: null };
  };

  // Derived outputs: separate from originals, pointing at source hashes.
  const derivedRel = `derived/${attempt.id}`;
  const tmp = join(root, 'tmp', `derived-${attempt.id}-${randomUUID().slice(0, 8)}`);
  await mkdir(tmp, { recursive: true });
  const extractionDoc = {
    attempt_id: attempt.id, created_at: new Date().toISOString(), source_attempt_dir: attempt.artifact_dir,
    note: 'Derived data. Format validity does not establish ownership, operability or criminal involvement.',
    failures, identifiers, field_status: Object.fromEntries(ALL_FIELDS.map((f) => [f, fieldStatus(f)])),
    qr: qrResults, ocr: ocrResults.map((o) => ({ source: o.source, source_sha256: o.sha256, engine: o.engine, chars: o.text.length })),
    links_discovered_not_contacted: [...links].slice(0, 500), form_actions: [...formActions], api_endpoints: [...apiEndpoints],
  };
  const files: { rel: string; data: string | Buffer; type?: string; derivedFrom?: number; meta?: Record<string, unknown> }[] = [{ rel: 'extraction.json', data: JSON.stringify(extractionDoc, null, 2) }];
  ocrResults.forEach((o, i) => files.push({ rel: `ocr-${String(i + 1).padStart(2, '0')}.txt`, data: o.text }));
  // Thumbnails for list/timeline views: derivatives that reference their original.
  for (const a of artifacts.filter((x) => ['screenshot_early', 'screenshot_settled', 'screenshot_full_or_tiles', 'screenshot_tile'].includes(x.artifact_type)).slice(0, 12)) {
    const buf = await load(a);
    if (!buf) continue;
    const th = makeThumbnail(buf, { maxSourceMegapixels: policy.bounds.max_image_decode_megapixels });
    if (!th) continue;
    files.push({ rel: `thumb-${a.id}.png`, data: th.png, type: 'thumbnail', derivedFrom: a.id,
      meta: { source_sha256: a.sha256, width: th.width, height: th.height, source_width: th.sourceWidth, source_height: th.sourceHeight, cropped_from_top: th.croppedFromTop, method: 'box-filter downscale (derivative; never evidence)' } });
  }
  const derivedManifest = files.map((f) => ({ path: f.rel, sha256: createHash('sha256').update(f.data).digest('hex'), size: Buffer.byteLength(f.data), type: f.type ?? 'derived_extraction', derivedFrom: f.derivedFrom ?? null, meta: f.meta ?? {} }));
  for (const f of files) await writeFile(join(tmp, f.rel), f.data, { mode: 0o640 });
  await writeFile(join(tmp, 'manifest.json'), JSON.stringify({ attempt_id: attempt.id, derived: derivedManifest, sources: artifacts.filter((a) => verified.has(a.id)).map((a) => ({ path: a.relative_path, sha256: a.sha256 })) }, null, 2));
  await mkdir(join(root, 'derived'), { recursive: true });
  // Replace any earlier derivation of this attempt (re-extraction is idempotent).
  const finalDir = join(root, derivedRel);
  await rename(finalDir, `${finalDir}.superseded-${Date.now()}`).catch(() => undefined);
  await rename(tmp, finalDir);

  await withTransaction(pool, async (client) => {
    await client.query('DELETE FROM identifiers WHERE attempt_id = $1', [attempt.id]);
    await client.query('DELETE FROM identifier_field_status WHERE attempt_id = $1', [attempt.id]);
    await client.query(`DELETE FROM domain_edges WHERE attempt_id = $1 AND edge_type IN ('link_discovered', 'form_action')`, [attempt.id]);
    await client.query('DELETE FROM artifacts WHERE attempt_id = $1 AND is_derivative', [attempt.id]);
    for (const i of identifiers) {
      await client.query(
        `INSERT INTO identifiers (attempt_id, job_id, target_id, field_type, raw_value, normalised_value, method, source_url, frame_url, locator, bbox, context, artifact_sha256,
            validation_state, display_context, observed_at, value_key, extractor_version, confidence, source_artifact_id, conflicts, signal_only)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,(SELECT started_at FROM attempts WHERE id = $1),$16,$17,$18,$19,$20,$21)`,
        [attempt.id, attempt.job_id, attempt.target_id, i.fieldType, i.rawValue, i.normalisedValue, i.method, i.sourceUrl, i.frameUrl, i.locator, i.bbox,
         i.note ? `${i.context} [${i.note}]` : i.context, i.artifactSha256, i.validation, i.displayContext,
         valueKey(i), EXTRACTOR_VERSION, confidenceFor(i), i.artifactSha256 ? artifactIdBySha.get(i.artifactSha256) ?? null : null,
         JSON.stringify(conflictsFor(i)), SIGNAL_ONLY_FIELDS.has(i.fieldType)],
      );
    }
    for (const f of ALL_FIELDS) {
      const s = fieldStatus(f);
      await client.query('INSERT INTO identifier_field_status (attempt_id, field_type, status, detail) VALUES ($1,$2,$3,$4)', [attempt.id, f, s.status, s.detail]);
    }
    const seenHosts = new Set<string>();
    for (const l of links) {
      try {
        const h = new URL(l).host;
        if (seenHosts.has(h)) continue;
        seenHosts.add(h);
      } catch { continue; }
      await client.query(`INSERT INTO domain_edges (attempt_id, edge_type, from_url, to_url, from_host, to_host, contacted) VALUES ($1,'link_discovered',$2,$3,$4,$5,false)`,
        [attempt.id, baseUrl, l, hostOf(baseUrl), hostOf(l)]);
    }
    for (const f of formActions) {
      await client.query(`INSERT INTO domain_edges (attempt_id, edge_type, from_url, to_url, from_host, to_host, contacted) VALUES ($1,'form_action',$2,$3,$4,$5,false)`,
        [attempt.id, baseUrl, f, hostOf(baseUrl), hostOf(f)]);
    }
    for (const d of derivedManifest) {
      await client.query(
        `INSERT INTO artifacts (attempt_id, artifact_type, relative_path, size_bytes, sha256, creation_method, completeness, is_derivative, derived_from, metadata, verification_state, last_verified_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, $9, 'verified_at_commit', now())`,
        [attempt.id, d.type, `${derivedRel}/${d.path}`, d.size, d.sha256, d.type === 'thumbnail' ? 'collector thumbnail (derivative)' : `collector extraction pipeline ${EXTRACTOR_VERSION}`,
         d.type === 'thumbnail' ? 'complete' : failures.length ? 'partial' : 'complete', d.derivedFrom, { root_relative: true, ...d.meta }],
      );
    }
    await client.query(`UPDATE attempts SET extraction_state = $2 WHERE id = $1`, [attempt.id, failures.length && !hadSources ? 'failed' : 'done']);
    await audit(client, 'extraction', 'extraction_done', { identifiers: identifiers.length, failures: failures.slice(0, 10), qr: qrResults.length, ocr: ocrResults.length }, { jobId: attempt.job_id, attemptId: attempt.id });
  });

  // Explainable triage aid, recomputed for every extraction (append-only versions).
  await recordRiskAssessment(pool, policy.governance.risk_policy_version, attempt.id).catch((err: Error) => logger.warn({ attempt: attempt.id, err: err.message }, 'risk assessment failed'));

  // Only pages whose content was actually reached are worth expanding; links on a
  // challenge, block or error page would spend budget on the same refusal.
  const contentReached = attempt.outcome === 'CONTENT_CAPTURED' || attempt.outcome === 'CONTENT_INCOMPLETE';
  if (attempt.kind === 'browser' && attempt.parent_job_id === null && attempt.profile === 'browser_evidence' && contentReached && links.size > 0) {
    await spawnChildJobs(pool, policy, attempt, [...links]);
  }
}

function hostOf(u: string | null): string | null {
  if (!u) return null;
  try {
    return new URL(u).host;
  } catch {
    return null;
  }
}

/** Up to child_pages_max relevant same-site pages per target window, as bounded child jobs (§6). */
async function spawnChildJobs(pool: Pool, policy: Policy, attempt: AttemptRow, links: string[]): Promise<void> {
  const max = Math.min(Number(attempt.scope.child_pages_max ?? policy.limits.child_pages_per_target_max), policy.limits.child_pages_per_target_max);
  if (max <= 0) return;
  const targetNoFrag = attempt.target_url.split('#')[0];
  // Same normalisation and rejection rules as the importer (userinfo, schemes, ports, PSL grouping).
  const candidates: TargetCandidate[] = [];
  const seen = new Set<string>();
  for (const l of links) {
    if (l.split('#')[0] === targetNoFrag) continue;
    const parsed = parseTargetInput(l, policy.scope, 'url');
    if (!parsed.ok) continue;
    const c = parsed.candidates[0]!;
    if (c.registrableDomain !== attempt.registrable_domain || seen.has(c.dedupKey)) continue;
    let pathAndQuery: string;
    try {
      const u = new URL(c.url);
      pathAndQuery = u.pathname + u.search;
    } catch {
      continue;
    }
    if (!RELEVANT_CHILD_LINK.test(pathAndQuery)) continue;
    seen.add(c.dedupKey);
    candidates.push(c);
  }
  if (candidates.length === 0) return;
  await withTransaction(pool, async (client) => {
    // Serialise child creation per parent so concurrent extractions cannot exceed the cap.
    await client.query('SELECT id FROM jobs WHERE id = $1 FOR UPDATE', [attempt.job_id]);
    const existing = await client.query<{ n: number }>(`SELECT count(*)::int AS n FROM jobs WHERE parent_job_id = $1 AND NOT (scope ? 'scheme_fallback_of_job')`, [attempt.job_id]);
    let room = max - (existing.rows[0]?.n ?? 0);
    for (const c of candidates) {
      if (room <= 0) break;
      const t = await upsertTarget(client, c);
      const dup = await client.query('SELECT 1 FROM jobs WHERE parent_job_id = $1 AND target_id = $2', [attempt.job_id, t.id]);
      if (dup.rowCount) continue;
      const child = await client.query<{ id: number }>(
        `INSERT INTO jobs (target_id, parent_job_id, profile, window_key, registrable_domain, priority, urgent, required_artifacts, capture_variant,
            scope, allowed_interactions, retention_class, case_ref, deadline, stage)
         SELECT $2, j.id, j.profile, j.window_key, j.registrable_domain, j.priority - 1, false, j.required_artifacts, j.capture_variant,
            jsonb_build_object('child_page', true, 'discovered_from_attempt', $3::text, 'child_pages_max', 0), j.allowed_interactions,
            j.retention_class, j.case_ref, j.deadline, 'browser_primary'
           FROM jobs j WHERE j.id = $1 RETURNING id`,
        [attempt.job_id, t.id, attempt.id],
      );
      await client.query('INSERT INTO job_sources (job_id, source_record_id) SELECT $2, source_record_id FROM job_sources WHERE job_id = $1 ON CONFLICT DO NOTHING', [attempt.job_id, child.rows[0]!.id]);
      await audit(client, 'extraction', 'child_job_created', { parent_job_id: attempt.job_id, url: c.url }, { jobId: child.rows[0]!.id, attemptId: attempt.id });
      room -= 1;
    }
  });
  logger.info({ job: attempt.job_id }, 'child page jobs evaluated');
}
