/**
 * Evidence packages (checklist §1 "seal the final manifest without
 * self-referential hashing"; §6 export; blueprint v4 §23.3, §24.4).
 *
 * A package copies original attempt files (unchanged bytes) plus a fresh
 * verification report into packages/<id>/, then writes package-index.json
 * listing every file's SHA-256 and every attempt manifest's ledger hash. The
 * index hash is recorded in the database and the custody chain, and the whole
 * directory is also written as one ustar archive for hand-off. Exported
 * packages stay verifiable after local cleanup: `cli.js package verify <dir>`
 * needs only the package itself.
 */
import { createHash, randomUUID } from 'node:crypto';
import { constants, createReadStream, createWriteStream } from 'node:fs';
import { copyFile, mkdir, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import type { AttemptManifest } from '../acquisition/contract.js';
import { audit, type Pool } from '../db/pool.js';
import { assertSafeRelative, sha256File } from '../storage/artifactStore.js';
import { canonicalJson } from './canonical.js';
import { formatIst } from './time.js';
import { runVerification } from './verify.js';

export const PACKAGE_MAX_BYTES = 2 * 1024 * 1024 * 1024;

export interface PackageIndexFile {
  path: string;
  sha256: string;
  size_bytes: number;
  role: 'original' | 'manifest' | 'derivative' | 'report' | 'readme';
  attempt_id: string | null;
}

export interface PackageIndex {
  format: 'cyber-web-collector/evidence-package@1';
  package_id: string;
  created_at_utc: string;
  created_at_ist: string;
  created_by: string;
  purpose: string;
  scope: { kind: 'job' | 'case' | 'attempts'; id: string };
  attempts: { attempt_id: string; job_id: number; manifest_sha256_ledger: string | null; manifest_path: string; outcome: string | null; requested_url: string | null; final_url: string | null }[];
  files: PackageIndexFile[];
  withheld: { attempt_id: string; path: string; sha256: string | null; reason: string }[];
  verification: { run_id: string; result: string; report_path: string; report_sha256: string };
  statement: string;
}

async function attemptIds(pool: Pool, kind: 'job' | 'case' | 'attempts', id: string): Promise<string[]> {
  if (kind === 'attempts') return id.split(',').map((s) => s.trim()).filter(Boolean);
  if (kind === 'job') return (await pool.query<{ id: string }>('SELECT id FROM attempts WHERE job_id = $1 AND artifact_dir IS NOT NULL ORDER BY attempt_no', [Number(id)])).rows.map((r) => r.id);
  return (await pool.query<{ id: string }>(
    `SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE a.artifact_dir IS NOT NULL AND (j.case_ref = $1 OR EXISTS (
       SELECT 1 FROM job_sources js JOIN source_records s ON s.id = js.source_record_id WHERE js.job_id = j.id AND s.case_ref = $1))
     ORDER BY a.started_at`, [id],
  )).rows.map((r) => r.id);
}

async function copyVerified(src: string, dst: string, expected: string): Promise<{ sha256: string; size: number }> {
  await mkdir(dirname(dst), { recursive: true });
  await copyFile(src, dst, constants.COPYFILE_FICLONE | constants.COPYFILE_EXCL);
  const got = await sha256File(dst);
  if (got.sha256 !== expected) throw new Error(`copy of ${src} does not match its recorded hash; package aborted`);
  return got;
}

export async function createEvidencePackage(pool: Pool, root: string, o: {
  kind: 'job' | 'case' | 'attempts'; id: string; purpose: string; actor: string; includeRestricted?: boolean;
  actorKind?: 'user' | 'operator'; requestId?: string | null; caseRef?: string | null;
}): Promise<{ package_id: string; relative_path: string; archive_path: string; index_sha256: string; archive_sha256: string; file_count: number; total_bytes: number; verification: PackageIndex['verification'] }> {
  const ids = await attemptIds(pool, o.kind, o.id);
  if (ids.length === 0) throw new Error('no committed attempts in scope; nothing to package');
  const packageId = randomUUID();
  const rel = `packages/${packageId}`;
  const tmp = join(root, 'tmp', `package-${packageId}`);
  await mkdir(tmp, { recursive: true, mode: 0o750 });

  // A fresh verification run is part of every package; a failing run aborts packaging.
  const verification = await runVerification(pool, root, o.kind === 'attempts' ? 'attempt' : o.kind, o.kind === 'attempts' ? ids.join(',') : o.id, o.actor,
    { actorKind: o.actorKind ?? 'operator', requestId: o.requestId ?? null, caseRef: o.caseRef ?? null });
  if (verification.result !== 'pass') throw new Error(`verification failed; package not created (report ${verification.report_path})`);

  const files: PackageIndexFile[] = [];
  const withheld: PackageIndex['withheld'] = [];
  const attempts: PackageIndex['attempts'] = [];
  let total = 0;
  for (const id of ids) {
    const a = (await pool.query<{ id: string; job_id: number; artifact_dir: string; manifest_sha256: string | null; outcome: string | null }>(
      'SELECT id, job_id, artifact_dir, manifest_sha256, outcome FROM attempts WHERE id = $1 AND artifact_dir IS NOT NULL', [id],
    )).rows[0];
    if (!a) throw new Error(`attempt ${id} has no committed directory`);
    assertSafeRelative(a.artifact_dir);
    const srcDir = join(root, a.artifact_dir);
    const manifestText = await readFile(join(srcDir, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(manifestText) as AttemptManifest;
    const base = `attempts/${a.id}`;
    const mCopy = await copyVerified(join(srcDir, 'manifest.json'), join(tmp, base, 'manifest.json'), a.manifest_sha256 ?? createHash('sha256').update(manifestText).digest('hex'));
    files.push({ path: `${base}/manifest.json`, sha256: mCopy.sha256, size_bytes: mCopy.size, role: 'manifest', attempt_id: a.id });
    total += mCopy.size;
    attempts.push({ attempt_id: a.id, job_id: a.job_id, manifest_sha256_ledger: a.manifest_sha256, manifest_path: `${base}/manifest.json`, outcome: a.outcome, requested_url: manifest.requestedUrl ?? null, final_url: manifest.finalUrl ?? null });
    for (const e of manifest.artifacts) {
      if (!e.path || !e.sha256) continue;
      if (e.restricted && !o.includeRestricted) {
        withheld.push({ attempt_id: a.id, path: e.path, sha256: e.sha256, reason: 'restricted artifact (cookies/tokens/session data) withheld from ordinary packages' });
        continue;
      }
      if (total + (e.sizeBytes ?? 0) > PACKAGE_MAX_BYTES) throw new Error('package exceeds the 2 GiB limit; narrow the scope');
      const c = await copyVerified(join(srcDir, e.path), join(tmp, base, e.path), e.sha256);
      files.push({ path: `${base}/${e.path}`, sha256: c.sha256, size_bytes: c.size, role: 'original', attempt_id: a.id });
      total += c.size;
    }
  }
  const report = await copyVerified(join(root, verification.report_path), join(tmp, 'verification-report.json'), verification.report_sha256);
  files.push({ path: 'verification-report.json', sha256: report.sha256, size_bytes: report.size, role: 'report', attempt_id: null });
  const createdAt = new Date().toISOString();
  const readme = [
    'Evidence package produced by cyber-web-collector.',
    `Package id: ${packageId}`,
    `Created: ${createdAt} (UTC) / ${formatIst(createdAt)}`,
    `Purpose: ${o.purpose}`,
    '',
    'package-index.json lists the SHA-256 of every file in this package and the ledger hash of each attempt manifest.',
    'The SHA-256 of package-index.json itself is recorded in the collector ledger and custody chain, not inside the index.',
    'Original files are byte-for-byte copies of the immutable attempt directories. Screenshots are observations of one',
    'browser session at the recorded time; they do not establish domain ownership, what other visitors saw, or admissibility.',
    'To verify offline: node dist/cli.js package verify <this directory>',
    '',
  ].join('\n');
  await writeFile(join(tmp, 'README.txt'), readme, { mode: 0o640 });
  files.push({ path: 'README.txt', sha256: createHash('sha256').update(readme).digest('hex'), size_bytes: Buffer.byteLength(readme), role: 'readme', attempt_id: null });

  const index: PackageIndex = {
    format: 'cyber-web-collector/evidence-package@1', package_id: packageId, created_at_utc: createdAt, created_at_ist: formatIst(createdAt),
    created_by: o.actor, purpose: o.purpose, scope: { kind: o.kind, id: o.id }, attempts, files, withheld,
    verification: { run_id: verification.run_id, result: verification.result, report_path: 'verification-report.json', report_sha256: verification.report_sha256 },
    statement: 'Integrity data supports detection of later modification. It does not by itself establish authenticity, lawful acquisition or admissibility; a BSA 2023 Section 63 certificate, where required, is a separate human-signed document.',
  };
  const indexText = `${JSON.stringify(JSON.parse(canonicalJson(index)), null, 2)}\n`;
  await writeFile(join(tmp, 'package-index.json'), indexText, { mode: 0o640 });
  const indexSha = createHash('sha256').update(indexText).digest('hex');

  await mkdir(join(root, 'packages'), { recursive: true });
  await rename(tmp, join(root, rel));
  const archiveRel = `packages/${packageId}.tar`;
  await writeTar(join(root, rel), join(root, archiveRel), `evidence-package-${packageId}`);
  const archive = await sha256File(join(root, archiveRel));

  await pool.query(
    `INSERT INTO evidence_packages (id, case_ref, purpose, scope, created_by, relative_path, index_sha256, file_count, total_bytes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [packageId, o.caseRef ?? (o.kind === 'case' ? o.id : null), o.purpose, { kind: o.kind, id: o.id, archive: archiveRel, archive_sha256: archive.sha256, withheld: withheld.length }, o.actor, rel, indexSha, files.length, total],
  );
  await audit(pool, o.actor, 'evidence_package_created', { package_id: packageId, index_sha256: indexSha, archive_sha256: archive.sha256, files: files.length, total_bytes: total, withheld: withheld.length, purpose: o.purpose },
    { actorKind: o.actorKind ?? 'operator', objectType: 'evidence_package', objectId: packageId, caseRef: o.caseRef ?? (o.kind === 'case' ? o.id : null), requestId: o.requestId ?? null, outcome: 'created' });
  return { package_id: packageId, relative_path: rel, archive_path: archiveRel, index_sha256: indexSha, archive_sha256: archive.sha256, file_count: files.length, total_bytes: total, verification: index.verification };
}

/** Offline verification of a package directory against its own index (and optionally the ledger's index hash). */
export async function verifyPackageDir(dir: string, expectedIndexSha?: string): Promise<{ ok: boolean; index_sha256: string; index_matches_expected: boolean | null; problems: string[]; files_checked: number }> {
  const indexText = await readFile(join(dir, 'package-index.json'), 'utf8');
  const indexSha = createHash('sha256').update(indexText).digest('hex');
  const index = JSON.parse(indexText) as PackageIndex;
  const problems: string[] = [];
  const listed = new Set<string>(['package-index.json']);
  for (const f of index.files) {
    listed.add(f.path);
    if (f.path.split('/').some((p) => p === '..' || p === '') || f.path.startsWith('/')) {
      problems.push(`unsafe path in index: ${f.path}`);
      continue;
    }
    const got = await sha256File(join(dir, f.path)).catch(() => null);
    if (!got) problems.push(`missing: ${f.path}`);
    else if (got.sha256 !== f.sha256) problems.push(`modified: ${f.path}`);
  }
  // Attempt manifests must match the hashes the ledger recorded at commit time.
  for (const a of index.attempts) {
    const f = index.files.find((x) => x.path === a.manifest_path);
    if (a.manifest_sha256_ledger && f && f.sha256 !== a.manifest_sha256_ledger) problems.push(`manifest for attempt ${a.attempt_id} differs from the ledger hash`);
  }
  // Files present but not listed are reported: nothing may be slipped into a package.
  async function walk(d: string): Promise<void> {
    for (const name of await readdir(d)) {
      const abs = join(d, name);
      const st = await stat(abs);
      if (st.isDirectory()) await walk(abs);
      else {
        const relPath = relative(dir, abs).split(sep).join('/');
        if (!listed.has(relPath)) problems.push(`unlisted file: ${relPath}`);
      }
    }
  }
  await walk(dir);
  const matches = expectedIndexSha ? expectedIndexSha === indexSha : null;
  if (matches === false) problems.push('package-index.json does not match the index hash recorded in the ledger');
  return { ok: problems.length === 0, index_sha256: indexSha, index_matches_expected: matches, problems, files_checked: index.files.length };
}

// --- Minimal POSIX ustar writer (regular files and directories only). ---
function tarHeader(name: string, size: number, mode: number, type: '0' | '5', mtime: number): Buffer {
  const h = Buffer.alloc(512, 0);
  let prefix = '';
  let n = name;
  if (Buffer.byteLength(n) > 100) {
    // Split at a '/' so the name part fits 100 bytes and the prefix fits 155 bytes.
    let split = -1;
    for (let i = n.indexOf('/'); i > 0; i = n.indexOf('/', i + 1)) {
      if (Buffer.byteLength(n.slice(0, i)) <= 155 && Buffer.byteLength(n.slice(i + 1)) <= 100) {
        split = i;
        break;
      }
    }
    if (split < 0) throw new Error(`path too long for ustar: ${name}`);
    prefix = n.slice(0, split);
    n = n.slice(split + 1);
  }
  h.write(n, 0, 100, 'utf8');
  h.write(`${mode.toString(8).padStart(7, '0')}\0`, 100, 8, 'ascii');
  h.write('0000000\0', 108, 8, 'ascii');
  h.write('0000000\0', 116, 8, 'ascii');
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii');
  h.write(`${Math.floor(mtime / 1000).toString(8).padStart(11, '0')}\0`, 136, 12, 'ascii');
  h.write('        ', 148, 8, 'ascii');
  h.write(type, 156, 1, 'ascii');
  h.write('ustar\0', 257, 6, 'ascii');
  h.write('00', 263, 2, 'ascii');
  h.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return h;
}

export async function writeTar(srcDir: string, outFile: string, topName: string): Promise<void> {
  const entries: { rel: string; abs: string; dir: boolean; size: number }[] = [];
  async function walk(d: string): Promise<void> {
    for (const name of (await readdir(d)).sort()) {
      const abs = join(d, name);
      const st = await stat(abs);
      const relPath = relative(srcDir, abs).split(sep).join('/');
      if (st.isDirectory()) {
        entries.push({ rel: relPath, abs, dir: true, size: 0 });
        await walk(abs);
      } else if (st.isFile()) entries.push({ rel: relPath, abs, dir: false, size: st.size });
    }
  }
  await walk(srcDir);
  const tmpOut = `${outFile}.partial`;
  const out = createWriteStream(tmpOut, { flags: 'wx', mode: 0o640 });
  const now = Date.now();
  const write = (b: Buffer) => new Promise<void>((res, rej) => out.write(b, (e) => (e ? rej(e) : res())));
  await write(tarHeader(`${topName}/`, 0, 0o750, '5', now));
  for (const e of entries) {
    if (e.dir) {
      await write(tarHeader(`${topName}/${e.rel}/`, 0, 0o750, '5', now));
      continue;
    }
    await write(tarHeader(`${topName}/${e.rel}`, e.size, 0o640, '0', now));
    for await (const chunk of createReadStream(e.abs)) await write(chunk as Buffer);
    const pad = (512 - (e.size % 512)) % 512;
    if (pad) await write(Buffer.alloc(pad, 0));
  }
  await write(Buffer.alloc(1024, 0));
  await new Promise<void>((res, rej) => out.end((e?: Error | null) => (e ? rej(e) : res())));
  await rename(tmpOut, outFile);
}
