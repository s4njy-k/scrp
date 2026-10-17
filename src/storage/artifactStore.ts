/**
 * Immutable attempt directories (blueprint §12, §15).
 *
 * Write path for one attempt:
 *   1. All files go to <root>/tmp/<attempt-id>/ (same filesystem as the final location).
 *   2. Writes are awaited, actual saved bytes are hashed (SHA-256) and fsynced.
 *   3. manifest.json is written and fsynced.
 *   4. The directory is atomically renamed to <root>/captures/YYYY/MM/DD/<attempt-id>/
 *      and the parent directory fsynced.
 *   5. Only then is the manifest/path/status committed to PostgreSQL.
 *
 * The filesystem and database are not one transaction; the reconciler handles
 * orphan final directories and stale pending records after a crash.
 * Untrusted URL text is never used to build a path: names come from this module.
 */
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream, mkdirSync, type WriteStream } from 'node:fs';
import { mkdir, open, readdir, rename, stat, statfs, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import type { ArtifactType, AttemptManifest, Completeness, ManifestEntry } from '../acquisition/contract.js';

export const ATTEMPT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SAFE_REL_RE = /^[a-z0-9][a-z0-9_.-]*(\/[a-z0-9][a-z0-9_.-]*)*$/;

export function artifactRoot(): string {
  const root = process.env.ARTIFACT_ROOT;
  if (!root) throw new Error('ARTIFACT_ROOT is not set');
  return root;
}

export function assertSafeRelative(rel: string): void {
  if (!SAFE_REL_RE.test(rel) || rel.split('/').some((p) => p === '..' || p === '.')) {
    throw new Error(`unsafe artifact path: ${JSON.stringify(rel)}`);
  }
}

async function fsyncPath(path: string): Promise<void> {
  const fh = await open(path, 'r');
  try {
    await fh.sync();
  } finally {
    await fh.close();
  }
}

export async function sha256File(path: string): Promise<{ sha256: string; size: number }> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    let size = 0;
    createReadStream(path)
      .on('data', (chunk: string | Buffer) => {
        size += chunk.length;
        hash.update(chunk);
      })
      .on('error', reject)
      .on('end', () => resolve({ sha256: hash.digest('hex'), size }));
  });
}

export type ManifestBase = Omit<AttemptManifest, 'artifacts' | 'manifestVersion'>;

export interface PendingEntry {
  type: ArtifactType;
  path: string | null;
  observedStart: string | null;
  observedEnd: string | null;
  creationMethod: string;
  completeness: Completeness;
  limitations: string[];
  restricted?: boolean;
  isDerivative?: boolean;
  derivedFrom?: string | null;
  error?: string | null;
  metadata?: Record<string, unknown>;
}

export interface BoundedStream {
  write(line: string): boolean;
  readonly truncated: boolean;
  readonly bytes: number;
  end(): Promise<void>;
}

export class AttemptWriter {
  readonly tmpDir: string;
  private readonly entries: PendingEntry[] = [];
  private readonly pending = new Set<Promise<unknown>>();
  private bytesReserved = 0;
  private readonly streams: { stream: WriteStream; done: Promise<void> }[] = [];
  readonly budgetEvents: string[] = [];

  constructor(
    readonly root: string,
    readonly attemptId: string,
    readonly attemptBudgetBytes: number,
  ) {
    if (!ATTEMPT_ID_RE.test(attemptId)) throw new Error('attempt id must be a UUID');
    this.tmpDir = join(root, 'tmp', attemptId);
  }

  async init(): Promise<void> {
    await mkdir(this.tmpDir, { recursive: true, mode: 0o750 });
  }

  get bytesUsed(): number {
    return this.bytesReserved;
  }

  remainingBytes(): number {
    return Math.max(0, this.attemptBudgetBytes - this.bytesReserved);
  }

  /** Reserve budget for `size` bytes; false (and a recorded budget event) when it does not fit. */
  reserve(size: number, what: string): boolean {
    if (this.bytesReserved + size > this.attemptBudgetBytes) {
      this.budgetEvents.push(`attempt_budget_exceeded:${what}:${size}`);
      return false;
    }
    this.bytesReserved += size;
    return true;
  }

  /** Write a whole file. Returns false when the attempt byte budget refuses it (entry recorded as omitted). */
  async writeArtifact(rel: string, data: Buffer | string, entry: Omit<PendingEntry, 'path'>): Promise<boolean> {
    assertSafeRelative(rel);
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    if (!this.reserve(buf.length, rel)) {
      this.entries.push({ ...entry, path: null, completeness: 'omitted', error: 'attempt_artifact_budget_exceeded', limitations: [...entry.limitations, `size ${buf.length} bytes exceeds remaining attempt budget`] });
      return false;
    }
    const target = join(this.tmpDir, rel);
    const task = (async () => {
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, buf, { mode: entry.restricted ? 0o600 : 0o640 });
    })();
    this.track(task);
    await task;
    this.entries.push({ ...entry, path: rel });
    return true;
  }

  /** Register an artifact whose file is produced by another component (e.g. Playwright HAR). */
  registerExternalFile(rel: string, entry: Omit<PendingEntry, 'path'>): string {
    assertSafeRelative(rel);
    this.entries.push({ ...entry, path: rel });
    return join(this.tmpDir, rel);
  }

  pathFor(rel: string): string {
    assertSafeRelative(rel);
    return join(this.tmpDir, rel);
  }

  /** Record an artifact that failed or was omitted. No file is invented. */
  recordMissing(entry: Omit<PendingEntry, 'path'>): void {
    this.entries.push({ ...entry, path: null });
  }

  /** Append-only JSONL stream bounded by bytes; truncation is recorded, never silent. */
  openJsonl(rel: string, maxBytes: number): BoundedStream {
    assertSafeRelative(rel);
    mkdirSync(dirname(join(this.tmpDir, rel)), { recursive: true });
    const stream = createWriteStream(join(this.tmpDir, rel), { flags: 'wx', mode: 0o640 });
    const done = new Promise<void>((resolve, reject) => {
      stream.on('finish', () => resolve());
      stream.on('error', reject);
    });
    this.streams.push({ stream, done });
    let bytes = 0;
    let truncated = false;
    const self = this;
    return {
      write(line: string): boolean {
        if (truncated) return false;
        const data = line.endsWith('\n') ? line : `${line}\n`;
        const len = Buffer.byteLength(data);
        if (bytes + len > maxBytes || !self.reserve(len, rel)) {
          truncated = true;
          stream.write(`${JSON.stringify({ type: 'recorder_truncated', at: new Date().toISOString(), reason: 'byte_limit' })}\n`);
          return false;
        }
        bytes += len;
        stream.write(data);
        return true;
      },
      get truncated() {
        return truncated;
      },
      get bytes() {
        return bytes;
      },
      end(): Promise<void> {
        if (!stream.writableEnded) stream.end();
        return done;
      },
    };
  }

  track<T>(p: Promise<T>): Promise<T> {
    this.pending.add(p);
    void p.finally(() => this.pending.delete(p)).catch(() => undefined);
    return p;
  }

  /** Await outstanding writes with a deadline; returns the number still pending at the deadline. */
  async settle(deadlineMs: number): Promise<number> {
    const all = Promise.allSettled([...this.pending, ...this.streams.map((s) => s.done)]);
    for (const s of this.streams) if (!s.stream.writableEnded) s.stream.end();
    const timeout = new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), Math.max(0, deadlineMs)).unref());
    const res = await Promise.race([all.then(() => 'ok' as const), timeout]);
    return res === 'timeout' ? this.pending.size : 0;
  }

  /**
   * Hash every saved file (actual bytes on disk), fsync, write the manifest,
   * atomically rename into captures/ and fsync the parent. Entries whose file
   * is missing on disk are downgraded to failed — never reported as present.
   */
  async finalise(
    base: ManifestBase | ((artifacts: ManifestEntry[]) => ManifestBase),
    location: 'captures' | 'incomplete' = 'captures',
  ): Promise<{
    relativeDir: string; manifest: AttemptManifest; manifestSha256: string; totalBytes: number;
  }> {
    const artifacts: ManifestEntry[] = [];
    let totalBytes = 0;
    for (const e of this.entries) {
      if (!e.path) {
        artifacts.push({ ...e, path: null, sizeBytes: null, sha256: null });
        continue;
      }
      const abs = join(this.tmpDir, e.path);
      try {
        const st = await stat(abs);
        if (!st.isFile()) throw new Error('not a regular file');
        await fsyncPath(abs);
        const { sha256, size } = await sha256File(abs);
        totalBytes += size;
        const completeness: Completeness = size === 0 && e.completeness === 'complete' ? 'partial' : e.completeness;
        artifacts.push({ ...e, sizeBytes: size, sha256, completeness, limitations: size === 0 ? [...e.limitations, 'zero-byte file'] : e.limitations });
      } catch (err) {
        artifacts.push({ ...e, path: null, sizeBytes: null, sha256: null, completeness: 'failed', error: `file missing at finalisation: ${(err as Error).message}` });
      }
    }
    const resolvedBase = typeof base === 'function' ? base(artifacts) : base;
    const manifest: AttemptManifest = { manifestVersion: 1, ...resolvedBase, artifacts };
    const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
    const manifestPath = join(this.tmpDir, 'manifest.json');
    await writeFile(manifestPath, manifestText, { mode: 0o640 });
    await fsyncPath(manifestPath);
    const manifestSha256 = createHash('sha256').update(manifestText).digest('hex');
    await fsyncPath(this.tmpDir);

    const d = new Date(resolvedBase.startedAt);
    const datePart = `${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(d.getUTCDate()).padStart(2, '0')}`;
    const relativeDir = `${location}/${datePart}/${this.attemptId}`;
    const finalDir = join(this.root, relativeDir);
    await mkdir(dirname(finalDir), { recursive: true, mode: 0o750 });
    await rename(this.tmpDir, finalDir);
    await fsyncPath(dirname(finalDir));
    return { relativeDir, manifest, manifestSha256, totalBytes: totalBytes + Buffer.byteLength(manifestText) };
  }
}

/** Locate a committed or incomplete attempt directory by id without trusting any DB path. */
export async function findAttemptDirs(root: string, location: 'captures' | 'incomplete'): Promise<{ attemptId: string; relativeDir: string }[]> {
  const base = join(root, location);
  const out: { attemptId: string; relativeDir: string }[] = [];
  async function walk(dir: string, depth: number): Promise<void> {
    let names: string[];
    try {
      names = await readdir(dir);
    } catch {
      return;
    }
    for (const name of names) {
      const abs = join(dir, name);
      if (depth === 3) {
        if (ATTEMPT_ID_RE.test(name)) out.push({ attemptId: name, relativeDir: relative(root, abs).split(sep).join('/') });
      } else if (/^\d{2,4}$/.test(name)) {
        await walk(abs, depth + 1);
      }
    }
  }
  await walk(base, 0);
  return out;
}

export async function diskFreeBytes(path: string): Promise<{ free: number; total: number }> {
  const s = await statfs(path);
  return { free: s.bavail * s.bsize, total: s.blocks * s.bsize };
}
