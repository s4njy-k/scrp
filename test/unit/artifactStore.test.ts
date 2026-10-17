import { createHash, randomUUID } from 'node:crypto';
import { readFile, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AttemptWriter, assertSafeRelative } from '../../src/storage/artifactStore.js';
import { tempRoot } from '../helpers.js';

let cleanup: (() => Promise<void>) | null = null;
afterEach(async () => { await cleanup?.(); cleanup = null; });

const base = (attemptId: string) => ({
  attemptId, jobId: 1, attemptNo: 1, kind: 'browser' as const, engine: 'chromium', adapter: 'playwright', vantage: 'test',
  requestedUrl: 'https://x.example/', finalUrl: null, startedAt: new Date().toISOString(), endedAt: new Date().toISOString(),
  outcome: 'CONTENT_CAPTURED' as const, classification: 'content_captured', requiredArtifacts: [], requiredSatisfied: true, missingRequired: [], limitations: [],
});

describe('immutable attempt directories (§12, §15)', () => {
  it('hashes saved bytes, writes a manifest and atomically renames into captures/', async () => {
    const t = await tempRoot();
    cleanup = t.cleanup;
    const id = randomUUID();
    const w = new AttemptWriter(t.root, id, 1024 * 1024);
    await w.init();
    await w.writeArtifact('dom/rendered.txt', 'hello', { type: 'rendered_text', observedStart: null, observedEnd: null, creationMethod: 't', completeness: 'complete', limitations: [] });
    w.recordMissing({ type: 'har', observedStart: null, observedEnd: null, creationMethod: 't', completeness: 'failed', limitations: [], error: 'flush timeout' });
    const fin = await w.finalise(base(id));
    expect(fin.relativeDir).toMatch(new RegExp(`^captures/\\d{4}/\\d{2}/\\d{2}/${id}$`));
    const manifest = JSON.parse(await readFile(join(t.root, fin.relativeDir, 'manifest.json'), 'utf8'));
    const text = manifest.artifacts.find((a: { type: string }) => a.type === 'rendered_text');
    expect(text.sha256).toBe(createHash('sha256').update('hello').digest('hex'));
    const har = manifest.artifacts.find((a: { type: string }) => a.type === 'har');
    expect(har).toMatchObject({ path: null, sha256: null, completeness: 'failed', error: 'flush timeout' });
    await expect(stat(join(t.root, 'tmp', id))).rejects.toThrow();
  });

  it('downgrades an entry whose file vanished instead of reporting it present', async () => {
    const t = await tempRoot();
    cleanup = t.cleanup;
    const id = randomUUID();
    const w = new AttemptWriter(t.root, id, 1024 * 1024);
    await w.init();
    await w.writeArtifact('a.txt', 'x', { type: 'rendered_text', observedStart: null, observedEnd: null, creationMethod: 't', completeness: 'complete', limitations: [] });
    await unlink(join(w.tmpDir, 'a.txt'));
    const fin = await w.finalise(base(id));
    expect(fin.manifest.artifacts[0]).toMatchObject({ path: null, completeness: 'failed' });
  });

  it('enforces the attempt byte budget and records the omission', async () => {
    const t = await tempRoot();
    cleanup = t.cleanup;
    const id = randomUUID();
    const w = new AttemptWriter(t.root, id, 10);
    await w.init();
    const ok = await w.writeArtifact('big.bin', Buffer.alloc(100), { type: 'response_body', observedStart: null, observedEnd: null, creationMethod: 't', completeness: 'complete', limitations: [] });
    expect(ok).toBe(false);
    const fin = await w.finalise(base(id));
    expect(fin.manifest.artifacts[0]).toMatchObject({ completeness: 'omitted', error: 'attempt_artifact_budget_exceeded' });
    expect(w.budgetEvents[0]).toMatch(/attempt_budget_exceeded/);
  });

  it('refuses writes after finalisation so late writers cannot recreate the moved directory', async () => {
    const t = await tempRoot();
    cleanup = t.cleanup;
    const id = randomUUID();
    const w = new AttemptWriter(t.root, id, 1024 * 1024);
    await w.init();
    await w.finalise(base(id));
    const ok = await w.writeArtifact('bodies/00001.html', 'late', { type: 'response_body', observedStart: null, observedEnd: null, creationMethod: 't', completeness: 'complete', limitations: [] });
    expect(ok).toBe(false);
    await expect(stat(join(t.root, 'tmp', id))).rejects.toThrow();
  });

  it('keeps a legitimately empty artifact complete but flags unexplained empty files', async () => {
    const t = await tempRoot();
    cleanup = t.cleanup;
    const id = randomUUID();
    const w = new AttemptWriter(t.root, id, 1024 * 1024);
    await w.init();
    await w.writeArtifact('dom/rendered.txt', '', { type: 'rendered_text', observedStart: null, observedEnd: null, creationMethod: 't', completeness: 'complete', limitations: [], metadata: { empty_is_legitimate: true } });
    await w.writeArtifact('dom/rendered.html', '', { type: 'rendered_dom', observedStart: null, observedEnd: null, creationMethod: 't', completeness: 'complete', limitations: [] });
    const fin = await w.finalise(base(id));
    expect(fin.manifest.artifacts.find((a) => a.type === 'rendered_text')?.completeness).toBe('complete');
    expect(fin.manifest.artifacts.find((a) => a.type === 'rendered_dom')?.completeness).toBe('partial');
  });

  it('never builds paths from untrusted text', () => {
    expect(() => assertSafeRelative('../etc/passwd')).toThrow();
    expect(() => assertSafeRelative('a/../../b')).toThrow();
    expect(() => assertSafeRelative('/abs')).toThrow();
    expect(() => assertSafeRelative('Evil Name.html')).toThrow();
    expect(() => assertSafeRelative('screenshots/01-early.png')).not.toThrow();
    expect(() => new AttemptWriter('/tmp', 'not-a-uuid', 1)).toThrow();
  });
});
