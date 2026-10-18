/**
 * Evidence integrity (checklist §1, §11): v2 manifest context, post-rename
 * re-verification, first-image progress, Verify Evidence, tamper-evident
 * custody chain with signed checkpoints, and offline-verifiable packages.
 */
import { execFileSync } from 'node:child_process';
import { readFile, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { audit, type Pool } from '../../src/db/pool.js';
import { importText } from '../../src/importer/importer.js';
import { BrowserWorker } from '../../src/worker/browserWorker.js';
import { BrowserPool } from '../../src/worker/browserPool.js';
import { claimNextExtraction, runExtraction } from '../../src/extraction/runner.js';
import { runVerification } from '../../src/evidence/verify.js';
import { createCheckpoint, generateSigningKey, sealPending, verifyChain, type CheckpointFile } from '../../src/evidence/custody.js';
import { createEvidencePackage, verifyPackageDir } from '../../src/evidence/package.js';
import { canonicalJson } from '../../src/evidence/canonical.js';
import { formatIst, istDateAndTime } from '../../src/evidence/time.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';
import { BROWSERS_AVAILABLE, TEST_CHROMIUM_SANDBOX, freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

describe('canonical JSON and IST rendering', () => {
  it('sorts keys deterministically and drops undefined members', () => {
    expect(canonicalJson({ b: 1, a: [true, null, 'x'], c: undefined, d: { z: 1, y: 2 } })).toBe('{"a":[true,null,"x"],"b":1,"d":{"y":2,"z":1}}');
    expect(() => canonicalJson({ n: Number.NaN })).toThrow();
  });
  it('renders IST without daylight saving and in the Schedule date/time format', () => {
    expect(formatIst('2026-10-18T06:30:00Z')).toBe('2026-10-18 12:00:00 IST');
    expect(istDateAndTime('2026-10-18T20:45:00Z')).toEqual({ date: '19/10/2026', time: '02:15' });
  });
});

describe.skipIf(!hasDb)('custody chain (tamper evidence)', () => {
  let pool: Pool;
  let root: string;
  let cleanup: () => Promise<void>;
  beforeAll(async () => {
    pool = await freshDb(testPolicy());
    ({ root, cleanup } = await tempRoot());
  });
  afterAll(async () => {
    await pool.end();
    await cleanup();
  });

  it('chains every event, refuses edits and deletes, and detects rewrites against a signed checkpoint', async () => {
    for (let i = 0; i < 25; i += 1) await audit(pool, 'tester', 'test_event', { i, note: 'ü€' }, { objectType: 'thing', objectId: i });
    expect(await sealPending(pool)).toBeGreaterThanOrEqual(25);
    const ok = await verifyChain(pool);
    expect(ok.ok).toBe(true);
    expect(ok.unsealed_events).toBe(0);
    expect(ok.head!.chain_pos).toBe(ok.sealed_events);

    // Append-only: the trigger refuses UPDATE of sealed rows and any DELETE.
    await expect(pool.query(`UPDATE audit_events SET details = '{"i":999}' WHERE chain_pos = 3`)).rejects.toThrow(/append-only/);
    await expect(pool.query(`DELETE FROM audit_events WHERE chain_pos = 3`)).rejects.toThrow(/append-only/);

    const keyFile = join(root, 'custody.key');
    const k = generateSigningKey();
    await writeFile(keyFile, k.privatePem, { mode: 0o600 });
    const cp = await createCheckpoint(pool, root, 'tester', { signingKeyPath: keyFile });
    expect(cp.signature_alg).toBe('ed25519');
    const cpFile = JSON.parse(await readFile(join(root, cp.path), 'utf8')) as CheckpointFile;
    expect((await verifyChain(pool, { checkpoint: cpFile })).checkpoint).toMatchObject({ matches: true, signature_valid: true });

    // An administrator bypassing the trigger and editing a row is detected...
    await pool.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only');
    await pool.query(`UPDATE audit_events SET details = '{"i": 999}' WHERE chain_pos = 5`);
    const edited = await verifyChain(pool);
    expect(edited.ok).toBe(false);
    expect(edited.problems.join('\n')).toMatch(/position 5 .*differ from the sealed payload/);

    // ...and so is a full, consistent rewrite of history, but only against the external checkpoint.
    await pool.query('UPDATE audit_events SET chain_pos = NULL, prev_hash = NULL, event_hash = NULL, sealed_payload = NULL, sealed_at = NULL');
    await pool.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only');
    while ((await sealPending(pool)) > 0) { /* re-seal */ }
    expect((await verifyChain(pool)).ok).toBe(true);
    const forged = await verifyChain(pool, { checkpoint: cpFile });
    expect(forged.ok).toBe(false);
    expect(forged.checkpoint?.matches).toBe(false);

    // A tampered checkpoint file fails its signature.
    const bad = { ...cpFile, event_hash: 'f'.repeat(64) };
    expect((await verifyChain(pool, { checkpoint: bad })).checkpoint?.signature_valid).toBe(false);
  });
});

describe.skipIf(!hasDb || !BROWSERS_AVAILABLE)('evidence integrity on a real capture', () => {
  let fixture: FixtureServer;
  let pool: Pool;
  let root: string;
  let cleanup: () => Promise<void>;
  let browsers: BrowserPool;
  let attemptId: string;
  let jobId: number;
  const egress = { proxyUrl: null, vantage: 'test-direct' };

  beforeAll(async () => {
    fixture = await startFixtureServer();
    const policy = testPolicy({
      scope: { allowed_ports: [80, 443, fixture.port] },
      limits: { per_domain_delay_seconds: 0, child_pages_per_target_max: 0 },
      browser: { navigation_timeout_seconds: 8, readiness_max_seconds: 3, challenge_wait_seconds: 2, scroll_step_wait_ms: 100 },
      extraction: { ocr_enabled: false },
    });
    ({ root, cleanup } = await tempRoot());
    pool = await freshDb(policy);
    browsers = new BrowserPool({ mode: 'local', wsEndpoint: null, connectTimeoutMs: 30_000, chromiumSandbox: TEST_CHROMIUM_SANDBOX }, policy, egress);
    const input = `${fixture.url('/static')}?utm_source=sms&b=2&a=1#refund-form`;
    await importText(pool, policy, `target,case_ref,urgent\n"${input}",CASE-EV-1,true\n${fixture.url('/qr-conflict')},CASE-EV-1,true`, { defaultProfile: 'browser_evidence', windowKey: 'w', importedBy: 'test', filename: 'e.csv', format: 'csv' });
    await pool.query(`INSERT INTO system_state (key, value) VALUES ('clock', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [{ source: 'test chrony', sync_verified: true, offset_ms: 3, recorded_at: new Date().toISOString() }]);
    const worker = new BrowserWorker({ pool, policy, egress, browsers, artifactRoot: root, workerId: 'ev-worker' });
    await worker.runOne();
    await worker.runOne();
    const a = (await pool.query<{ id: string; job_id: number }>(`SELECT a.id, a.job_id FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN targets t ON t.id = j.target_id WHERE a.status = 'committed' AND t.url LIKE '%/static%' LIMIT 1`)).rows[0]!;
    attemptId = a.id;
    jobId = a.job_id;
  }, 120_000);
  afterAll(async () => {
    await browsers.closeAll();
    await pool.end();
    await fixture.close();
    await cleanup();
  });

  it('writes a v2 manifest with the exact original input, capture context, clock and IST time', async () => {
    const a = (await pool.query(`SELECT artifact_dir, manifest_sha256, manifest_version, first_image_rel, first_image_sha256, progress_stage FROM attempts WHERE id = $1`, [attemptId])).rows[0];
    expect(a.manifest_version).toBe(2);
    expect(a.progress_stage).toBe('committed');
    const m = JSON.parse(await readFile(join(root, a.artifact_dir, 'manifest.json'), 'utf8'));
    expect(m.originalInputs).toEqual([`${fixture.url('/static')}?utm_source=sms&b=2&a=1#refund-form`]);
    expect(m.navigationUrl).toBe(`${fixture.url('/static')}?utm_source=sms&b=2&a=1#refund-form`);
    expect(m.observedAtIst).toMatch(/ IST$/);
    expect(m.clock).toMatchObject({ source: 'test chrony', sync_verified: true, offset_ms: 3 });
    expect(m.profile).toMatchObject({ name: 'browser_evidence', captureVariant: 'desktop', caseRefs: ['CASE-EV-1'] });
    expect(m.engineInfo.version).toBeTruthy();
    expect(m.captureContext.viewport).toEqual({ width: 1440, height: 1000 });
    expect(m.networkVantage).toMatchObject({ id: 'test-direct', publicIpSource: 'not_observed' });
    expect(m.software.collector_version).toBeTruthy();
    // The manifest never contains its own hash (it is recorded in the ledger and the custody chain).
    expect(JSON.stringify(m)).not.toContain(a.manifest_sha256);
    // The first viewport image was published while the attempt was open, with its hash.
    expect(a.first_image_rel).toMatch(/^screenshots\/.+\.png$/);
    const firstEntry = m.artifacts.find((e: { path: string }) => e.path === a.first_image_rel);
    expect(firstEntry.sha256).toBe(a.first_image_sha256);
    const states = (await pool.query(`SELECT DISTINCT verification_state FROM artifacts WHERE attempt_id = $1 AND relative_path IS NOT NULL`, [attemptId])).rows.map((r) => r.verification_state);
    expect(states).toEqual(['verified_at_commit']);
  });

  it('preserves a QR payee that differs from the displayed payee, flags the conflict, makes thumbnails and assesses risk', async () => {
    const policy = testPolicy({ extraction: { ocr_enabled: false } });
    for (let x = await claimNextExtraction(pool); x; x = await claimNextExtraction(pool)) await runExtraction(pool, policy, root, x);
    const rows = (await pool.query(`SELECT i.normalised_value, i.method, i.display_context, i.conflicts, i.source_artifact_id, i.extractor_version, i.confidence, i.signal_only
      FROM identifiers i JOIN targets t ON t.id = i.target_id WHERE t.url LIKE '%/qr-conflict' AND i.field_type = 'upi_vpa'`)).rows;
    const qr = rows.find((r) => r.method === 'qr');
    const shown = rows.find((r) => r.method === 'dom' && r.display_context === 'displayed');
    expect(qr.normalised_value).toBe('fraudster.test@okaxis');
    expect(shown.normalised_value).toBe('genuine.merchant@okaxis');
    expect(qr.conflicts[0]).toMatchObject({ kind: 'qr_vs_displayed_text' });
    expect(shown.conflicts[0].detail).toMatch(/QR pays fraudster.test@okaxis/);
    expect(qr.source_artifact_id).toBeGreaterThan(0);
    expect(qr.extractor_version).toMatch(/^extract-/);
    expect(Number(qr.confidence)).toBeGreaterThan(Number(shown.confidence) - 0.2);
    const thumbs = (await pool.query(`SELECT a.derived_from, a.metadata, o.artifact_type AS source_type FROM artifacts a JOIN artifacts o ON o.id = a.derived_from WHERE a.artifact_type = 'thumbnail'`)).rows;
    expect(thumbs.length).toBeGreaterThan(0);
    expect(thumbs[0].source_type).toMatch(/^screenshot_/);
    expect(thumbs[0].metadata.width).toBeLessThanOrEqual(360);
    const risk = (await pool.query(`SELECT r.band, r.signals, r.conflicts FROM risk_assessments r JOIN targets t ON t.id = r.target_id WHERE t.url LIKE '%/qr-conflict'`)).rows[0];
    expect(risk.signals.map((s: { code: string }) => s.code)).toContain('qr_payment_code');
    expect(risk.conflicts.map((c: { code: string }) => c.code)).toContain('identifier_conflict');
    // Verification covers the derivatives too.
    const job = (await pool.query(`SELECT j.id FROM jobs j JOIN targets t ON t.id = j.target_id WHERE t.url LIKE '%/qr-conflict'`)).rows[0].id;
    const v = await runVerification(pool, root, 'job', String(job), 'tester');
    expect(v.result).toBe('pass');
    expect(v.attempts[0]!.artifacts.some((c) => c.derivative && c.type === 'thumbnail')).toBe(true);
  });

  it('Verify Evidence passes on untouched bytes and fails on modified or missing files', async () => {
    const pass = await runVerification(pool, root, 'job', String(jobId), 'tester');
    expect(pass.result).toBe('pass');
    expect(pass.counts.ok).toBe(pass.counts.artifacts_checked);
    const reportText = await readFile(join(root, pass.report_path), 'utf8');
    expect((await import('node:crypto')).createHash('sha256').update(reportText).digest('hex')).toBe(pass.report_sha256);

    const dir = (await pool.query(`SELECT artifact_dir FROM attempts WHERE id = $1`, [attemptId])).rows[0].artifact_dir as string;
    const text = join(root, dir, 'dom', 'rendered.txt');
    const original = await readFile(text);
    await writeFile(text, Buffer.concat([original, Buffer.from(' forged')]));
    const fail = await runVerification(pool, root, 'attempt', attemptId, 'tester');
    expect(fail.result).toBe('fail');
    expect(fail.attempts[0]!.artifacts.find((c) => c.path === 'dom/rendered.txt')?.status).toBe('mismatch');
    expect((await pool.query(`SELECT verification_state FROM artifacts WHERE attempt_id = $1 AND relative_path = 'dom/rendered.txt'`, [attemptId])).rows[0].verification_state).toBe('mismatch');
    // A package is refused while verification fails.
    await expect(createEvidencePackage(pool, root, { kind: 'job', id: String(jobId), purpose: 'test', actor: 'tester' })).rejects.toThrow(/verification failed/);
    await writeFile(text, original);

    const shot = join(root, dir, 'dom', 'rendered.html');
    const html = await readFile(shot);
    await unlink(shot);
    const missing = await runVerification(pool, root, 'attempt', attemptId, 'tester');
    expect(missing.attempts[0]!.artifacts.find((c) => c.path === 'dom/rendered.html')?.status).toBe('missing');
    await writeFile(shot, html);
    expect((await runVerification(pool, root, 'attempt', attemptId, 'tester')).result).toBe('pass');
    const events = (await pool.query(`SELECT outcome FROM audit_events WHERE event_type = 'evidence_verified' AND object_id <> (SELECT j.id::text FROM jobs j JOIN targets t ON t.id = j.target_id WHERE t.url LIKE '%/qr-conflict') ORDER BY id`)).rows.map((r) => r.outcome);
    expect(events).toEqual(['pass', 'fail', 'fail', 'fail', 'pass']);
  });

  it('builds a package whose index is hashed outside itself and verifies offline; tampering is detected', async () => {
    const p = await createEvidencePackage(pool, root, { kind: 'job', id: String(jobId), purpose: 'handover test', actor: 'tester' });
    expect(p.verification.result).toBe('pass');
    const dir = join(root, p.relative_path);
    const index = JSON.parse(await readFile(join(dir, 'package-index.json'), 'utf8'));
    expect(JSON.stringify(index)).not.toContain(p.index_sha256);
    expect(index.withheld.every((w: { reason: string }) => /restricted/.test(w.reason))).toBe(true);
    expect((await verifyPackageDir(dir, p.index_sha256)).ok).toBe(true);
    expect((await pool.query(`SELECT index_sha256 FROM evidence_packages WHERE id = $1`, [p.package_id])).rows[0].index_sha256).toBe(p.index_sha256);
    // The archive is a valid tar containing the index.
    const listing = execFileSync('tar', ['-tf', join(root, p.archive_path)], { encoding: 'utf8' });
    expect(listing).toContain(`evidence-package-${p.package_id}/package-index.json`);

    const shot = index.files.find((f: { role: string; path: string }) => f.role === 'original' && f.path.endsWith('.png')).path as string;
    await writeFile(join(dir, shot), Buffer.from('not the original'));
    await writeFile(join(dir, 'extra.txt'), 'slipped in');
    const r = await verifyPackageDir(dir, p.index_sha256);
    expect(r.ok).toBe(false);
    expect(r.problems).toEqual(expect.arrayContaining([`modified: ${shot}`, 'unlisted file: extra.txt']));
    expect((await verifyPackageDir(dir, 'a'.repeat(64))).index_matches_expected).toBe(false);
  });
});
