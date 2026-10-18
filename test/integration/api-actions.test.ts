/**
 * Legally routed actions and Section 63 worksheets end to end (checklist §1,
 * §5, §6, §11): eligibility checks, maker-checker, approval snapshots, report
 * generation (formula-safe, script-free), proof-backed issuance records,
 * verification-before-closure, false-positive blocking, statutory-ground
 * validation, retention protection and the certificate worksheet lifecycle.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from '../../src/db/pool.js';
import { BrowserWorker } from '../../src/worker/browserWorker.js';
import { BrowserPool } from '../../src/worker/browserPool.js';
import { claimNextExtraction, runExtraction } from '../../src/extraction/runner.js';
import type { ApiApp } from '../../src/web/server.js';
import { startFixtureServer, type FixtureServer } from '../fixtures/server.js';
import { ApiClient, loggedIn, startApi } from '../apiHelpers.js';
import { BROWSERS_AVAILABLE, TEST_CHROMIUM_SANDBOX, freshDb, hasDb, tempRoot, testPolicy } from '../helpers.js';

describe.skipIf(!hasDb || !BROWSERS_AVAILABLE)('analyst API: legally routed actions and certificates', () => {
  let fixture: FixtureServer;
  let pool: Pool;
  let root: string;
  let cleanup: () => Promise<void>;
  let browsers: BrowserPool;
  let app: ApiApp;
  let maker: ApiClient;
  let checker: ApiClient;
  let reporter: ApiClient;
  let caseId: string;
  let worker: BrowserWorker;
  let policy: ReturnType<typeof testPolicy>;
  const t: Record<string, number> = {};
  const egress = { proxyUrl: null, vantage: 'test-direct' };
  const pdf = Buffer.from('%PDF-1.4\n% test document\n%%EOF\n');

  async function captureAll(): Promise<void> {
    for (let i = 0; i < 4; i += 1) await worker.runOne();
    for (let a = await claimNextExtraction(pool); a; a = await claimNextExtraction(pool)) await runExtraction(pool, policy, root, a);
  }

  beforeAll(async () => {
    fixture = await startFixtureServer();
    policy = testPolicy({
      scope: { allowed_ports: [80, 443, fixture.port] },
      limits: { per_domain_delay_seconds: 0, child_pages_per_target_max: 0 },
      browser: { navigation_timeout_seconds: 8, readiness_max_seconds: 3, challenge_wait_seconds: 2, scroll_step_wait_ms: 100 },
      extraction: { ocr_enabled: false },
    });
    ({ root, cleanup } = await tempRoot());
    pool = await freshDb(policy);
    browsers = new BrowserPool({ mode: 'local', wsEndpoint: null, connectTimeoutMs: 30_000, chromiumSandbox: TEST_CHROMIUM_SANDBOX }, policy, egress);
    worker = new BrowserWorker({ pool, policy, egress, browsers, artifactRoot: root, workerId: 'act-worker' });
    let base: string;
    ({ app, base } = await startApi(pool, policy, root));
    maker = (await loggedIn(base, pool, 'maker', ['analyst', 'intake'])).client;
    checker = (await loggedIn(base, pool, 'checker', ['approver', 'analyst'])).client;
    reporter = (await loggedIn(base, pool, 'reporter', ['report', 'evidence', 'analyst'])).client;
    caseId = (await maker.post('/api/v1/cases', { case_ref: 'ACT-CASE-1', title: 'Refund desk takedown' })).body.id;
    for (const u of ['checker', 'reporter']) await maker.post(`/api/v1/cases/${caseId}/members`, { username: u, case_role: 'investigator', reason: 'action team' });
    const list = `${fixture.url('/static')}\n${fixture.url('/qr')}\n`;
    await maker.call('POST', `/api/v1/intake-batches?case_id=${caseId}&urgent=true`, undefined, { raw: list, contentType: 'text/plain', headers: { 'idempotency-key': 'act-intake-0001' } });
    await captureAll();
    for (const [k, path] of [['static', '/static'], ['qr', '/qr']] as const) t[k] = (await pool.query(`SELECT id FROM targets WHERE url = $1`, [fixture.url(path)])).rows[0].id;
  }, 180_000);
  afterAll(async () => {
    await app.close();
    await browsers.closeAll();
    await pool.end();
    await fixture.close();
    await cleanup();
  });

  it('blocks ineligible drafts, enforces maker-checker and generates a report only from the approved snapshot', async () => {
    await maker.post('/api/v1/decisions', { target_id: t.static, decision: 'likely_malicious', reason_code: 'payment_redirection', reason: 'Fake refund desk collects UPI fee', expected_last_decision_id: null });
    const draft = await maker.post('/api/v1/notices', {
      case_id: caseId, route: 'registrar_abuse', recipient: { name: 'Example Registrar Abuse Desk', kind: 'registrar', contact: 'abuse@registrar.example' },
      targets: [{ target_id: t.static, legal_ground: '=HYPERLINK("http://evil.example","x")' }],
    });
    expect(draft.status).toBe(201);
    const nid = draft.body.id;
    const fail = await maker.post(`/api/v1/notices/${nid}/transition`, { action: 'submit' });
    expect(fail.body.error.code).toBe('not_eligible');
    expect(fail.body.error.details.failures.map((f: { code: string }) => f.code)).toEqual(expect.arrayContaining(['facts_summary', 'requested_action', 'field_legal_basis', 'route_policy_clause']));

    expect((await maker.patch(`/api/v1/notices/${nid}`, {
      expected_version: 1, facts_summary: 'On the date shown the page displayed a UPI payee and requested a refund processing fee.',
      requested_action: 'Review the domain under your anti-abuse policy.', legal_basis: 'Registrar anti-abuse policy (phishing/fraud).',
      route_fields: { policy_clause: 'Section 3.18 abuse handling' }, reference_no: 'I4C/2026/0001',
    })).body.version).toBe(2);
    expect((await maker.post(`/api/v1/notices/${nid}/transition`, { action: 'submit' })).body.state).toBe('analyst_review');
    expect((await maker.post(`/api/v1/notices/${nid}/transition`, { action: 'review_ok' })).body.error.code).toBe('maker_checker');
    expect((await maker.patch(`/api/v1/notices/${nid}`, { expected_version: 3, facts_summary: 'edit after submit' })).body.error.code).toBe('not_editable');
    expect((await checker.post(`/api/v1/notices/${nid}/transition`, { action: 'review_ok' })).body.state).toBe('legal_check');
    expect((await maker.post(`/api/v1/actions/${nid}/approve`, {})).status).toBe(403);
    const approved = await checker.post(`/api/v1/actions/${nid}/approve`, {});
    expect(approved.body.state).toBe('approved');
    expect(approved.body.approved_snapshot_sha256).toMatch(/^[0-9a-f]{64}$/);

    const preview = await maker.post('/api/v1/reports/notice/preview', { notice_id: nid, format: 'markdown' });
    expect(preview.body).toMatchObject({ preview_only: true, dispatch: 'none' });
    expect(preview.body.content).toContain('DRAFT');

    const gen = await reporter.post(`/api/v1/reports/${nid}/generate`, {});
    expect(gen.body.state).toBe('generated');
    const detail = await reporter.get(`/api/v1/notices/${nid}`);
    const report = detail.body.reports[0];
    const files = Object.fromEntries((report.files as { path: string }[]).map((f) => [f.path, f]));
    expect(Object.keys(files).sort()).toEqual(['notice.html', 'notice.json', 'notice.md', 'report-index.json', 'targets.csv']);
    const dir = (await pool.query('SELECT relative_dir FROM notice_reports WHERE id = $1', [report.id])).rows[0].relative_dir;
    const md = await readFile(join(root, dir, 'notice.md'), 'utf8');
    expect(md).toContain(fixture.url('/static'));
    expect(md).toContain('I4C/2026/0001');
    expect(md).toMatch(/[0-9a-f]{64}/);
    expect(md).not.toMatch(/Response period/); // no lawful deadline recorded, so none is stated
    const html = await readFile(join(root, dir, 'notice.html'), 'utf8');
    expect(html).not.toMatch(/<script|href=/i);
    expect(html).toContain('&quot;http://evil.example&quot;');
    const csv = await readFile(join(root, dir, 'targets.csv'), 'utf8');
    expect(csv).toContain(`"'=HYPERLINK(""http://evil.example"",""x"")"`);
    const dl = await reporter.get(`/api/v1/notices/${nid}/reports/${report.id}/notice.md`);
    expect(dl.status).toBe(200);
    // Cited evidence is protected from routine expiry.
    const retention = (await pool.query(`SELECT DISTINCT a.retention_class, a.expires_at FROM attempts a JOIN notice_targets nt ON a.id = ANY(nt.evidence_attempt_ids) WHERE nt.notice_id = $1`, [nid])).rows;
    expect(retention).toEqual([{ retention_class: 'notice_issued', expires_at: null }]);

    // Issuance and receipt need documentary proof; "issued" is not "complied"; closure needs a fresh capture.
    expect((await reporter.post(`/api/v1/notices/${nid}/transition`, { action: 'record_issued', issued_at: new Date().toISOString(), issue_channel: 'registrar abuse portal' })).body.error.code).toBe('dispatch_proof_required');
    const up = await reporter.call('POST', `/api/v1/cases/${caseId}/uploads?purpose=dispatch_proof&filename=portal-receipt.pdf`, undefined, { raw: pdf, contentType: 'application/pdf' });
    expect(up.status).toBe(201);
    const fake = await reporter.call('POST', `/api/v1/cases/${caseId}/uploads?purpose=dispatch_proof`, undefined, { raw: Buffer.from('<html>'), contentType: 'application/pdf' });
    expect(fake.body.error.code).toBe('content_mismatch');
    expect((await reporter.post(`/api/v1/notices/${nid}/transition`, { action: 'record_issued', issued_at: new Date().toISOString(), issue_channel: 'registrar abuse portal', dispatch_upload_id: up.body.id })).body.state).toBe('issued');
    expect((await reporter.post(`/api/v1/notices/${nid}/transition`, { action: 'record_acknowledged', received_at: new Date().toISOString() })).body.error.code).toBe('receipt_proof_required');
    const out = await reporter.post(`/api/v1/notices/${nid}/transition`, { action: 'record_outcome', outcome: 'complied', target_statuses: [{ target_id: t.static, status: 'acted_upon' }] });
    expect(out.body.state).toBe('complied');
    expect((await checker.post(`/api/v1/notices/${nid}/transition`, { action: 'close', close_as: 'verified_closed' })).body.error.code).toBe('verification_capture_required');
    await maker.post(`/api/v1/jobs/${(await pool.query('SELECT id FROM jobs WHERE target_id = $1 ORDER BY id LIMIT 1', [t.static])).rows[0].id}/recapture`, { reason: 'verify takedown', urgent: true });
    await captureAll();
    expect((await checker.post(`/api/v1/notices/${nid}/transition`, { action: 'close', close_as: 'verified_closed' })).body.state).toBe('verified_closed');
    const events = (await pool.query('SELECT to_state FROM notice_events WHERE notice_id = $1 ORDER BY id', [nid])).rows.map((r) => r.to_state);
    expect(events).toEqual(['draft', 'analyst_review', 'legal_check', 'approved', 'generated', 'issued', 'complied', 'verified_closed']);
    await expect(pool.query('DELETE FROM notice_events')).rejects.toThrow(/append-only/);
  }, 240_000);

  it('blocks notices for false-positive targets and s.69A requests without a prescribed ground', async () => {
    await maker.post('/api/v1/decisions', { target_id: t.qr, decision: 'false_positive', reason_code: 'legitimate_official', reason: 'Genuine merchant checkout', expected_last_decision_id: null });
    const n = await maker.post('/api/v1/notices', {
      case_id: caseId, route: 'it_act_69a_blocking', recipient: { name: 'Designated Officer', kind: 'government_nodal' }, targets: [{ target_id: t.qr }],
      facts_summary: 'facts', requested_action: 'block', legal_basis: 'IT Act s.69A', authority_ref: 'REF-1', issuing_authority: 'Agency', signatory_name: 'Officer',
      signatory_designation: 'SP', necessity_note: 'n', proportionality_note: 'p', route_fields: { ground_69a: 'online_fraud', public_access_impact: 'single URL' },
    });
    const r = await maker.post(`/api/v1/notices/${n.body.id}/transition`, { action: 'submit' });
    const codes = r.body.error.details.failures.map((f: { code: string }) => f.code);
    expect(codes).toEqual(expect.arrayContaining(['ground_69a_valid', `target_${t.qr}_not_suppressed`, `target_${t.qr}_reviewed`]));
    expect((await maker.get('/api/v1/legal-routes')).body.routes.find((x: { id: string }) => x.id === 'it_act_79_3_b_intimation').timing_note).toMatch(/not an internal SLA/);
  });

  it('prepares Section 63 fact sheets and worksheets without signing or inventing particulars', async () => {
    const att = (await pool.query(`SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id WHERE j.target_id = $1 AND a.status = 'committed' ORDER BY a.started_at LIMIT 1`, [t.static])).rows[0].id;
    const c = await reporter.post('/api/v1/certificates', { case_id: caseId, attempt_ids: [att], part: 'A' });
    expect(c.status).toBe(201);
    const id = c.body.id;
    const cert = await reporter.get(`/api/v1/certificates/${id}`);
    expect(cert.body.template_verified).toBe(false);
    expect(cert.body.certificate.worksheet.a_name).toEqual({ value: null, source: 'blank' });
    expect(cert.body.certificate.worksheet.a_serial_number.value).toBeNull();
    expect(cert.body.certificate.worksheet.a_declaration_lawful_control.value).toBeNull();
    expect(cert.body.certificate.worksheet.a_hash_algorithm).toEqual({ value: 'SHA256', source: 'system_proposed' });
    const hashReport = (await reporter.get(`/api/v1/certificates/${id}/files/hash-report`)).text;
    expect(hashReport).toMatch(/^# Hash report/);
    expect(hashReport).toContain('manifest.json');

    expect((await reporter.post(`/api/v1/certificates/${id}/transition`, { action: 'complete' })).body.error.code).toBe('template_not_verified');
    expect((await maker.post('/api/v1/templates/bsa-2023-schedule-s63-4-c/verify', { source_reference: 'India Code PDF, Schedule pp. 30-31', confirm_checked_against_official_text: true })).status).toBe(403);
    expect((await checker.post('/api/v1/templates/bsa-2023-schedule-s63-4-c/verify', { source_reference: 'India Code PDF, Schedule pp. 30-31', confirm_checked_against_official_text: true })).status).toBe(201);
    const incomplete = await reporter.post(`/api/v1/certificates/${id}/transition`, { action: 'complete' });
    expect(incomplete.body.error.code).toBe('worksheet_incomplete');
    expect(incomplete.body.error.details.gaps).toEqual(expect.arrayContaining(['a_name', 'a_hash_values', 'a_hash_algorithm']));
    expect((await reporter.patch(`/api/v1/certificates/${id}/worksheet`, { expected_version: 1, edits: { a_date: { value: '2026-10-18' } } })).body.error.code).toBe('invalid_worksheet_edit');
    expect((await reporter.patch(`/api/v1/certificates/${id}/worksheet`, { expected_version: 1, edits: { a_source_type: { value: 'Telepathy' } } })).body.error.code).toBe('invalid_worksheet_edit');
    const fields = cert.body.fields as { key: string; kind: string }[];
    const edits: Record<string, { value: unknown; marked_unknown?: boolean }> = {};
    for (const f of fields) edits[f.key] = { value: null, marked_unknown: true };
    Object.assign(edits, {
      a_name: { value: 'Investigating Officer (test)' }, a_source_type: { value: 'Server' }, a_declaration_lawful_control: { value: true },
      a_control: { value: ['Operated'] }, a_hash_values: { value: 'As listed in the enclosed hash report' }, a_hash_algorithm: { value: 'SHA256' },
      a_date: { value: '18/10/2026' }, a_time: { value: '14:05' }, a_place: { value: 'New Delhi' },
    });
    expect((await reporter.patch(`/api/v1/certificates/${id}/worksheet`, { expected_version: 1, edits })).body.gaps).toEqual([]);
    expect((await reporter.post(`/api/v1/certificates/${id}/transition`, { action: 'complete' })).body.state).toBe('completed');
    expect((await reporter.post(`/api/v1/certificates/${id}/transition`, { action: 'record_signed' })).body.error.code).toBe('upload_required');
    const signed = await reporter.call('POST', `/api/v1/cases/${caseId}/uploads?purpose=signed_certificate&filename=s63-signed.pdf`, undefined, { raw: pdf, contentType: 'application/pdf' });
    const s = await reporter.post(`/api/v1/certificates/${id}/transition`, { action: 'record_signed', upload_id: signed.body.id });
    expect(s.body).toMatchObject({ state: 'signed', signed_document_sha256: signed.body.sha256 });
    expect((await reporter.post(`/api/v1/certificates/${id}/transition`, { action: 'record_submission', submission: { authority: 'Court of the CJM, New Delhi', reference: 'CR-1/2026', submitted_at: new Date().toISOString() } })).body.state).toBe('attached_to_submission');
    expect((await reporter.post(`/api/v1/certificates/${id}/transition`, { action: 'withdraw', note: 'not allowed now' })).body.error.code).toBe('invalid_state');
    const ws = (await reporter.get(`/api/v1/certificates/${id}/files/worksheet`)).text;
    expect(ws).toContain('This worksheet is not a certificate');
    expect(ws).toContain('[marked unknown / not applicable]');
  });
});
