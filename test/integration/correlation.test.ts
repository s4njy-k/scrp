/**
 * Correlation and risk on the relational ledger (checklist §5): grouping needs
 * multiple corroborating uncommon identifiers; low-specificity signals never
 * group; results respect case scope; risk picks up links to judged sites.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from '../../src/db/pool.js';
import { importText } from '../../src/importer/importer.js';
import { relatedTargets } from '../../src/investigation/correlation.js';
import { recordRiskAssessment } from '../../src/investigation/risk.js';
import { freshDb, hasDb, testPolicy } from '../helpers.js';

describe.skipIf(!hasDb)('correlation and risk over the ledger', () => {
  let pool: Pool;
  const policy = testPolicy();
  const users = { a: randomUUID(), b: randomUUID() };
  const attempt: Record<string, string> = {};
  const target: Record<string, number> = {};

  async function seedTarget(key: string, url: string, caseRef: string, ids: [string, string, string?][]): Promise<void> {
    await importText(pool, policy, `target,case_ref\n${url},${caseRef}`, { defaultProfile: 'browser_evidence', windowKey: 'w', importedBy: 't', filename: `${key}.csv`, format: 'csv' });
    const j = (await pool.query<{ id: number; target_id: number }>(`SELECT j.id, j.target_id FROM jobs j JOIN targets t ON t.id = j.target_id WHERE t.url = $1`, [url])).rows[0]!;
    const aid = randomUUID();
    await pool.query(
      `INSERT INTO attempts (id, job_id, attempt_no, kind, engine, adapter, vantage, lease_token, worker_id, retention_class, status, outcome, classification, required_satisfied)
       VALUES ($1,$2,1,'browser','chromium','playwright','t',1,'w','transient_triage','committed','CONTENT_CAPTURED','content_captured',true)`, [aid, j.id],
    );
    for (const [field, value, ctx] of ids) {
      await pool.query(
        `INSERT INTO identifiers (attempt_id, job_id, target_id, field_type, raw_value, normalised_value, value_key, method, validation_state, display_context, observed_at)
         VALUES ($1,$2,$3,$4,$5,$5,$5,'dom','format_valid',$6, now())`, [aid, j.id, j.target_id, field, value, ctx ?? 'displayed'],
      );
    }
    attempt[key] = aid;
    target[key] = j.target_id;
  }

  beforeAll(async () => {
    pool = await freshDb(policy);
    for (const [k, id] of Object.entries(users)) {
      await pool.query(`INSERT INTO users (id, username, display_name, password_hash, roles, created_by) VALUES ($1,$2,$2,'x',ARRAY['analyst'],'t')`, [id, `user${k}`]);
    }
    const caseA = randomUUID();
    const caseB = randomUUID();
    await pool.query(`INSERT INTO cases (id, case_ref, title) VALUES ($1,'CASE-A','A'), ($2,'CASE-B','B')`, [caseA, caseB]);
    await pool.query(`INSERT INTO case_members (case_id, user_id, case_role) VALUES ($1,$2,'investigator'), ($3,$4,'investigator')`, [caseA, users.a, caseB, users.b]);
    await seedTarget('t1', 'https://refund-one.example/', 'CASE-A', [['upi_vpa', 'payee@ybl'], ['whatsapp', '+919876543210'], ['analytics_id', 'G-SHARED1', 'resource_string']]);
    await seedTarget('t2', 'https://refund-two.example/', 'CASE-A', [['upi_vpa', 'payee@ybl'], ['whatsapp', '+919876543210']]);
    await seedTarget('t3', 'https://unrelated-shop.example/', 'CASE-A', [['analytics_id', 'G-SHARED1', 'resource_string']]);
    await seedTarget('t4', 'https://other-case.example/', 'CASE-B', [['upi_vpa', 'payee@ybl'], ['whatsapp', '+919876543210']]);
  });
  afterAll(async () => { await pool.end(); });

  it('groups only on corroborating uncommon identifiers and keeps analytics-only links weak', async () => {
    const rel = await relatedTargets(pool, target.t1!, { userId: users.a, all: false });
    const byUrl = Object.fromEntries(rel.map((r) => [r.url, r]));
    expect(byUrl['https://refund-two.example/']).toMatchObject({ relationship: 'possible_relationship' });
    expect(byUrl['https://refund-two.example/']!.explanation).toMatch(/common control is not established/);
    expect(byUrl['https://unrelated-shop.example/']).toMatchObject({ relationship: 'weak_signal_only' });
    // Case scope: the matching site in another case is invisible to this analyst.
    expect(byUrl['https://other-case.example/']).toBeUndefined();
    const all = await relatedTargets(pool, target.t1!, { userId: users.a, all: true });
    expect(all.map((r) => r.url)).toContain('https://other-case.example/');
  });

  it('raises risk when a site shares a payee with a site an analyst judged suspicious, and records versions immutably', async () => {
    const before = await recordRiskAssessment(pool, 'risk-rules-1', attempt.t1!);
    expect(before.signals.map((s) => s.code)).not.toContain('coordinated_with_judged_site');
    await pool.query(`INSERT INTO analyst_decisions (target_id, decision, verdict, reason_code, reason, actor) VALUES ($1,'likely_malicious','likely_malicious','payment_redirection','fake refund desk','t')`, [target.t2]);
    const after = await recordRiskAssessment(pool, 'risk-rules-1', attempt.t1!);
    expect(after.signals.find((s) => s.code === 'coordinated_with_judged_site')?.evidence.join(' ')).toMatch(/payee@ybl/);
    expect(after.score).toBeGreaterThan(before.score);
    expect((await pool.query('SELECT count(*)::int AS n FROM risk_assessments WHERE target_id = $1', [target.t1])).rows[0].n).toBe(2);
    await expect(pool.query('UPDATE risk_assessments SET score = 0')).rejects.toThrow(/append-only/);
  });
});
