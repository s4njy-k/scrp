#!/usr/bin/env node
/**
 * Operator CLI contract (blueprint §18). Run inside the coordinator container:
 *   docker --context rootless compose -p cyber-web-collector exec coordinator node dist/cli.js <command>
 */
import { readFile, writeFile } from 'node:fs/promises';
import { Command } from 'commander';
import { loadPolicy, type Policy } from './config/policy.js';
import { audit, createPool, type Pool } from './db/pool.js';
import { migrate, syncPermitSlots } from './db/migrate.js';
import { importFile } from './importer/importer.js';
import { writeExport } from './export/exporter.js';
import { collectStatus } from './observability/status.js';
import { reconcile } from './coordinator/reconciler.js';
import { applyRetention } from './coordinator/retention.js';
import { artifactRoot } from './storage/artifactStore.js';
import { runVerification } from './evidence/verify.js';
import { createCheckpoint, generateSigningKey, sealPending, verifyChain, type CheckpointFile } from './evidence/custody.js';
import { createEvidencePackage, verifyPackageDir } from './evidence/package.js';
import { effectiveClockStatus, type ClockStatus } from './evidence/time.js';
import { logger } from './observability/logger.js';

const program = new Command();
program.name('cyber-web-collector').description('Evidence-grade web collection: operator CLI').version('0.1.0');

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

async function withPool<T>(fn: (pool: Pool, policy: Policy) => Promise<T>): Promise<T> {
  const policy = loadPolicy();
  const pool = createPool(undefined, 3);
  try {
    return await fn(pool, policy);
  } finally {
    await pool.end();
  }
}

function print(v: unknown): void {
  process.stdout.write(`${JSON.stringify(v, null, 2)}\n`);
}

program.command('validate-policy')
  .argument('[path]', 'policy YAML (default: COLLECTOR_POLICY_PATH or config/policy.default.yaml)')
  .description('Validate the collector policy and print the resolved values')
  .action((path?: string) => {
    const p = path ? loadPolicy(path) : loadPolicy();
    print({ ok: true, policy: p });
  });

program.command('migrate').description('Apply database migrations and sync browser permit slots').action(async () => {
  await withPool(async (pool, policy) => {
    const applied = await migrate(pool);
    await syncPermitSlots(pool, policy.limits.browser_slots_global);
    print({ applied });
  });
});

program.command('serve')
  .argument('<role>', 'coordinator | browser-worker | gateway')
  .description('Run a long-lived service role')
  .action(async (role: string) => {
    process.env.COLLECTOR_ROLE = role;
    if (role === 'gateway') {
      const { EgressGateway, gatewayOptionsFromEnv } = await import('./gateway/server.js');
      const gw = new EgressGateway(gatewayOptionsFromEnv());
      const { port } = await gw.listen();
      logger.info({ port }, 'egress gateway listening');
      const stop = () => { void gw.close().then(() => process.exit(0)); };
      process.once('SIGTERM', stop);
      process.once('SIGINT', stop);
      return;
    }
    const policy = loadPolicy();
    const root = artifactRoot();
    if (role === 'coordinator') {
      const { runCoordinator } = await import('./coordinator/main.js');
      await runCoordinator(createPool(undefined, 8), policy, root);
    } else if (role === 'browser-worker') {
      const { runBrowserWorker } = await import('./worker/main.js');
      await runBrowserWorker(createPool(undefined, 4), policy, root);
    } else {
      throw new Error(`unknown role: ${role}`);
    }
  });

program.command('import')
  .argument('<file>', 'CSV or JSONL file (inside the container, e.g. /input/urls.csv)')
  .option('--profile <profile>', 'default capture profile: data_triage | browser_evidence', 'browser_evidence')
  .option('--window <key>', 'collection window key for target/profile/window deduplication', today())
  .option('--format <format>', 'csv | jsonl (default: by extension)')
  .option('--by <actor>', 'operator identifier recorded in the audit log', process.env.USER ?? 'operator')
  .description('Import targets; every line is recorded, including rejections with reasons')
  .action(async (file: string, o: { profile: string; window: string; format?: string; by: string }) => {
    if (o.profile !== 'data_triage' && o.profile !== 'browser_evidence') throw new Error('--profile must be data_triage or browser_evidence');
    await withPool(async (pool, policy) => {
      const s = await importFile(pool, policy, file, { defaultProfile: o.profile as 'data_triage' | 'browser_evidence', windowKey: o.window, importedBy: o.by, ...(o.format ? { format: o.format as 'csv' | 'jsonl' } : {}) });
      print(s);
    });
  });

program.command('export')
  .option('--date <date>', 'YYYY-MM-DD (UTC)', today())
  .option('--format <format>', 'jsonl | csv', 'jsonl')
  .description('Write a status export under ARTIFACT_ROOT/exports/')
  .action(async (o: { date: string; format: string }) => {
    if (o.format !== 'jsonl' && o.format !== 'csv') throw new Error('--format must be jsonl or csv');
    await withPool(async (pool) => print(await writeExport(pool, artifactRoot(), o.date, o.format as 'jsonl' | 'csv')));
  });

program.command('status')
  .option('--hours <n>', 'reporting window', '24')
  .description('Queue health, required-artifact completion, yields, integrity and resource state')
  .action(async (o: { hours: string }) => withPool(async (pool) => print(await collectStatus(pool, Number(o.hours)))));

program.command('job')
  .argument('<id>', 'job id')
  .description('Show one job with attempts, artifacts and identifiers')
  .action(async (id: string) => withPool(async (pool) => {
    const job = (await pool.query('SELECT j.*, t.url FROM jobs j JOIN targets t ON t.id = j.target_id WHERE j.id = $1', [Number(id)])).rows[0];
    if (!job) throw new Error('job not found');
    const attempts = (await pool.query('SELECT id, attempt_no, kind, engine, status, outcome, classification, required_satisfied, missing_required, artifact_dir, error, active_seconds FROM attempts WHERE job_id = $1 ORDER BY attempt_no', [Number(id)])).rows;
    const sources = (await pool.query('SELECT s.* FROM job_sources js JOIN source_records s ON s.id = js.source_record_id WHERE js.job_id = $1', [Number(id)])).rows;
    const identifiers = (await pool.query('SELECT field_type, normalised_value, method, validation_state, display_context FROM identifiers WHERE job_id = $1 ORDER BY field_type', [Number(id)])).rows;
    print({ job, sources, attempts, identifiers });
  }));

program.command('requeue')
  .argument('<id>', 'job id')
  .option('--new-window <key>', 'create a NEW job for a new collection window (fresh budget) instead of modifying history')
  .option('--relaxed-tls', 'explicitly labelled relaxed-TLS inspection profile for the new job (never global)')
  .option('--stage <stage>', 'initial stage for the new job: http | browser_primary', 'browser_primary')
  .option('--by <actor>', 'operator', process.env.USER ?? 'operator')
  .description('Schedule a revisit as a new job; finished jobs and their attempts are never rewritten')
  .action(async (id: string, o: { newWindow?: string; relaxedTls?: boolean; stage: string; by: string }) => withPool(async (pool) => {
    if (!o.newWindow) throw new Error('--new-window <key> is required: revisits are new jobs with a fresh, recorded budget');
    const r = await pool.query<{ id: number }>(
      `INSERT INTO jobs (target_id, profile, window_key, registrable_domain, priority, urgent, required_artifacts, capture_variant, scope,
          allowed_interactions, retention_class, case_ref, deadline, stage)
       SELECT target_id, profile, $2, registrable_domain, priority, urgent, required_artifacts, capture_variant,
              scope || jsonb_build_object('relaxed_tls', $3::boolean, 'requeued_from_job', id), allowed_interactions, retention_class, case_ref, NULL, $4::job_stage
         FROM jobs WHERE id = $1
       ON CONFLICT (target_id, profile, capture_variant, window_key) WHERE parent_job_id IS NULL DO NOTHING RETURNING id`,
      [Number(id), o.newWindow, Boolean(o.relaxedTls), o.stage],
    );
    if (!r.rows[0]) throw new Error('job not found, or a job for that window already exists');
    await pool.query('INSERT INTO job_sources (job_id, source_record_id) SELECT $2, source_record_id FROM job_sources WHERE job_id = $1 ON CONFLICT DO NOTHING', [Number(id), r.rows[0].id]);
    await audit(pool, o.by, 'job_requeued', { from_job: Number(id), window: o.newWindow, relaxed_tls: Boolean(o.relaxedTls) }, { jobId: r.rows[0].id });
    print({ new_job_id: r.rows[0].id });
  }));

program.command('manual-review').description('List jobs awaiting operator attention').action(async () => withPool(async (pool) => {
  print((await pool.query(`SELECT j.id, t.url, j.outcome, j.outcome_reason, j.case_ref, j.updated_at FROM jobs j JOIN targets t ON t.id = j.target_id WHERE j.state = 'MANUAL_REVIEW' ORDER BY j.urgent DESC, j.priority DESC, j.updated_at`)).rows);
}));

const hold = program.command('case-hold').description('Case holds override routine retention');
hold.command('place').argument('<caseRef>').requiredOption('--reason <text>').option('--by <actor>', 'operator', process.env.USER ?? 'operator')
  .action(async (caseRef: string, o: { reason: string; by: string }) => withPool(async (pool) => {
    await pool.query(`INSERT INTO case_holds (case_ref, reason, placed_by) VALUES ($1,$2,$3)
                      ON CONFLICT (case_ref) DO UPDATE SET reason = EXCLUDED.reason, placed_by = EXCLUDED.placed_by, placed_at = now(), released_at = NULL, released_by = NULL`, [caseRef, o.reason, o.by]);
    await audit(pool, o.by, 'case_hold_placed', { case_ref: caseRef, reason: o.reason });
    print({ ok: true });
  }));
hold.command('release').argument('<caseRef>').option('--by <actor>', 'operator', process.env.USER ?? 'operator')
  .action(async (caseRef: string, o: { by: string }) => withPool(async (pool) => {
    const r = await pool.query(`UPDATE case_holds SET released_at = now(), released_by = $2 WHERE case_ref = $1 AND released_at IS NULL`, [caseRef, o.by]);
    await audit(pool, o.by, 'case_hold_released', { case_ref: caseRef });
    print({ released: r.rowCount === 1 });
  }));

program.command('finding')
  .argument('<jobId>')
  .requiredOption('--assessment <a>', 'suspected_fraud | not_suspected | unknown | inconclusive')
  .requiredOption('--rationale <text>', 'corroborating reasons (shared CDN/IP or visual similarity alone is not attribution)')
  .option('--evidence <json>', 'JSON array of evidence references (attempt ids, artifact hashes)', '[]')
  .option('--by <actor>', 'analyst', process.env.USER ?? 'analyst')
  .description('Record a fraud assessment, separate from acquisition and extraction quality')
  .action(async (jobId: string, o: { assessment: string; rationale: string; evidence: string; by: string }) => withPool(async (pool) => {
    const r = await pool.query<{ id: number }>(
      `INSERT INTO findings (job_id, target_id, assessment, rationale, evidence_refs, created_by) SELECT id, target_id, $2, $3, $4, $5 FROM jobs WHERE id = $1 RETURNING id`,
      [Number(jobId), o.assessment, o.rationale, JSON.parse(o.evidence), o.by],
    );
    print({ finding_id: r.rows[0]?.id ?? null });
  }));

program.command('reconcile').description('Run crash reconciliation now').action(async () => withPool(async (pool, policy) => print(await reconcile(pool, policy, artifactRoot()))));

program.command('retention')
  .option('--delete', 'actually delete expired, unheld attempt directories (default: report only)')
  .action(async (o: { delete?: boolean }) => withPool(async (pool, policy) => print(await applyRetention(pool, policy, artifactRoot(), { deleteEnabled: Boolean(o.delete) }))));

program.command('verify')
  .argument('[attemptId]', 'attempt id (or use --job / --case)')
  .option('--job <id>', 'verify every committed attempt of a job')
  .option('--case <ref>', 'verify every committed attempt linked to a case reference')
  .option('--by <actor>', 'operator', process.env.USER ?? 'operator')
  .description('Verify Evidence: re-hash artifacts against manifests and the ledger; writes a hashed verification report')
  .action(async (attemptId: string | undefined, o: { job?: string; case?: string; by: string }) => withPool(async (pool) => {
    const scope = o.case ? 'case' : o.job ? 'job' : 'attempt';
    const id = o.case ?? o.job ?? attemptId;
    if (!id) throw new Error('give an attempt id, --job <id> or --case <ref>');
    const r = await runVerification(pool, artifactRoot(), scope, id, o.by, { actorKind: 'operator' });
    print({ run_id: r.run_id, result: r.result, counts: r.counts, report_path: r.report_path, report_sha256: r.report_sha256,
      failures: r.attempts.flatMap((a) => [...(a.manifest.status === 'ok' ? [] : [{ attempt: a.attempt_id, manifest: a.manifest.status }]),
        ...a.artifacts.filter((c) => c.status !== 'ok').map((c) => ({ attempt: a.attempt_id, path: c.path, status: c.status }))]),
      note: r.statement });
    if (r.result !== 'pass') process.exitCode = 2;
  }));

const custody = program.command('custody').description('Tamper-evident custody chain over the audit log');
custody.command('seal').description('Seal all committed, unsealed audit events now').action(async () => withPool(async (pool) => {
  let n = 0;
  for (let k = await sealPending(pool); k > 0; k = await sealPending(pool)) n += k;
  print({ sealed: n });
}));
custody.command('verify')
  .option('--checkpoint <file>', 'externally held checkpoint file to compare against')
  .description('Recompute the whole chain; optionally compare with an external signed checkpoint')
  .action(async (o: { checkpoint?: string }) => withPool(async (pool) => {
    const checkpoint = o.checkpoint ? JSON.parse(await readFile(o.checkpoint, 'utf8')) as CheckpointFile : undefined;
    const r = await verifyChain(pool, checkpoint ? { checkpoint } : {});
    print(r);
    if (!r.ok) process.exitCode = 2;
  }));
custody.command('checkpoint')
  .option('--note <text>', 'free-text note stored with the checkpoint')
  .option('--by <actor>', 'operator', process.env.USER ?? 'operator')
  .description('Export a (signed) chain-head checkpoint; copy it to storage outside this host')
  .action(async (o: { note?: string; by: string }) => withPool(async (pool) => print(await createCheckpoint(pool, artifactRoot(), o.by, o.note ? { note: o.note } : {}))));
custody.command('keygen')
  .argument('<privateKeyFile>', 'where to write the Ed25519 private key (mode 0600; keep it off the artifact volume)')
  .description('Generate an Ed25519 checkpoint-signing key pair (public key printed and written next to it)')
  .action(async (file: string) => {
    const k = generateSigningKey();
    await writeFile(file, k.privatePem, { mode: 0o600, flag: 'wx' });
    await writeFile(`${file}.pub`, k.publicPem, { mode: 0o644, flag: 'wx' });
    print({ private_key: file, public_key: `${file}.pub`, public_key_pem: k.publicPem });
  });

const pkg = program.command('package').description('Evidence packages with a parent hash index');
pkg.command('create')
  .requiredOption('--purpose <text>', 'why the package is produced (recorded in the custody chain)')
  .option('--job <id>').option('--case <ref>').option('--attempts <ids>', 'comma-separated attempt ids')
  .option('--include-restricted', 'include restricted artifacts (session/cookie data); requires a documented need')
  .option('--by <actor>', 'operator', process.env.USER ?? 'operator')
  .action(async (o: { purpose: string; job?: string; case?: string; attempts?: string; includeRestricted?: boolean; by: string }) => withPool(async (pool) => {
    const kind = o.case ? 'case' : o.job ? 'job' : o.attempts ? 'attempts' : null;
    if (!kind) throw new Error('give --job, --case or --attempts');
    print(await createEvidencePackage(pool, artifactRoot(), { kind, id: (o.case ?? o.job ?? o.attempts)!, purpose: o.purpose, actor: o.by, includeRestricted: Boolean(o.includeRestricted), actorKind: 'operator' }));
  }));
pkg.command('verify')
  .argument('<dir>', 'package directory (extracted from the .tar if needed)')
  .option('--index-sha256 <hex>', 'index hash from the ledger or the hand-off record')
  .description('Verify a package offline against its own index')
  .action(async (dir: string, o: { indexSha256?: string }) => {
    const r = await verifyPackageDir(dir, o.indexSha256);
    print(r);
    if (!r.ok) process.exitCode = 2;
  });

program.command('clock')
  .argument('<action>', 'record | show')
  .option('--source <text>', 'time source, e.g. "chrony: ntp.example.in"')
  .option('--synchronized <yes|no>', 'whether the host reports synchronised time')
  .option('--offset-ms <n>', 'measured offset from the reference in milliseconds')
  .description('Record the host clock-synchronisation fact attached to every manifest (run by scripts/preflight.sh)')
  .action(async (action: string, o: { source?: string; synchronized?: string; offsetMs?: string }) => withPool(async (pool) => {
    if (action === 'show') {
      const r = (await pool.query<{ value: Record<string, unknown> }>(`SELECT value FROM system_state WHERE key = 'clock'`)).rows[0];
      print(effectiveClockStatus(r?.value as Partial<ClockStatus>));
      return;
    }
    if (action !== 'record') throw new Error('action must be record or show');
    if (!o.source || !o.synchronized) throw new Error('--source and --synchronized are required');
    const value = { source: o.source, sync_verified: o.synchronized === 'yes', offset_ms: o.offsetMs === undefined ? null : Number(o.offsetMs), recorded_at: new Date().toISOString() };
    await pool.query(`INSERT INTO system_state (key, value) VALUES ('clock', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [value]);
    await audit(pool, process.env.USER ?? 'operator', 'clock_status_recorded', value, { actorKind: 'operator', objectType: 'system', objectId: 'clock' });
    print(value);
  }));

const backup = program.command('backup').description('Record and report backup facts (the backup itself runs scripts/backup.sh)');
backup.command('record').requiredOption('--destination <text>').requiredOption('--independent <yes|no>').option('--note <text>', '', '')
  .action(async (o: { destination: string; independent: string; note: string }) => withPool(async (pool) => {
    const value = { last_success_at: new Date().toISOString(), destination: o.destination, independent_storage: o.independent === 'yes', note: o.note };
    await pool.query(`INSERT INTO system_state (key, value) VALUES ('backup', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [value]);
    await audit(pool, 'backup', 'backup_recorded', value);
    print(value);
  }));
backup.command('status').action(async () => withPool(async (pool) => {
  const r = (await pool.query<{ value: { last_success_at: string; independent_storage: boolean } }>(`SELECT value FROM system_state WHERE key = 'backup'`)).rows[0];
  print(r ? { ...r.value, age_hours: Number(((Date.now() - Date.parse(r.value.last_success_at)) / 3.6e6).toFixed(1)), single_disk_risk: !r.value.independent_storage }
    : { last_success_at: null, single_disk_risk: true, warning: 'no successful backup recorded' });
}));

program.command('healthcheck')
  .option('--port <port>', 'health port', process.env.HEALTH_PORT ?? '8081')
  .description('Exit 0 when the local liveness endpoint is healthy (Docker healthcheck)')
  .action(async (o: { port: string }) => {
    try {
      const res = await fetch(`http://127.0.0.1:${o.port}/healthz`, { signal: AbortSignal.timeout(5000) });
      process.exit(res.ok ? 0 : 1);
    } catch {
      process.exit(1);
    }
  });

program.parseAsync(process.argv).catch((err: Error) => {
  logger.error({ err: err.message }, 'command failed');
  process.stderr.write(`error: ${err.message}\n`);
  process.exit(1);
});
