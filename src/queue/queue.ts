/**
 * Durable queue on PostgreSQL (blueprint §12).
 *
 *  - Jobs and browser permits are acquired atomically in one short transaction
 *    using FOR UPDATE SKIP LOCKED; no row lock is held during a visit.
 *  - Every lease carries a monotonically increasing fencing token. All
 *    subsequent writes must match the current token, so a worker that lost its
 *    lease can never overwrite a newer owner's state.
 *  - The attempt budget is charged when the lease is granted.
 *  - Execution is at-least-once: after a crash a site may be visited again.
 *    Result commits are idempotent instead of claiming exactly-once access.
 */
import { randomUUID } from 'node:crypto';
import type { Policy } from '../config/policy.js';
import type { AttemptManifest, JobStage } from '../acquisition/contract.js';
import { audit, withTransaction, type Pool, type PoolClient, type Queryable } from '../db/pool.js';
import { attemptSecondsFor, canRunStage, isAlternateStage, stageKind } from '../router/budget.js';
import type { JobRow, Lease, RouterDecision, TargetRow } from './types.js';

export interface LeaseRequest {
  workerId: string;
  stages: JobStage[];
  needsBrowserPermit: boolean;
  engine: string;
  adapter: string;
  vantage: string;
}

const ACTIVE_STATES = `('LEASED','CAPTURING','FINALISING')`;
const ALTERNATE_PERMIT_LOCK = 727274002;

export async function readAdmission(db: Queryable): Promise<{ paused: boolean; low_priority_paused: boolean; reasons: string[] }> {
  const { rows } = await db.query<{ value: { paused: boolean; low_priority_paused: boolean; reasons: string[] } }>(
    `SELECT value FROM system_state WHERE key = 'admission'`,
  );
  return rows[0]?.value ?? { paused: false, low_priority_paused: false, reasons: [] };
}

export async function leaseNext(pool: Pool, policy: Policy, req: LeaseRequest): Promise<Lease | null> {
  return withTransaction(pool, async (client) => {
    const admission = await readAdmission(client);
    if (admission.paused) return null;

    const { rows: candidates } = await client.query<JobRow>(
      `SELECT j.* FROM jobs j
        WHERE j.state IN ('QUEUED','DEFERRED')
          AND j.stage = ANY($1::job_stage[])
          AND j.next_eligible_at <= now()
          AND ($2::boolean = false OR j.urgent)
          AND NOT EXISTS (SELECT 1 FROM domain_pacing d
                           WHERE d.registrable_domain = j.registrable_domain AND d.next_allowed_at > now())
        ORDER BY j.urgent DESC, j.priority DESC, j.deadline ASC NULLS LAST, j.next_eligible_at, j.id
        FOR UPDATE OF j SKIP LOCKED
        LIMIT 20`,
      [req.stages, admission.low_priority_paused],
    );

    for (const job of candidates) {
      // Serialise acquirers of the same registrable domain, then re-check concurrency.
      const lock = await client.query<{ ok: boolean }>('SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0)) AS ok', [job.registrable_domain]);
      if (!lock.rows[0]?.ok) continue;
      const active = await client.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM jobs WHERE registrable_domain = $1 AND state IN ${ACTIVE_STATES} AND lease_expires_at > now()`,
        [job.registrable_domain],
      );
      if ((active.rows[0]?.n ?? 0) >= policy.limits.top_level_concurrency_per_domain) continue;

      if (!canRunStage(job, job.stage, policy)) {
        // Defensive: the router should never leave a job on a stage it cannot afford.
        await finishWithoutLease(client, job, 'FAILED_FINAL', job.outcome ?? 'INFRASTRUCTURE_DEFERRED', `budget exhausted before stage ${job.stage}`);
        continue;
      }

      let permitSlot: number | null = null;
      if (req.needsBrowserPermit) {
        if (isAlternateStage(job.stage)) {
          await client.query('SELECT pg_advisory_xact_lock($1)', [ALTERNATE_PERMIT_LOCK]);
          const alt = await client.query<{ n: number }>(
            `SELECT count(*)::int AS n FROM global_permits WHERE holder_job_id IS NOT NULL AND expires_at > now() AND adapter LIKE 'alternate:%'`,
          );
          if ((alt.rows[0]?.n ?? 0) >= policy.limits.alternate_browser_slots_max) return null;
        }
        const permit = await client.query<{ slot: number }>(
          `SELECT slot FROM global_permits
            WHERE slot <= $1 AND (holder_job_id IS NULL OR expires_at < now())
            ORDER BY slot FOR UPDATE SKIP LOCKED LIMIT 1`,
          [policy.limits.browser_slots_global],
        );
        if (!permit.rows[0]) return null; // all browser permits busy: lease nothing
        permitSlot = permit.rows[0].slot;
      }

      const tokenRes = await client.query<{ token: number }>(`SELECT nextval('lease_token_seq')::bigint AS token`);
      const token = tokenRes.rows[0]!.token;
      const attemptId = randomUUID();
      const kind = stageKind(job.stage);
      const attemptSeconds = attemptSecondsFor(job, job.stage, policy);

      const upd = await client.query<JobRow>(
        `UPDATE jobs SET state = 'LEASED', lease_owner = $2, lease_token = $3,
            lease_expires_at = now() + make_interval(secs => $4), heartbeat_at = now(),
            http_attempts = http_attempts + CASE WHEN $5 = 'http' THEN 1 ELSE 0 END,
            browser_attempts = browser_attempts + CASE WHEN $5 = 'browser' THEN 1 ELSE 0 END,
            alternate_used = alternate_used OR $6,
            current_attempt_id = $7, updated_at = now()
          WHERE id = $1 RETURNING *`,
        [job.id, req.workerId, token, policy.queue.lease_seconds, kind, isAlternateStage(job.stage), attemptId],
      );
      const leasedJob = upd.rows[0]!;

      if (permitSlot !== null) {
        await client.query(
          `UPDATE global_permits SET holder_job_id = $2, holder_owner = $3, lease_token = $4, adapter = $5,
              acquired_at = now(), expires_at = now() + make_interval(secs => $6) WHERE slot = $1`,
          [permitSlot, job.id, req.workerId, token, `${isAlternateStage(job.stage) ? 'alternate' : 'primary'}:${req.adapter}`, policy.queue.lease_seconds],
        );
      }

      await client.query(
        `INSERT INTO domain_pacing (registrable_domain, next_allowed_at) VALUES ($1, now() + make_interval(secs => $2))
         ON CONFLICT (registrable_domain) DO UPDATE
           SET next_allowed_at = GREATEST(domain_pacing.next_allowed_at, EXCLUDED.next_allowed_at), updated_at = now()`,
        [job.registrable_domain, policy.limits.per_domain_delay_seconds],
      );

      const attemptNoRes = await client.query<{ n: number }>('SELECT count(*)::int + 1 AS n FROM attempts WHERE job_id = $1', [job.id]);
      const attemptNo = attemptNoRes.rows[0]!.n;
      await client.query(
        `INSERT INTO attempts (id, job_id, attempt_no, kind, engine, adapter, capture_variant, vantage, lease_token, worker_id, retention_class, settings)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [attemptId, job.id, attemptNo, kind, req.engine, req.adapter, job.capture_variant, req.vantage, token, req.workerId,
         job.retention_class, { stage: job.stage, attempt_seconds: attemptSeconds }],
      );

      const target = await client.query<TargetRow>('SELECT * FROM targets WHERE id = $1', [job.target_id]);
      await audit(client, req.workerId, 'lease_acquired', { token, stage: job.stage, permit_slot: permitSlot, attempt_seconds: attemptSeconds }, { jobId: job.id, attemptId });

      return {
        job: leasedJob,
        target: target.rows[0]!,
        token,
        workerId: req.workerId,
        stage: job.stage,
        permitSlot,
        attemptId,
        attemptNo,
        attemptSeconds,
        leasedAt: new Date(),
      } satisfies Lease;
    }
    return null;
  });
}

async function finishWithoutLease(client: PoolClient, job: JobRow, state: string, outcome: string, reason: string): Promise<void> {
  await client.query(
    `UPDATE jobs SET state = $2, stage = 'done', outcome = $3, outcome_reason = $4, finished_at = now(), updated_at = now() WHERE id = $1`,
    [job.id, state, outcome, reason],
  );
  await audit(client, 'queue', 'job_finished_without_lease', { state, outcome, reason }, { jobId: job.id });
}

/** Renew the job lease and its permit. Returns false when ownership was lost (fencing). */
export async function renewLease(pool: Pool, lease: Lease, leaseSeconds: number): Promise<boolean> {
  return withTransaction(pool, async (client) => {
    const res = await client.query(
      `UPDATE jobs SET lease_expires_at = now() + make_interval(secs => $3), heartbeat_at = now()
        WHERE id = $1 AND lease_token = $2 AND state IN ${ACTIVE_STATES}`,
      [lease.job.id, lease.token, leaseSeconds],
    );
    if (res.rowCount !== 1) return false;
    if (lease.permitSlot !== null) {
      const p = await client.query(
        `UPDATE global_permits SET expires_at = now() + make_interval(secs => $3) WHERE slot = $1 AND lease_token = $2`,
        [lease.permitSlot, lease.token, leaseSeconds],
      );
      if (p.rowCount !== 1) return false;
    }
    return true;
  });
}

export async function setLeasedState(pool: Pool, lease: Lease, state: 'CAPTURING' | 'FINALISING'): Promise<boolean> {
  const res = await pool.query(
    `UPDATE jobs SET state = $3, updated_at = now() WHERE id = $1 AND lease_token = $2 AND state IN ${ACTIVE_STATES}`,
    [lease.job.id, lease.token, state],
  );
  return res.rowCount === 1;
}

/**
 * Give back a lease before any target contact happened (e.g. graceful shutdown
 * or browser connection failure before navigation). The budget charge is
 * refunded because no visit took place; the attempt row is kept as interrupted.
 */
export async function releaseUnstarted(pool: Pool, lease: Lease, reason: string, retryDelaySeconds = 30): Promise<boolean> {
  return withTransaction(pool, async (client) => {
    const kind = stageKind(lease.stage);
    const res = await client.query(
      `UPDATE jobs SET state = 'QUEUED', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
          current_attempt_id = NULL, next_eligible_at = now() + make_interval(secs => $3), updated_at = now(),
          http_attempts = http_attempts - CASE WHEN $4 = 'http' THEN 1 ELSE 0 END,
          browser_attempts = browser_attempts - CASE WHEN $4 = 'browser' THEN 1 ELSE 0 END,
          alternate_used = CASE WHEN $5 THEN false ELSE alternate_used END
        WHERE id = $1 AND lease_token = $2 AND state IN ${ACTIVE_STATES}`,
      [lease.job.id, lease.token, retryDelaySeconds, kind, isAlternateStage(lease.stage)],
    );
    await client.query(
      `UPDATE attempts SET status = 'interrupted', error = $2, ended_at = now(), active_seconds = 0 WHERE id = $1 AND status = 'pending'`,
      [lease.attemptId, `released_before_target_contact: ${reason}`],
    );
    await releasePermit(client, lease);
    await audit(client, lease.workerId, 'lease_released_unstarted', { reason, token: lease.token }, { jobId: lease.job.id, attemptId: lease.attemptId });
    return res.rowCount === 1;
  });
}

async function releasePermit(client: Queryable, lease: Lease): Promise<void> {
  if (lease.permitSlot === null) return;
  await client.query(
    `UPDATE global_permits SET holder_job_id = NULL, holder_owner = NULL, lease_token = NULL, adapter = NULL,
        acquired_at = NULL, expires_at = NULL WHERE slot = $1 AND lease_token = $2`,
    [lease.permitSlot, lease.token],
  );
}

/** Release the browser permit while a job waits for something that needs no browser (operator, backoff). */
export async function releasePermitOnly(pool: Pool, lease: Lease): Promise<void> {
  await releasePermit(pool, lease);
}

export interface DomainEdgeInput {
  edgeType: string;
  fromUrl: string | null;
  toUrl: string;
  contacted: boolean;
  observedAt: string | null;
}

export interface AttemptResult {
  status: 'committed' | 'interrupted';
  manifest: AttemptManifest | null;
  manifestSha256: string | null;
  artifactDir: string | null;
  totalBytes: number;
  activeSeconds: number;
  engineVersion: string | null;
  userAgent: string | null;
  settings: Record<string, unknown>;
  error: string | null;
  edges: DomainEdgeInput[];
  sessionId?: string | null;
  decision: RouterDecision;
  /** HTTP body extraction is not applicable to some outcomes (e.g. DNS failure). */
  extractionApplicable: boolean;
}

function hostOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Commit an attempt and apply the router decision. Idempotent per attempt id.
 * The attempt's own evidence is always recorded; the job row is changed only
 * when the fencing token still matches.
 */
export async function commitAttempt(pool: Pool, policy: Policy, lease: Lease, result: AttemptResult): Promise<{ ownershipHeld: boolean }> {
  return withTransaction(pool, async (client) => {
    const existing = await client.query<{ status: string }>('SELECT status FROM attempts WHERE id = $1 FOR UPDATE', [lease.attemptId]);
    const prior = existing.rows[0]?.status;
    if (prior && prior !== 'pending' && prior !== 'interrupted') {
      return { ownershipHeld: prior === 'committed' }; // already committed: idempotent no-op
    }

    const own = await client.query<JobRow>(
      `SELECT * FROM jobs WHERE id = $1 AND lease_token = $2 AND state IN ${ACTIVE_STATES} FOR UPDATE`,
      [lease.job.id, lease.token],
    );
    const ownershipHeld = own.rows.length === 1;
    const m = result.manifest;
    const attemptStatus = result.status === 'interrupted' ? 'interrupted' : ownershipHeld ? 'committed' : 'committed_lease_lost';
    const retentionDays = policy.retention.classes[lease.job.retention_class] ?? null;

    await client.query(
      `UPDATE attempts SET status = $2, outcome = $3, classification = $4, error = $5, ended_at = now(),
          active_seconds = $6, artifact_dir = $7, manifest_sha256 = $8, total_bytes = $9,
          required_satisfied = $10, missing_required = $11, engine_version = $12, user_agent = $13,
          settings = settings || $14::jsonb, session_id = COALESCE($15, session_id),
          extraction_state = $16,
          expires_at = CASE WHEN $17::int IS NULL THEN NULL ELSE now() + make_interval(days => $17::int) END
        WHERE id = $1`,
      [lease.attemptId, attemptStatus, m?.outcome ?? null, m?.classification ?? null, result.error,
       result.activeSeconds, result.artifactDir, result.manifestSha256, result.totalBytes,
       m?.requiredSatisfied ?? false, m?.missingRequired ?? null, result.engineVersion, result.userAgent,
       result.settings, result.sessionId ?? null,
       result.artifactDir && result.extractionApplicable ? 'pending' : 'not_applicable', retentionDays],
    );

    if (m) {
      await client.query('DELETE FROM artifacts WHERE attempt_id = $1', [lease.attemptId]); // idempotent re-commit after reconcile
      for (const a of m.artifacts) {
        await client.query(
          `INSERT INTO artifacts (attempt_id, artifact_type, relative_path, size_bytes, sha256, observed_start, observed_end,
              creation_method, completeness, limitations, restricted, is_derivative, error, metadata)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [lease.attemptId, a.type, a.path, a.sizeBytes, a.sha256, a.observedStart, a.observedEnd, a.creationMethod,
           a.completeness, a.limitations, a.restricted ?? false, a.isDerivative ?? false, a.error ?? null, a.metadata ?? {}],
        );
      }
    }
    await client.query('DELETE FROM domain_edges WHERE attempt_id = $1', [lease.attemptId]);
    for (const e of result.edges) {
      await client.query(
        `INSERT INTO domain_edges (attempt_id, edge_type, from_url, to_url, from_host, to_host, contacted, observed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [lease.attemptId, e.edgeType, e.fromUrl, e.toUrl, hostOf(e.fromUrl), hostOf(e.toUrl), e.contacted, e.observedAt],
      );
    }

    if (!ownershipHeld) {
      await audit(client, lease.workerId, 'commit_after_lease_loss', { token: lease.token, attempt_status: attemptStatus }, { jobId: lease.job.id, attemptId: lease.attemptId });
      return { ownershipHeld };
    }

    await applyDecision(client, policy, own.rows[0]!, lease, result.decision, result.activeSeconds);
    await releasePermit(client, lease);
    await audit(client, lease.workerId, 'attempt_committed', {
      token: lease.token, outcome: m?.outcome, classification: m?.classification, decision: result.decision,
      required_satisfied: m?.requiredSatisfied, missing: m?.missingRequired,
    }, { jobId: lease.job.id, attemptId: lease.attemptId });
    return { ownershipHeld };
  });
}

async function applyDecision(client: PoolClient, policy: Policy, job: JobRow, lease: Lease, d: RouterDecision, activeSeconds: number): Promise<void> {
  const clearLease = `lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, current_attempt_id = NULL`;
  if (d.kind === 'finish') {
    await client.query(
      `UPDATE jobs SET state = $2, stage = 'done', outcome = $3, outcome_reason = $4, classification = $4,
          active_seconds_used = active_seconds_used + $5, finished_at = now(), updated_at = now(), ${clearLease}
        WHERE id = $1`,
      [job.id, d.state, d.outcome, d.reason, activeSeconds],
    );
    if (d.spawnSchemeFallback) await spawnSchemeFallback(client, policy, job, lease);
    return;
  }
  await client.query(
    `UPDATE jobs SET state = $2, stage = $3, outcome = COALESCE($4, outcome), outcome_reason = $5, classification = $5,
        active_seconds_used = active_seconds_used + $6, next_eligible_at = now() + make_interval(secs => $7),
        updated_at = now(), ${clearLease}
      WHERE id = $1`,
    [job.id, d.state, d.stage, d.outcome, d.reason, activeSeconds, d.delaySeconds],
  );
  if (d.domainBackoffSeconds && d.domainBackoffSeconds > 0) {
    await client.query(
      `INSERT INTO domain_pacing (registrable_domain, next_allowed_at, backoff_level) VALUES ($1, now() + make_interval(secs => $2), 1)
       ON CONFLICT (registrable_domain) DO UPDATE
         SET next_allowed_at = GREATEST(domain_pacing.next_allowed_at, EXCLUDED.next_allowed_at),
             backoff_level = domain_pacing.backoff_level + 1, updated_at = now()`,
      [job.registrable_domain, d.domainBackoffSeconds],
    );
  }
}

/**
 * HTTPS candidate of a domain-only seed failed at the connection/TLS level:
 * schedule the HTTP candidate as its own job so it is a separately recorded
 * attempt and never relabelled as the HTTPS observation (§6).
 */
async function spawnSchemeFallback(client: PoolClient, policy: Policy, job: JobRow, lease: Lease): Promise<void> {
  const ids = job.scope.scheme_fallback_target_ids ?? [];
  const nextTarget = ids[0];
  if (!nextTarget) return;
  const ins = await client.query<{ id: number }>(
    `INSERT INTO jobs (target_id, parent_job_id, profile, window_key, registrable_domain, priority, urgent, required_artifacts,
        capture_variant, scope, allowed_interactions, retention_class, case_ref, deadline, stage)
     SELECT $2, j.id, j.profile, j.window_key, j.registrable_domain, j.priority, j.urgent, j.required_artifacts,
        j.capture_variant, jsonb_set(j.scope, '{scheme_fallback_target_ids}', to_jsonb($3::bigint[])) || '{"scheme_fallback_of_job": true}'::jsonb,
        j.allowed_interactions, j.retention_class, j.case_ref, j.deadline,
        CASE WHEN j.profile = 'data_triage' OR (NOT j.urgent AND $4::int > 0) THEN 'http'::job_stage ELSE 'browser_primary'::job_stage END
       FROM jobs j WHERE j.id = $1
     RETURNING id`,
    [job.id, nextTarget, ids.slice(1), policy.limits.http_attempts_max],
  );
  const childId = ins.rows[0]?.id;
  if (childId) {
    await client.query('INSERT INTO job_sources (job_id, source_record_id) SELECT $2, source_record_id FROM job_sources WHERE job_id = $1 ON CONFLICT DO NOTHING', [job.id, childId]);
    await audit(client, lease.workerId, 'scheme_fallback_job_created', { parent_job_id: job.id, target_id: nextTarget }, { jobId: childId });
  }
}

/**
 * Reclaim jobs whose lease expired (worker crash, OOM, partition). The open
 * attempt is recorded as interrupted; the job goes back to the queue when its
 * budget allows, otherwise it ends as infrastructure-deferred (§8 table).
 */
export async function reclaimExpiredLeases(pool: Pool, policy: Policy, actor = 'reclaimer'): Promise<number> {
  return withTransaction(pool, async (client) => {
    const { rows } = await client.query<JobRow>(
      `SELECT * FROM jobs WHERE state IN ${ACTIVE_STATES} AND lease_expires_at < now() FOR UPDATE SKIP LOCKED LIMIT 100`,
    );
    for (const job of rows) {
      let spent = 0;
      if (job.current_attempt_id) {
        const att = await client.query<{ secs: number }>(
          `UPDATE attempts SET status = 'interrupted', ended_at = now(),
              error = COALESCE(error, 'lease_expired: worker lost or stalled'),
              active_seconds = LEAST(EXTRACT(EPOCH FROM now() - started_at), $2)
            WHERE id = $1 AND status = 'pending' RETURNING active_seconds AS secs`,
          [job.current_attempt_id, attemptSecondsFor(job, job.stage, policy) || policy.limits.alternate_browser_seconds],
        );
        spent = att.rows[0]?.secs ?? 0;
      }
      const after = { ...job, active_seconds_used: job.active_seconds_used + spent };
      const canRetry = canRunStage(after, job.stage, policy)
        || (job.stage === 'http' && job.profile === 'browser_evidence' && canRunStage(after, 'browser_primary', policy));
      const nextStage: JobStage = canRunStage(after, job.stage, policy) ? job.stage : 'browser_primary';
      if (canRetry) {
        await client.query(
          `UPDATE jobs SET state = 'QUEUED', stage = $2, outcome = 'INFRASTRUCTURE_DEFERRED',
              outcome_reason = 'worker lost lease; requeued', active_seconds_used = active_seconds_used + $3,
              next_eligible_at = now() + interval '30 seconds', lease_owner = NULL, lease_token = NULL,
              lease_expires_at = NULL, current_attempt_id = NULL, updated_at = now() WHERE id = $1`,
          [job.id, nextStage, spent],
        );
      } else {
        await client.query(
          `UPDATE jobs SET state = 'FAILED_FINAL', stage = 'done', outcome = 'INFRASTRUCTURE_DEFERRED',
              outcome_reason = 'worker lost lease and attempt budget exhausted', active_seconds_used = active_seconds_used + $2,
              lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, current_attempt_id = NULL,
              finished_at = now(), updated_at = now() WHERE id = $1`,
          [job.id, spent],
        );
      }
      await client.query(
        `UPDATE global_permits SET holder_job_id = NULL, holder_owner = NULL, lease_token = NULL, adapter = NULL,
            acquired_at = NULL, expires_at = NULL WHERE holder_job_id = $1 AND lease_token = $2`,
        [job.id, job.lease_token],
      );
      await audit(client, actor, 'lease_reclaimed', { token: job.lease_token, owner: job.lease_owner, requeued: canRetry, spent_seconds: spent }, { jobId: job.id, attemptId: job.current_attempt_id });
    }
    // Permits whose holder vanished without a matching job lease.
    await client.query(
      `UPDATE global_permits SET holder_job_id = NULL, holder_owner = NULL, lease_token = NULL, adapter = NULL,
          acquired_at = NULL, expires_at = NULL WHERE holder_job_id IS NOT NULL AND expires_at < now()`,
    );
    return rows.length;
  });
}
