"""Ledger access for the Scrapling adapter: the same lease/fencing/commit
semantics as src/queue/queue.ts, restricted to stage 'scrapling'."""
from __future__ import annotations

import json
import os
import uuid
from typing import Any

import psycopg
from psycopg.rows import dict_row

ACTIVE = "('LEASED','CAPTURING','FINALISING')"


def connect() -> psycopg.Connection:
    pw_file = os.environ.get("PGPASSWORD_FILE")
    password = open(pw_file, encoding="utf-8").read().strip() if pw_file else os.environ.get("PGPASSWORD")
    return psycopg.connect(
        host=os.environ["PGHOST"], port=int(os.environ.get("PGPORT", "5432")), user=os.environ["PGUSER"],
        dbname=os.environ["PGDATABASE"], password=password, autocommit=False, row_factory=dict_row,
        options="-c statement_timeout=30000 -c idle_in_transaction_session_timeout=30000",
        application_name="cyber-web-collector:scrapling-worker",
    )


def audit(cur, actor: str, event: str, details: dict[str, Any], job_id=None, attempt_id=None) -> None:
    cur.execute("INSERT INTO audit_events (actor, event_type, job_id, attempt_id, details) VALUES (%s,%s,%s,%s,%s)",
                (actor, event, job_id, attempt_id, json.dumps(details)))


def lease(conn, policy: dict[str, Any], worker_id: str, vantage: str) -> dict[str, Any] | None:
    lim = policy["limits"]
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("SELECT value FROM system_state WHERE key = 'admission'")
        adm = (cur.fetchone() or {}).get("value") or {}
        if adm.get("paused"):
            return None
        cur.execute(
            f"""SELECT j.*, t.url FROM jobs j JOIN targets t ON t.id = j.target_id
                 WHERE j.state IN ('QUEUED','DEFERRED') AND j.stage = 'scrapling' AND j.next_eligible_at <= now()
                   AND (%s = false OR j.urgent)
                   AND NOT EXISTS (SELECT 1 FROM domain_pacing d WHERE d.registrable_domain = j.registrable_domain AND d.next_allowed_at > now())
                 ORDER BY j.urgent DESC, j.priority DESC, j.next_eligible_at, j.id
                 FOR UPDATE OF j SKIP LOCKED LIMIT 5""",
            (bool(adm.get("low_priority_paused")),),
        )
        for job in cur.fetchall():
            cur.execute("SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0)) AS ok", (job["registrable_domain"],))
            if not cur.fetchone()["ok"]:
                continue
            cur.execute(f"SELECT count(*) AS n FROM jobs WHERE registrable_domain = %s AND state IN {ACTIVE} AND lease_expires_at > now()",
                        (job["registrable_domain"],))
            if cur.fetchone()["n"] >= lim["top_level_concurrency_per_domain"]:
                continue
            if job["browser_attempts"] >= lim["browser_attempts_max"] or job["alternate_used"] \
                    or job["http_attempts"] + job["browser_attempts"] >= lim["acquisition_attempts_max"]:
                continue
            cur.execute("SELECT pg_advisory_xact_lock(727274002)")
            cur.execute("SELECT count(*) AS n FROM global_permits WHERE holder_job_id IS NOT NULL AND expires_at > now() AND adapter LIKE 'alternate:%%'")
            if cur.fetchone()["n"] >= lim["alternate_browser_slots_max"]:
                return None
            cur.execute("""SELECT slot FROM global_permits WHERE slot <= %s AND (holder_job_id IS NULL OR expires_at < now())
                           ORDER BY slot FOR UPDATE SKIP LOCKED LIMIT 1""", (lim["browser_slots_global"],))
            permit = cur.fetchone()
            if not permit:
                return None
            cur.execute("SELECT nextval('lease_token_seq') AS t")
            token = cur.fetchone()["t"]
            attempt_id = str(uuid.uuid4())
            remaining = lim["active_acquisition_seconds_max"] - job["active_seconds_used"]
            seconds = max(0, min(lim["alternate_browser_seconds"], remaining))
            lease_s = policy["queue"]["lease_seconds"]
            cur.execute("""UPDATE jobs SET state='LEASED', lease_owner=%s, lease_token=%s, lease_expires_at = now() + make_interval(secs => %s),
                             heartbeat_at = now(), browser_attempts = browser_attempts + 1, alternate_used = true,
                             current_attempt_id = %s, updated_at = now() WHERE id = %s""",
                        (worker_id, token, lease_s, attempt_id, job["id"]))
            cur.execute("""UPDATE global_permits SET holder_job_id=%s, holder_owner=%s, lease_token=%s, adapter='alternate:scrapling',
                             acquired_at=now(), expires_at = now() + make_interval(secs => %s) WHERE slot=%s""",
                        (job["id"], worker_id, token, lease_s, permit["slot"]))
            cur.execute("""INSERT INTO domain_pacing (registrable_domain, next_allowed_at) VALUES (%s, now() + make_interval(secs => %s))
                           ON CONFLICT (registrable_domain) DO UPDATE SET next_allowed_at = GREATEST(domain_pacing.next_allowed_at, EXCLUDED.next_allowed_at)""",
                        (job["registrable_domain"], lim["per_domain_delay_seconds"]))
            cur.execute("SELECT count(*) + 1 AS n FROM attempts WHERE job_id = %s", (job["id"],))
            attempt_no = cur.fetchone()["n"]
            cur.execute("""INSERT INTO attempts (id, job_id, attempt_no, kind, engine, adapter, capture_variant, vantage, lease_token, worker_id, retention_class, settings)
                           VALUES (%s,%s,%s,'browser','scrapling-dynamic','scrapling',%s,%s,%s,%s,%s,%s)""",
                        (attempt_id, job["id"], attempt_no, job["capture_variant"], vantage, token, worker_id, job["retention_class"],
                         json.dumps({"stage": "scrapling", "attempt_seconds": seconds})))
            audit(cur, worker_id, "lease_acquired", {"token": token, "stage": "scrapling", "permit_slot": permit["slot"]}, job["id"], attempt_id)
            return {"job": job, "token": token, "permit": permit["slot"], "attempt_id": attempt_id, "attempt_no": attempt_no, "seconds": seconds}
    return None


def renew(conn, lease_: dict[str, Any], lease_seconds: float) -> bool:
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(f"""UPDATE jobs SET lease_expires_at = now() + make_interval(secs => %s), heartbeat_at = now()
                        WHERE id = %s AND lease_token = %s AND state IN {ACTIVE}""", (lease_seconds, lease_["job"]["id"], lease_["token"]))
        if cur.rowcount != 1:
            return False
        cur.execute("UPDATE global_permits SET expires_at = now() + make_interval(secs => %s) WHERE slot = %s AND lease_token = %s",
                    (lease_seconds, lease_["permit"], lease_["token"]))
        return cur.rowcount == 1


def commit(conn, lease_: dict[str, Any], manifest: dict[str, Any] | None, manifest_sha: str | None, rel_dir: str | None,
           total_bytes: int, active_seconds: float, decision: dict[str, Any], error: str | None, retention_days: int | None) -> bool:
    job_id, token, attempt_id = lease_["job"]["id"], lease_["token"], lease_["attempt_id"]
    with conn.transaction(), conn.cursor() as cur:
        # Lock order jobs -> attempts, identical to the TypeScript queue and reclaimer (no deadlock).
        cur.execute("SELECT lease_token, state FROM jobs WHERE id = %s FOR UPDATE", (job_id,))
        job = cur.fetchone()
        cur.execute("SELECT status FROM attempts WHERE id = %s FOR UPDATE", (attempt_id,))
        row = cur.fetchone()
        if row and row["status"] not in ("pending", "interrupted"):
            return row["status"] == "committed"
        held = bool(job and job["lease_token"] == token and job["state"] in ("LEASED", "CAPTURING", "FINALISING"))
        status = "interrupted" if error else ("committed" if held else "committed_lease_lost")
        cur.execute("""UPDATE attempts SET status=%s, outcome=%s, classification=%s, error=%s, ended_at=now(), active_seconds=%s,
                         artifact_dir=%s, manifest_sha256=%s, total_bytes=%s, required_satisfied=%s, missing_required=%s,
                         engine_version=%s, extraction_state=%s,
                         expires_at = CASE WHEN %s::int IS NULL THEN NULL ELSE now() + make_interval(days => %s::int) END
                       WHERE id=%s""",
                    (status, manifest and manifest["outcome"], manifest and manifest["classification"], error, active_seconds, rel_dir,
                     manifest_sha, total_bytes, bool(manifest and manifest["requiredSatisfied"]), manifest and manifest["missingRequired"],
                     manifest and manifest.get("engineVersion"), "pending" if rel_dir and not error else "not_applicable",
                     retention_days, retention_days, attempt_id))
        if manifest:
            cur.execute("DELETE FROM artifacts WHERE attempt_id = %s", (attempt_id,))
            for a in manifest["artifacts"]:
                cur.execute("""INSERT INTO artifacts (attempt_id, artifact_type, relative_path, size_bytes, sha256, observed_start, observed_end,
                                 creation_method, completeness, limitations, restricted, error, metadata)
                               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                            (attempt_id, a["type"], a.get("path"), a.get("sizeBytes"), a.get("sha256"), a.get("observedStart"), a.get("observedEnd"),
                             a["creationMethod"], a["completeness"], a.get("limitations", []), bool(a.get("restricted")), a.get("error"),
                             json.dumps(a.get("metadata", {}))))
        if not held:
            audit(cur, "scrapling-worker", "commit_after_lease_loss", {"token": token}, job_id, attempt_id)
            return False
        cur.execute("""UPDATE jobs SET state=%s, stage='done', outcome=%s, outcome_reason=%s, classification=%s,
                         active_seconds_used = active_seconds_used + %s, finished_at=now(), updated_at=now(),
                         lease_owner=NULL, lease_token=NULL, lease_expires_at=NULL, current_attempt_id=NULL WHERE id=%s""",
                    (decision["state"], decision["outcome"], decision["reason"], decision["reason"], active_seconds, job_id))
        cur.execute("""UPDATE global_permits SET holder_job_id=NULL, holder_owner=NULL, lease_token=NULL, adapter=NULL, acquired_at=NULL, expires_at=NULL
                       WHERE slot=%s AND lease_token=%s""", (lease_["permit"], token))
        audit(cur, "scrapling-worker", "attempt_committed", {"token": token, "decision": decision}, job_id, attempt_id)
        return True
