# Operator runbook

All commands assume the rootless Docker context is called `rootless`. If `docker context ls`
shows a different name, use that name instead. Throughout this runbook:

```bash
DC="docker --context rootless compose -p cyber-web-collector"
CLI="$DC exec coordinator node dist/cli.js"
```

## 1. Preflight (Phase A) — before anything else

```bash
scripts/preflight.sh --context rootless --data-dir /srv/cyber-web-collector > compatibility-record.md
```

The script only reads the host. It records the OS, CPU, load, I/O wait and steal (`vmstat`),
memory and swap, filesystems, GPU, cgroup v2 and delegated controllers, user-namespace sysctls,
Docker contexts and existing Compose projects, listening ports, user lingering, free space at the
data directory and the backup destination. It ends with **Blockers** and **Warnings**. Copy the
result into `docs/deployment-readiness.md` (section *Compatibility record*). Also record the CPU,
memory and disk allocation you have actually been granted, and the services that must be
preserved. Pass `--check-public-ip` only if you accept a request to `api.ipify.org`.

Do not continue past a blocker. In particular, do not disable the Chromium sandbox and do not
take resources from other projects.

### cgroup delegation

Compose `cpus`, `mem_limit` and `pids_limit` only take effect under rootless Docker if cgroup v2
delegates the `cpu`, `memory` and `pids` controllers to your user. Changing systemd delegation
is a host change: agree it with the host owner first. Docker's rootless documentation
(<https://docs.docker.com/engine/security/rootless/>, "Limiting resources") describes the
`Delegate=` drop-in. If delegation is impossible, document that the caps are not enforced,
lower `browser_slots_global` to 1 and watch the host with `vmstat`.

### Start on boot

The rootless daemon must survive logout: `loginctl enable-linger <user>` (subject to the host's
service policy) and `systemctl --user enable docker`. Every service uses
`restart: unless-stopped`, so containers come back when the daemon does.

## 2. First deployment

```bash
cp .env.example .env            # COLLECTOR_DATA_DIR, BROWSER_SERVER_PATH=$(openssl rand -hex 24), GATEWAY_EXTRA_DENY_CIDRS
cp config/policy.yaml.example config/policy.yaml
scripts/init-secrets.sh         # secrets/{postgres_superuser_password,collector_db_password,scrapling_db_password}
$DC config --quiet              # validates interpolation, secrets, networks
$DC build
scripts/prepare-host-dirs.sh --context rootless
$DC run --rm --no-deps coordinator validate-policy /app/config/policy.yaml
$DC up -d --scale browser-worker=1
$DC ps                           # all healthy within ~1 minute
$CLI status
```

Add this VM's own public address, and any provider metadata or management ranges that the
built-in list does not cover, to `GATEWAY_EXTRA_DENY_CIDRS`.

### Post-deployment verification

1. **Network isolation.** Run `docker --context rootless network inspect cyber-web-collector_acquisition`
   and check that `Internal` is `true`. The engine container must not be able to resolve or reach
   the Internet directly:
   `$DC exec browser-engine node -e "require('dns').lookup('example.com',e=>console.log(e?e.code:'RESOLVED'))"`
   should print an error code.
2. **Gateway refusals.** Import a fixture list that points at internal targets (for example
   `http://169.254.169.254/`, `http://127.0.0.1/`, `http://[::ffff:10.0.0.1]/`). Each job must
   end in `MANUAL_REVIEW` with the classification `egress_denied`.
3. **Sandbox.** Follow [`security.md#sandbox-verification`](security.md#sandbox-verification).
4. **Canaries.** See section 6.

## 3. Daily operation

| Task | Command |
|---|---|
| Import targets | Put the file in `$COLLECTOR_DATA_DIR/input/`, then `$CLI import /input/urls.csv --profile browser_evidence [--window 2026-10-17] [--by analyst-id]` |
| Status, metrics, admission | `$CLI status [--hours 24]` |
| One job, its attempts and identifiers | `$CLI job <id>` |
| Jobs needing attention | `$CLI manual-review` |
| Revisit in a new window | `$CLI requeue <id> --new-window 2026-10-18 [--stage http\|browser_primary] [--relaxed-tls]` |
| Daily export (automatic at ~00:10 UTC for the previous day) | `$CLI export --date 2026-10-17 --format jsonl\|csv` |
| Integrity check of one attempt | `$CLI verify <attempt-uuid>` |
| Record a fraud assessment | `$CLI finding <job-id> --assessment suspected_fraud --rationale "..." --evidence '["<attempt-uuid>"]'` |
| Case hold | `$CLI case-hold place CASE-114 --reason "court order 12/2026"` / `$CLI case-hold release CASE-114` |
| Retention report or deletion | `$CLI retention` (report) / `$CLI retention --delete` |
| Reconcile now | `$CLI reconcile` |
| Logs | `$DC logs -f --tail 200 coordinator browser-worker egress-gateway` |

Outputs: attempt directories are under `$COLLECTOR_DATA_DIR/artifacts/captures/YYYY/MM/DD/<attempt-uuid>/`,
derived data under `artifacts/derived/<attempt-uuid>/`, and exports under `artifacts/exports/<date>/`.

### Reading outcomes

* `state` is the processing state: `COMPLETE`, `PARTIAL`, `DEFERRED`, `MANUAL_REVIEW`, `FAILED_FINAL`.
* `outcome` is what was observed at the target. `COMPLETE` always means `CONTENT_CAPTURED` with
  the required artifacts validated.
* `CHALLENGE_PAGE_CAPTURED` / `MANUAL_REVIEW` means the challenge screenshot is valid evidence
  **of the challenge**, not of the target content.
* `INFRASTRUCTURE_DEFERRED` means the attempt budget was used up by the collector's own
  failures. It is **not** evidence that the origin is offline. Requeue it in a new window once
  the infrastructure is healthy.
* Identifier field status `not_observed` (a legitimate absence) is different from
  `extraction_failed`. A missing identifier does not make a page benign.

### Operator-assisted sessions

Interactive operator-assisted capture (release the permits while waiting for the operator, then
re-acquire one for the live session) is **not implemented** in this release. Jobs needing login,
OTP or challenge completion end in `MANUAL_REVIEW` and keep their evidence. See
`docs/deployment-readiness.md`.

## 4. Admission control and backpressure

The coordinator re-evaluates admission every 30 s (`system_state.admission`):

* free space at `ARTIFACT_ROOT` below **30 GB** pauses all new leases. Leasing resumes only
  above **40 GB**;
* retained capture bytes at or above **80 GB** pause low-priority work (only urgent jobs are
  leased);
* an unhealthy gateway pauses all leasing. There is never an unprotected fallback.

In-flight attempts finish within their own deadline. Running out of storage is handled by
deferring or pausing. Case-hold evidence is never deleted silently.

## 5. Failure handling

| Symptom | What happens automatically | Operator action |
|---|---|---|
| Worker or browser crash, OOM | The lease expires after ≤ 120 s. The reclaimer records the attempt as interrupted and requeues the job, or ends it as `INFRASTRUCTURE_DEFERRED`. The watchdog exits a stuck process and Compose restarts it | Check `$CLI status` → `integrity`. If it repeats, lower `browser_slots_global` |
| Crash between directory rename and DB commit | The reconciler verifies the manifest hashes and records the attempt as `recovered` | None. Audit event `orphan_final_directory_recovered` |
| Crash mid-write | `tmp/<uuid>` is salvaged into `incomplete/` with a manifest of what exists | None |
| Database outage | Workers stop leasing. Heartbeats retry. Commits that fail are recovered by the reconciler | Restore the DB and check `$CLI status` |
| Disk full | Admission pauses. Writers are bounded per attempt | Free space, add storage, or move held cases to approved independent storage |
| Gateway down | Admission pauses | `$DC restart egress-gateway`, check its logs |
| Unknown directory under `captures/` | Reported (`orphan_directory_without_attempt_row`), never deleted | Investigate by hand |

## 6. Canaries (§16)

Run controlled canaries separately from live targets: simple static HTML, JS hydration, a QR or
element screenshot, and the network recorder. In development they are the fixture tests
(`npm run test:integration`). On the VM, host equivalent pages on an approved public URL you
control, import them daily with `--window canary-YYYY-MM-DD`, and alert if any canary does not
end `COMPLETE`. A failing live target is not a reason to restart workers globally.

## 7. Upgrades

See [`rollback.md`](rollback.md). Never use `down -v`, and never delete
`$COLLECTOR_DATA_DIR/postgres` or `artifacts` as part of an upgrade or rollback.

## CLI contract

`node dist/cli.js <command>`. All output is JSON on stdout. Errors go to stderr with a non-zero exit code.

| Command | Arguments / options |
|---|---|
| `validate-policy [path]` | Validates and prints the resolved policy |
| `migrate` | Applies migrations and syncs permit slots |
| `serve <coordinator\|browser-worker\|gateway>` | Long-running service roles (Compose `command`) |
| `import <file>` | `--profile data_triage\|browser_evidence`, `--window <key>`, `--format csv\|jsonl`, `--by <actor>` |
| `export` | `--date YYYY-MM-DD`, `--format jsonl\|csv` |
| `status` | `--hours <n>` |
| `job <id>` | — |
| `requeue <id>` | `--new-window <key>` (required), `--stage`, `--relaxed-tls`, `--by` |
| `manual-review` | — |
| `case-hold place <case>` / `case-hold release <case>` | `--reason`, `--by` |
| `finding <job-id>` | `--assessment`, `--rationale`, `--evidence <json>`, `--by` |
| `reconcile` | — |
| `retention` | `--delete` |
| `verify <attempt-id>` | — |
| `backup record` / `backup status` | `--destination`, `--independent yes\|no`, `--note` |
| `healthcheck` | `--port` (Docker healthcheck) |
