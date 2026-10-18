# cyber-web-collector

Evidence-grade web collection for cybercrime investigation. This is an implementation of
[`docs/blueprint.md`](docs/blueprint.md) (*Cybercrime Web Collection — Final Deployment Blueprint* v3.0, 17 Oct 2026),
extended for the *Final Implementation Blueprint v4* and the *v0.3 Improvement Checklist*. Item-by-item status:
[`docs/checklist-v0.3-status.md`](docs/checklist-v0.3-status.md).

The system has the following parts:

- **Crawlee + Playwright** is the primary collection system. Crawlee's `AutoscaledPool`
  orchestrates the work and the code owns each Playwright context explicitly.
- **PostgreSQL** is the authoritative job ledger. It handles leases with fencing tokens,
  global browser permits and a shared attempt budget.
- **A controlled egress gateway** checks each destination when it connects. It denies
  private, loopback, link-local, metadata and IPv4-mapped addresses and pins each name to
  the address it resolved, which defeats DNS rebinding.
- **An immutable artifact store** writes each attempt to its own directory, hashes the
  saved files with SHA-256, adds a manifest and moves the directory into place with an
  atomic rename. Crash reconciliation covers the gap between the filesystem and the database.
- **One optional Scrapling adapter** is disabled by default. It uses the same job/result
  contract and the same caps as the primary path.
- **Deterministic extraction** runs only after the originals are saved: DOM and attributes
  first, then JSON, then QR decoding, then selective OCR. AI is not used. Paid APIs and
  hosted classifiers are absent. Every identifier keeps its provenance, extractor version,
  confidence and review state.
- **Evidence integrity and custody**: manifests re-verified after commit, a hash-chained
  append-only custody log with signed checkpoints, a *Verify Evidence* action and evidence
  packages with a separately recorded index hash.
- **An analyst console** (optional Compose profile `console`, loopback only, reached through an
  SSH tunnel). It provides MFA sign-in, case-scoped access, intake, a single-target investigation
  view, review queues, false-positive suppression and scoped correlation. It also covers legally
  routed notice drafts with maker-checker and proof-backed issuance records, Section 63 worksheets,
  monitoring revisits and trustworthy analytics. Nothing is ever sent, signed or taken down by the
  system. API reference: [`docs/openapi.json`](docs/openapi.json).

> **Status.** The code, migrations, container definitions and tests in this repository are complete
> for the baseline profile. The system **has not been deployed or benchmarked on the target VM**.
> [`docs/deployment-readiness.md`](docs/deployment-readiness.md) lists every requirement that can only
> be met on the real machine (preflight, cgroup delegation, sandbox verification, pilot, 24-hour run,
> independent backup). Do not label the deployment ready until that list is closed.

No software combination guarantees retrieval from every website. Each job ends with an explicit
outcome, for example `CONTENT_CAPTURED`, `CHALLENGE_PAGE_CAPTURED`, `ACCESS_BLOCKED`, `AUTH_REQUIRED`,
`DNS_FAILURE`, `TLS_FAILURE`, `NOT_FOUND`, `ORIGIN_UNAVAILABLE` or `INFRASTRUCTURE_DEFERRED`. The
design aims for zero silent result loss. It does not promise 100% retrieval.

## Repository layout

| Path | Contents |
|---|---|
| `src/config/` | Policy schema (§14) with validation and cross-field rules |
| `src/importer/` | CSV/JSONL importer, exact-URL handling, IDNA, PSL grouping, rejection reasons (§6) |
| `src/queue/` | Leases, fencing, permits, per-domain pacing, idempotent commits, reclaim (§12) |
| `src/router/` | Challenge/auth/JS-shell signals, failure-specific router, shared budget (§8) |
| `src/acquisition/` | Task contract, HTTP triage, egress client, generic leased-attempt runner (§7) |
| `src/capture/` | Staged screenshots, network/page recorder, element crops, image checks (§9–§10) |
| `src/worker/` | Browser driver worker (Crawlee AutoscaledPool), browser connection pool |
| `src/coordinator/` | Coordinator service, HTTP triage loop, reconciler, admission control, retention |
| `src/extraction/` | Identifiers and validators, QR, OCR, child-page jobs (§11) |
| `src/gateway/` | Egress gateway (forward proxy with destination policy) (§13) |
| `src/export/`, `src/observability/` | Daily JSONL/CSV export, status metrics, health and watchdog (§16) |
| `src/evidence/` | Canonical JSON, IST time, manifest context, custody chain, Verify Evidence, packages (v4 §20–21) |
| `src/investigation/` | Decisions and suppression, brands and lookalikes, explainable risk, correlation (v4 §22, §25) |
| `src/actions/` | Legal routes and eligibility, report rendering, Section 63 worksheets (v4 §24, §26) |
| `src/monitoring/`, `src/enrichment/` | Revisits, change classification, reappearance alerts; DNS/TLS/RDAP through the gateway |
| `src/web/`, `web/` | Analyst API (router, auth, authorisation, routes, OpenAPI docs) and the strict-CSP console |
| `db/migrations/` | Forward-only, checksum-verified SQL migrations |
| `config/` | `policy.default.yaml`, generated `policy.schema.json`, `brands.yaml` (official domains for lookalike checks) |
| `docker/`, `compose.yaml` | Pinned images, Chromium seccomp profile, isolated Compose project |
| `scrapling-worker/` | Optional Python Scrapling adapter (same contract) |
| `scripts/` | Preflight, secrets, host directories, backup, restore verification, test DB |
| `test/` | Unit tests, integration tests and local controlled fixtures |
| `docs/` | Architecture, configuration, runbook, security, recovery, rollback, acceptance, pilot, benchmark |

## Quick start on the target VM

Read [`docs/runbook.md`](docs/runbook.md) first. The short version:

```bash
scripts/preflight.sh --context rootless --data-dir /srv/cyber-web-collector > compatibility-record.md
cp .env.example .env                        # set COLLECTOR_DATA_DIR, BROWSER_SERVER_PATH (openssl rand -hex 24)
cp config/policy.yaml.example config/policy.yaml
scripts/init-secrets.sh                     # Compose secret files, mode 0600
docker --context rootless compose -p cyber-web-collector config
docker --context rootless compose -p cyber-web-collector build
scripts/prepare-host-dirs.sh --context rootless
docker --context rootless compose -p cyber-web-collector up -d --scale browser-worker=1
docker --context rootless compose -p cyber-web-collector ps
```

Operator CLI (inside the coordinator container; input files go under `$COLLECTOR_DATA_DIR/input`, mounted read-only at `/input`):

```bash
DC="docker --context rootless compose -p cyber-web-collector"
$DC exec coordinator node dist/cli.js import /input/urls.csv --profile browser_evidence
$DC exec coordinator node dist/cli.js status
$DC exec coordinator node dist/cli.js job 42
$DC exec coordinator node dist/cli.js export --date 2026-10-17 --format jsonl
$DC exec coordinator node dist/cli.js verify <attempt-uuid>
```

Full command reference: [`docs/runbook.md#cli-contract`](docs/runbook.md#cli-contract).

Analyst console (optional; runbook §2 "Analyst console"):

```bash
$DC --profile console up -d api
$DC exec api node dist/cli.js user create --username admin.one --display-name "Admin One" --roles admin,auditor
ssh -N -L 8080:127.0.0.1:8080 operator@collector-vm   # on the workstation, then open http://localhost:8080
```

## Development

Requires Node.js 22.19+ (pinned 22.22.0), PostgreSQL 16 binaries for integration tests, and the
Chromium build that matches `playwright-core@1.56.1`.

```bash
npm ci
npm run typecheck && npm run build
npm run test:unit
export TEST_DATABASE_URL=$(scripts/test-postgres.sh)   # throwaway local cluster
PLAYWRIGHT_BROWSERS_PATH=/path/to/browsers npm test     # unit and integration tests
python3 -I scrapling-worker/tests/test_contract.py -v
npm run schema                                          # regenerate config/policy.schema.json
npm run openapi                                         # regenerate docs/openapi.json from the routes
API_BIND=127.0.0.1 npx tsx src/cli.ts serve api         # console at http://127.0.0.1:8080 (needs DATABASE_URL)
```

Integration suites skip themselves when `TEST_DATABASE_URL` or `PLAYWRIGHT_BROWSERS_PATH` is unset.
They use only local fixtures (`test/fixtures/server.ts`) and never contact unrelated live sites.

## Licence

The project licence has not been chosen yet (see `NOTICE`). Third-party licences are listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
