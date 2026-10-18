# Architecture

This document maps the implementation onto the blueprint. Section numbers (§) refer to [`blueprint.md`](blueprint.md).

## Components and responsibilities (§4, §5)

| Service | Code | Responsibility | Networks | Memory / CPU cap |
|---|---|---|---|---|
| `coordinator` | `src/coordinator/main.ts` | Migrations, reconciliation, admission control, HTTP triage (`AutoscaledPool`, ≤ 8), extraction (QR, OCR serialised), retention, daily export, liveness | control, triage | 1.5 GiB / 0.3 |
| `browser-worker` (1 replica) | `src/worker/` | Leases browser jobs and global permits; drives the **remote** engine over a private Playwright connection; owns each context; writes artifacts | control, acquisition | 0.75 GiB / 0.1 |
| `browser-engine` | `docker/browser-engine.Dockerfile` | `playwright run-server` with sandboxed Chromium (and Firefox for the one alternate attempt); no DB credentials, no artifact mount | acquisition | 5 GiB / 1.1 (512 MiB / 0.1 reallocated to `api`) |
| `postgres` | `db/migrations/` | Only scheduler of record | control | 1.5 GiB / 0.3 |
| `egress-gateway` | `src/gateway/` | Connection-time destination policy for HTTP, HTTPS (CONNECT) and WebSocket | egress, acquisition, triage | 0.5 GiB / 0.1 |
| `scrapling-worker` (profile `scrapling`) | `scrapling-worker/` | Optional alternate adapter, at most one global permit | control, acquisition | shares the envelope |
| `api` (profile `console`) | `src/web/`, `web/` | Analyst API and strict-CSP console: sessions + TOTP, case-scoped authorisation, intake, investigation, evidence verification, notices, Section 63 worksheets, monitoring, analytics, metrics. Never contacts target sites | control, console (loopback publish only) | 0.5 GiB / 0.1 |

The six caps add up to 9.75 GiB and 2.0 vCPU, matching the blueprint's proposal: the console's
share was taken from `browser-engine`, not added on top (v4 §4). They are caps for evaluation.
They are not measured requirements.

Only `egress-gateway` is attached to a network with an Internet route. The `console` bridge has
IP masquerade disabled and exists only to publish the console on host loopback. The `acquisition`, `triage` and
`control` networks are `internal: true`, so the browser engine has no route except through the
gateway. This is enforced by the network topology, not only by page routing.

## Job lifecycle (§7, §8, §12)

```
import ──► QUEUED(stage=http | browser_primary)
             │  lease (FOR UPDATE SKIP LOCKED + permit + domain lock, token=nextval)
             ▼
          LEASED ─► CAPTURING ─► FINALISING ─► commit (fenced by token)
             │                                     │
             │ lease expiry ─► reclaimer           ├─ finish: COMPLETE | PARTIAL | MANUAL_REVIEW | FAILED_FINAL
             ▼                                     └─ continue: QUEUED/DEFERRED on next stage (or same stage after backoff)
   attempt=interrupted, job requeued or INFRASTRUCTURE_DEFERRED
```

* **Stages**: `http` → `browser_primary` → (`browser_alternate` = Firefox | `scrapling`). Each
  worker leases only its own stages. The router (`src/router/router.ts`) is a set of pure
  functions. It maps one attempt's observation to an outcome and the next step.
* **Budget** (`src/router/budget.ts`): ≤ 2 HTTP + ≤ 2 browser attempts, ≤ 4 in total, ≤ 180 s of
  cumulative active time. Each attempt is capped at the stage limit (15/60/90 s) or at the time
  left, whichever is smaller. Navigation, readiness, screenshots and finalisation all draw from
  one deadline that keeps a 15 s finalisation reserve. Attempts are charged **when the lease is
  granted**. A lease returned before any contact with the target is refunded.
* **Retries**: no library retries itself. undici has no retry, Playwright has no retry, Crawlee's
  `AutoscaledPool` does not retry tasks, and Scrapling runs with `retries=1`. The router is the
  only place where retries are decided.
* **Lock order**: every transaction that touches both locks the `jobs` row before the `attempts`
  row (commit, release, reclaim, Scrapling commit), so a commit racing a lease expiry cannot deadlock.
* **Idle backoff**: Crawlee's `AutoscaledPool` re-runs a task immediately after one finishes. When
  work is due but cannot be leased (permits busy, domain locked or paced), the workers back off
  for 1–2 s instead of spinning against PostgreSQL.
* **Shared browsers** (`src/worker/browserPool.ts`): captures take a lease on the shared browser.
  Recycling (after N jobs or minutes), crash discards and memory recycling *retire* a browser:
  it takes no new work and closes only after its last in-flight capture releases it. Concurrent
  first acquires share a single launch.
* **Deadlines**: every Playwright call in the capture is raced against the attempt deadline,
  because some calls, such as `page.screenshot` on a page stuck mid-navigation, can ignore
  their own timeout. As a backstop, `runLeasedAttempt` abandons a capture 20 s past its
  deadline and records it as an infrastructure failure. Before finalising, it waits up to 30 s
  for the abandoned capture's own bounded cleanup, because closing the context makes Playwright
  flush the HAR straight into the attempt directory. After that, the directory is sealed against
  late writes.
* **Permits** (`global_permits`): there are two slots in total across every engine and adapter.
  At most one can be held by an alternate adapter, enforced under an advisory lock. Backoff and
  `429` deferrals give the slot back. They never sleep inside it.
* **Per-domain pacing** (`domain_pacing` + `pg_try_advisory_xact_lock`): at most one top-level
  visit runs per registrable domain at a time, with a 3 s gap between visits. A `429` raises the
  gap to the `Retry-After` value.
* **Processing state vs. outcome**: these are separate columns. `COMPLETE` requires
  `CONTENT_CAPTURED` and a fully satisfied `required_artifacts` contract
  (`processingStateFor`, `applyContract`). A challenge screenshot or block page that was saved
  can never mark an `ACCESS_BLOCKED` job `COMPLETE`.

## Acquisition paths (§7)

| Profile | Required by default | Completion rule |
|---|---|---|
| `data_triage` | `http_response_record` | May finish from HTTP alone and never escalates to the browser. Never advertised as browser evidence |
| `browser_evidence` | `screenshot_viewport`, `rendered_dom`, `rendered_text`, `network_events`, `har`, `manifest` | Cannot finish as `COMPLETE` from HTML or API data. Urgent jobs skip HTTP triage |

`required_artifacts` can be overridden per input row. Override names are checked against
`ARTIFACT_TYPES` in `src/acquisition/contract.ts`. A `data_triage` row may not require browser
artifacts.

## Browser capture protocol (§9) — `src/capture/browserCapture.ts`

1. A fresh isolated context per attempt with a fixed recorded profile: viewport 1440×1000,
   DPR 1, locale, timezone, service workers allowed, no ad blocking, downloads refused. The
   recorders are attached to the **context** before navigation, so popups, frames and service
   workers are captured. HAR recording starts at context creation.
2. `goto(waitUntil: 'commit')`, then a bounded wait for `domcontentloaded`. If the wait times
   out, the surviving page is inspected, not discarded.
3. An early viewport screenshot is taken as soon as a renderable target or challenge exists. If
   `page.screenshot` stalls waiting for fonts on a page that never finishes loading, a Chromium
   CDP capture is used instead and labelled as such.
4. Challenge interstitials get a bounded wait for ordinary completion (no clicks, no CAPTCHA
   solving). Readiness checks then run: the `load` event, DOM quiet time measured with a
   MutationObserver, `document.fonts.status`, viewport images and visible loaders. The code
   **never** relies on `networkidle`.
5. Settled viewport, `page.content()` (rendered DOM), `innerText` and the DOM of accessible
   frames (≤ 50).
6. Controlled scrolling (if `scroll` is allowed), then a full-page shot if it fits in 20 MP.
   Otherwise up to 6 viewport tiles are taken with recorded positions and a truncation reason.
   Infinite or virtualised pages are labelled as a bounded sample.
7. Element crops (≤ 20): logo, login form, QR candidates, payment details, contact blocks and
   suspicious claims. Each crop records a structural CSS locator, the frame URL, its bounding box
   and the surrounding text. The DOM is not modified to find them.
8. Every PNG is checked: signature/IHDR, non-zero size, and a decode within budget. A
   near-uniform image is a warning only.
9. Finalisation runs in a `finally` block inside the reserve. It saves the restricted storage
   state, closes the context (which flushes the HAR), drains body writes up to the deadline,
   writes the action log and attempt metadata, records an error for each failed artifact, and
   releases the permit when the attempt is committed.

## Network and original content (§10) — `src/capture/networkRecorder.ts`

* Streams bounded `network/events.jsonl` covering requests (with frame or service-worker
  origin), responses (with server address and TLS details), failures, frames, popups, service
  workers, WebSocket open/frame/close, dialogs and refused downloads. Cookie and authorization
  headers are redacted here. The unredacted HAR is a **restricted** artifact.
* Bodies of the main document, xhr, fetch, eventsource and scripts are kept up to 5 MiB each,
  using up to 40% of the 50 MiB attempt budget. Every omission is written as a `body_omitted`
  event with its reason.
* `server_addr` is recorded with the note that, behind the gateway, it is the gateway's address,
  not the origin's.
* Only documents loaded in the captured page's own top frame decide its status and headers.
  Popups are recorded as popups, so a popup's 401/403/429 never stands in for the target's response.

## Artifact store and reconciliation (§12, §15)

`src/storage/artifactStore.ts` writes `tmp/<uuid>/`, fsyncs each file, hashes the bytes actually
on disk, writes `manifest.json`, renames the directory atomically to
`captures/YYYY/MM/DD/<uuid>/` and fsyncs the parent. Only after that does the database commit
happen. Names are generated by the collector and checked against a strict pattern. URL text is
never used to build a path.

`src/coordinator/reconciler.ts` runs at start-up and every 30 s. It:

- reclaims expired leases (the attempt becomes `interrupted` and the job is requeued, or ends as
  `INFRASTRUCTURE_DEFERRED` when the budget is spent);
- records final directories whose attempt row is still `pending` as `recovered`;
- salvages orphaned `tmp/` directories into `incomplete/`;
- marks pending rows that have no directory as interrupted;
- reports unknown directories and never deletes them.

Salvage waits for a quiet period of one lease duration with no file changes, so a worker that
is slow to notice its lost lease is never disturbed mid-write. A tmp directory left over from an
attempt that was already finalised is moved aside once (`tmp/stray-…`) and audited.

Retention honours a hold on **any** case linked to a job. That covers the job's own `case_ref`
and the case of every seed merged into it by deduplication (`job_sources` → `source_records`).

Child pages (≤ 2 per target window) are created only from attempts that actually reached content.
They go through the same parser as imported URLs, so the same rejection rules and Public Suffix
List grouping apply.

Derived outputs (identifiers, QR, OCR text) go to `derived/<uuid>/` with their own manifest, which
points at the hashes of the source files. Attempt directories are never modified after the rename.

## Evidence integrity and custody (v4 §20, §21)

| Step | Module | Guarantee |
|---|---|---|
| Write | `src/storage/artifactStore.ts` | SHA-256 over saved bytes; files `0440`; attempt directory renamed atomically, then every file re-hashed (`verifiedAtCommit`) |
| Describe | `src/evidence/manifestContext.ts` | Manifest v2: exact original inputs, navigation URL, UTC and IST, clock fact, engine, profile, capture context, declared vantage, redirect chain, software versions, integrity note |
| Seal | ledger `attempts.manifest_sha256`, `src/evidence/package.ts` | The manifest never contains its own hash; packages hash their index, and the index hash lives in the database and hand-off record |
| Custody | `src/evidence/custody.ts`, `audit_events` | Hash-chained, append-only audit log sealed every 2 s; Ed25519-signed checkpoints for external storage |
| Verify | `src/evidence/verify.ts` | Re-hashes every file of an attempt, job or case; hashed JSON report; `artifacts.verification_state` updated |
| Derive | `src/extraction/thumbnail.ts`, `annotations` | Derivatives carry `derived_from` and their own hash; notes and decisions never change originals |

## Analyst API (v4 §22, §23)

`src/web/server.ts` is a small `node:http` router: explicit routes (literal paths sorted before
parameterised ones), per-route auth level (`none`, `password`, `full`) and roles, CSRF on every
mutation, body limits, request IDs and security headers. `src/web/authz.ts` resolves case
membership (`job_case_links` view) for every object; anything outside the caller's cases returns
404. Route modules live in `src/web/routes/` (auth, cases, jobs, evidence, investigate, actions,
monitoring, ops). `docs/openapi.json` is generated from the live route table (`npm run openapi`)
and checked in CI.

Investigation data is append-only: `analyst_decisions`, `identifier_reviews`, `annotations` and
`risk_assessments` reject updates and deletes (`forbid_mutation()`). The latest decision per
target forms the verdict (`target_verdicts` view). A false-positive or benign verdict suppresses
external actions until an approver overrides it on newer evidence.

Notices follow `draft → analyst_review → legal_check → approved → generated → issued →
acknowledged → complied | partially_complied | rejected | no_response → verified_closed |
escalated` (plus `withdrawn` and `disputed`). Eligibility checks per legal route
(`src/actions/legalRoutes.ts`) block submission and approval. Approval stores a snapshot hash that
generation re-checks. Issuance and receipt need uploaded proof. Verified closure needs a capture
taken after issuance.

## Security boundaries (§13)

See [`security.md`](security.md).

## Observability (§16)

`node dist/cli.js status` reports the following, with denominators:

- queue health: oldest due job, backlog by stage and urgency, merged duplicate seeds;
- the required-artifact completion rate, with blocked, unavailable and infrastructure outcomes
  counted separately;
- screenshot yield by type and completeness;
- per-field identifier status;
- per-engine cost and benefit of the alternate adapter;
- integrity counters: lease losses, reclaims, hash mismatches, recovered orphans;
- admission state, worker heartbeats and browser permits.

Logs are structured JSON with secrets redacted, and Docker log rotation bounds them to
10 MB × 5 files. Each service has a loopback-only `/healthz`, which is liveness only. An
in-process watchdog exits a stalled process so the Compose restart policy replaces it. Leases
recover through fencing.
