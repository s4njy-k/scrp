# Deployment readiness record

The blueprint (§18) says: *document every unavailable requirement before labelling the deployment
ready.* This file is that record. The deployment is **NOT READY** until every item in A and B is
closed or explicitly accepted by the owner. Each closure needs a date, the operator and evidence.

## A. Must be completed on the target VM

| # | Requirement | Why it cannot be closed in the repository | Procedure | Status |
|---|---|---|---|---|
| A1 | Phase A compatibility record: OS, rootless context name, existing services, ports, mounts, allocation granted | Needs the real host | `scripts/preflight.sh` → paste below | Open |
| A2 | cgroup v2 delegation of cpu/memory/pids for the rootless user | Host configuration, agreed with the host owner | runbook §1 "cgroup delegation" | Open |
| A3 | Images build and the project starts | No Docker daemon was available while this was prepared. `docker compose config` was validated; `build` and `up` were not run | runbook §2 | Open |
| A4 | Chromium sandbox actually enabled in `browser-engine` | Kernel/AppArmor dependent | `security.md#sandbox-verification` | Open |
| A5 | Network isolation: engine has no direct route or DNS; gateway refusals end as `egress_denied` | Needs the real Docker networks | runbook §2 post-deployment verification | Open |
| A6 | Effective resource caps (`docker stats` within caps under load) | Needs A2 | Pilot and 24-hour run | Open |
| A7 | 100–200 URL representative pilot with stratified metrics | Needs authorised real targets | `pilot-evaluation.md` | Open |
| A8 | 24-hour run within the allocation, plus a filled-in benchmark report | Needs the VM | `benchmark-report.md` | Open |
| A9 | Failure injection: worker kill mid-capture, DB outage, disk-threshold crossing | Needs the VM | `acceptance.md` (OOM/disk/DB row) | Open |
| A10 | Independent backup destination and a successful restore verification | No destination identified. **Single-disk risk remains** until closed | `recovery-and-backup.md` | Open |
| A11 | Start-on-boot / lingering for the rootless daemon under the host's service policy | Host policy | runbook §1 "Start on boot" | Open |
| A12 | Clock NTP-synchronised (evidence timestamps) | Host configuration | `preflight.sh` | Open |
| A13 | `GATEWAY_EXTRA_DENY_CIDRS` set to the VM's own public address and any provider management ranges | Deployment-specific | `.env` | Open |

## B. Not implemented in this release (by scope or because they are optional)

| # | Item | Blueprint | Current behaviour | Notes |
|---|---|---|---|---|
| B1 | Operator-assisted live sessions (release permit while waiting, re-acquire, record operator actions) | §8 | Jobs end in `MANUAL_REVIEW` with evidence preserved | Needs a private operator browser channel, which is not designed yet |
| B2 | Analyst UI with safe raw-HTML viewing | §13 | None. Use the CLI and files | When built: view HTML as text or in a script-less sandboxed iframe on a separate origin |
| B3 | Alerts through a notification channel | §16 | Local metrics (`cli status`) and the daily JSONL export only | Wire alerts only to an already-configured channel. Data must not go to new services |
| B4 | Scrapling adapter exercised against real browsers | §4, §14 | Contract code and unit tests only. Disabled by default | Before enabling, verify screenshots, HAR via `additional_args`, sandbox and resource cost on the pinned versions |
| B5 | Browsertrix (WARC/WACZ) and Lookyloo | §4 | Not included | Optional separate workflows. The HAR here is not WARC |
| B6 | Scrapling adaptive extraction | §11 | Not used | If added: keep the selector version and relocation flag, and never normalise a changed payment recipient |
| B7 | AI interpretation | §13 | Not implemented; policy forbids enabling it | — |
| B8 | WAL archiving (RPO < 24 h) | §15 | `archive_mode=off`; daily dumps | Enable together with an independent archive destination |
| B9 | OCR languages other than English | §11 | `tesseract-ocr-eng` only | Add e.g. `tesseract-ocr-hin` to the app image and set `TESSERACT_LANG=eng+hin` if needed |
| B10 | ~~Dedicated two-target cookie-isolation fixture test~~ | §18 C | **Closed 2026-10-17**: `browserCapture.test.ts › isolates cookies between targets…` | — |
| B11 | Mobile capture on Firefox | §9 | Mobile emulation is Chromium-only; Firefox falls back to desktop with a recorded limitation | — |
| B12 | Project licence | — | `UNLICENSED`, all rights reserved | The owner chooses |

## C. Compatibility record

_Paste `scripts/preflight.sh` output here (date, operator)._

## D. Change log

| Date | Operator | Change | Evidence |
|---|---|---|---|
| 2026-10-17 | Claude Code (repository setup) | Initial implementation of the blueprint; fixture tests passing in development | `docs/acceptance.md` |
| 2026-10-17 | Claude Code (review pass) | Corrections from a full self-review: shared-browser lifetime (leases, no close under a running capture, no duplicate launches); idle backoff instead of a tight lease-polling loop; consistent jobs→attempts lock order (no commit/reclaim deadlock); every Playwright await bounded plus a hard attempt deadline; pre-response timeouts and browser error pages no longer count as evidence; status judged on the document finally shown; case holds honoured across merged seeds; legitimately empty text accepted; sealed attempt directories; reconciler quiet period and stray handling; gateway survives client resets during DNS/connect and counts pending tunnels; DNS answer cache; child pages normalised like imports and only from reached content; watchdogs ignore database outages; Compose policy mount fails loudly, grace periods, Crawlee storage on tmpfs; CI action and healthcheck updates. 10 new regression tests (132 total) | `docs/acceptance.md` |
