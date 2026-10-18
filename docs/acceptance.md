# Acceptance checks (blueprint §18 Phase C)

Status key:

- **Verified (dev)**: an automated test in this repository passes against local fixtures, a
  local PostgreSQL 16 and Chromium 141 (Playwright 1.56.1).
- **Needs VM**: can only be shown on the target machine. The procedure is given.

Development verification ran on 2026-10-17: `npm test` gave 11 test files (6 unit, 5 integration) and
134 tests passing; the Python contract tests gave 4 passing. The browser in those tests ran
in-process **without** the Chromium sandbox, because the development container runs as root.
The hardened sandboxed engine still has to be verified on the VM.

| Check | Passing requirement | Evidence | Status |
|---|---|---|---|
| Deep URL and fragment route | Exact supplied location preserved and the relevant view attempted; no homepage substitution | `url.test.ts` (path/query order/tracking fields/fragment kept, distinct dedup keys); `browserCapture.test.ts › captures the exact deep URL with fragment route` (SPA route content captured, `finalUrl` = requested URL) | Verified (dev) |
| Urgent task | First browser observation not blocked behind enrichment or AI | `importer.initialStage` sends urgent jobs to `browser_primary`; `queue.test.ts › merges duplicate seeds` (urgent merge promotes the stage); extraction runs only after commit | Verified (dev) |
| HTTP 200 challenge or API returning HTML | Challenge or incomplete outcome, not successful target data | `router.test.ts › HTTP 200 challenge…`, `› API returning HTML is incomplete`; `browserCapture.test.ts › records a challenge interstitial`; `pipeline.test.ts › records a challenge outcome without completing the job`; `browserCapture.test.ts › judges a challenge that clears by itself by the document finally shown` | Verified (dev) |
| JS hydration, lazy loading, virtual lists | Relevant visible content captured within policy; bounded coverage recorded | `browserCapture.test.ts › captures hydrated JS content and lazy content after controlled scrolling`; tiles/`truncated` path in `captureFullOrTiles` | Verified (dev) for hydration and lazy content. Infinite-list labelling is covered by code review only |
| Navigation timeout with usable page | Best-effort screenshot and DOM preserved and the incompleteness described | `browserCapture.test.ts › preserves a best-effort screenshot and DOM when navigation never finishes` (`navigation_timeout_salvaged`, `CONTENT_INCOMPLETE`, CDP fallback labelled); `› treats a navigation timeout with no document response as a timeout` (blank page never counted as evidence; attempt returns within its deadline) | Verified (dev) |
| Screenshot and element crop | Decodable images; locator, frame and context provenance; correct temporal attribution | `imageCheck` on every PNG; `browserCapture.test.ts › captures a QR element crop with locator, frame URL and bounding box`; early ≤ settled timestamps asserted | Verified (dev) |
| Multi-frame, popups, service workers, WebSocket | Supported events collected; unsupported gaps explicit; no missing-frame crash | `browserCapture.test.ts › records frames, popups, service workers, WebSocket frames and fetch bodies`; `frameInfo()` never calls `request.frame()` on service-worker requests | Verified (dev, Chromium). The Firefox gaps (no CDP, no service-worker events) are recorded as limitations |
| Identifiers, adaptive matching, OCR | Known fixture values correct; wrong relocations or uncertain digits not promoted to confirmed identifiers | `extraction.test.ts` (UPI/IFSC/phones/WhatsApp/Telegram/BTC/TRON checksums; OCR → `uncertain`; resource strings suppressed); `pipeline.test.ts` (DOM + QR identifiers end to end) | Verified (dev) for DOM and QR. OCR runs only where `tesseract` is installed (the app image). Adaptive matching is not used because Scrapling adaptive mode is not enabled |
| Retry multiplication | Shared caps respected across all engines and their internal retries | `router.test.ts › shared budget prevents retry multiplication`; `queue.test.ts › charges the shared budget at lease time…`; library retries disabled (undici none, Playwright none, Scrapling `retries=1`) | Verified (dev) |
| Cookie isolation and session continuity | Different targets isolated; the same target flow keeps its own coherent session | New context per attempt; storage state reused only from the same job and engine (`previousStorageState`); `sessions` rows; `browserCapture.test.ts › isolates cookies between targets and keeps them within one target session` (fresh context sees no cookie; restored session state does; cookie redacted from the event log) | Verified (dev) |
| Lease loss and worker kill | Old worker cannot commit over new ownership; completed artifacts kept and the interrupted attempt recorded | `queue.test.ts › fences a worker that lost its lease` (`committed_lease_lost`, job untouched); `› commits idempotently` | Verified (dev) |
| Crash during artifact or database commit | Reconciler handles both orphan directories and pending records | `pipeline.test.ts › reconciles a crash between directory rename and database commit, and salvages tmp directories` | Verified (dev) |
| OOM, disk full, database outage | Bounded resource use, admission pause and recovery, no silent job disappearance | `queue.test.ts › pauses admission and admits only urgent work`; attempt byte budget (`artifactStore.test.ts`); reclaim on lease expiry | Partly verified (dev). OOM kill and DB outage injection need the VM: `docker kill` the worker mid-capture, `$DC stop postgres` for 2 min, `fallocate` a temporary file to cross 30 GB free |
| Internal-access attempts | Redirect, rebinding, subresource, IPv6 and alternate-transport tests cannot reach host or internal services | `gatewayPolicy.test.ts` (27 denied forms); `gateway.test.ts` (CONNECT, absolute-form, rebinding, mapped IPv6, ports, NXDOMAIN); `browserCapture.test.ts` (loopback routed to the gateway and refused; internal subresources and metadata redirect refused) | Verified (dev). UDP/QUIC suppression additionally relies on the `internal` network, which needs the VM |
| Sandbox and cgroups | Actually enabled sandbox and effective resource caps shown | `security.md#sandbox-verification`; `scripts/preflight.sh` (cgroup v2 and delegated controllers) | **Needs VM** |
| Case hold, retention, restore | Held evidence kept; authorised expiry recorded; independent restore verified if available | `retention.test.ts › keeps evidence when a seed merged into the job belongs to a held case` (holds on any linked case protect the job; deletion start and end audited); `scripts/restore-verify.sh` | Code complete. **Needs VM** for the restore run and an independent destination |
| Free baseline | Operates with every commercial-provider and model credential absent | No provider code paths; policy forbids `external_providers_enabled` and `ai_enabled`; the full test suite runs with no credentials | Verified (dev) |

## How to re-run

```bash
npm ci && npm run typecheck
export TEST_DATABASE_URL=$(scripts/test-postgres.sh)
PLAYWRIGHT_BROWSERS_PATH=/path/to/playwright-browsers npm test
python3 -I scrapling-worker/tests/test_contract.py -v
```
