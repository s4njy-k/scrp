# Configuration and library mappings

`config/policy.default.yaml` is the **collector's own policy** (blueprint §14). It is not a set of
upstream options to paste into a library. `src/config/policy.ts` validates it: unknown keys are
rejected, cross-field rules are enforced, and `config/policy.schema.json` is generated from the
same schema with `npm run schema`. The deployed copy is `config/policy.yaml`, mounted read-only
into the containers. Validate it with:

```bash
docker --context rootless compose -p cyber-web-collector run --rm --no-deps coordinator validate-policy /app/config/policy.yaml
```

## Cross-field rules enforced at load

* `alternate_browser_slots_max ≤ browser_slots_global`
* `acquisition_attempts_max ≤ http_attempts_max + browser_attempts_max`
* `finalisation_reserve_seconds` < each browser stage cap; each stage cap ≤ `active_acquisition_seconds_max`
* `lease_seconds ≥ 3 × heartbeat_seconds`
* `host_free_gb_resume_above > host_free_gb_pause_below` (hysteresis)
* `individual_text_body_mib_max ≤ attempt_artifacts_mib_max`; request bound ≤ event bound
* `delete_case_hold_artifacts` must be `false`; `ai_required_for_collection` must be `false`
* `external_providers_enabled` and `extraction.ai_enabled` must be `false` because no such
  adapter exists in this release

## Explicit mappings

| Policy key | Where it is applied | Library mapping |
|---|---|---|
| `limits.browser_slots_global` | `global_permits` rows (`syncPermitSlots`), lease query | PostgreSQL permits. The `AutoscaledPool.maxConcurrency` hard cap per replica equals this value |
| `limits.alternate_browser_slots_max` | lease (advisory lock 727274002) | Counts permits whose `adapter` starts with `alternate:` |
| `limits.http_concurrency_global` | `HttpTriageWorker` | `AutoscaledPool({ maxConcurrency })` |
| `limits.top_level_concurrency_per_domain`, `per_domain_delay_seconds` | lease query, `domain_pacing` | `pg_try_advisory_xact_lock(hashtextextended(domain))` |
| `limits.*_attempts_max`, `active_acquisition_seconds_max` | `src/router/budget.ts` | Charged at lease time |
| `limits.http_attempt_seconds` | `runHttpTriage` | undici `headersTimeout`/`bodyTimeout` + `AbortController` |
| `limits.primary_browser_seconds`, `alternate_browser_seconds`, `finalisation_reserve_seconds` | `captureWithBrowser` deadline | Every Playwright timeout is derived from the time remaining |
| `capture.viewport`, `device_scale_factor` | `browser.newContext` | `viewport`, `deviceScaleFactor` |
| `capture.original_service_workers` | `browser.newContext` | `serviceWorkers: 'allow' \| 'block'` (`block` gives a labelled diagnostic run) |
| `capture.block_ads`, `suppress_render_resources` | recorded in settings; no routing is installed | Scrapling: `block_ads`, `disable_resources` |
| `capture.full_image_megapixels_max`, `scroll_tiles_max` | `captureFullOrTiles` | `page.screenshot({ fullPage })` or tiles |
| `capture.individual_text_body_mib_max`, `attempt_artifacts_mib_max` | `NetworkRecorder`, `AttemptWriter` | Body cap, attempt byte budget |
| `storage.*` | `src/coordinator/admission.ts` | `statfs` on `ARTIFACT_ROOT` and the ledger's byte totals |
| `queue.heartbeat_seconds`, `lease_seconds` | `runLeasedAttempt`, `renewLease` | — |
| `scope.allowed_ports` | importer and child jobs | Must match `GATEWAY_ALLOWED_PORTS` |
| `scope.max_redirects` | HTTP triage (manual redirects) | Chromium follows redirects natively; the gateway re-checks every hop |
| `bounds.*` | `NetworkRecorder`, capture | Event, request, WebSocket-frame, frame, popup, DOM, decode and element bounds |
| `http.user_agent`, `accept_language` | HTTP triage | Fixed per deployment and recorded. Never rotated per request |
| `browser.chromium_channel` | launch options | `channel: 'chromium'` (new headless, full Chromium) |
| `browser.user_agent` | `newContext({ userAgent })` | `null` means the engine's own UA, recorded per attempt |
| `browser.locale`, `timezone` | `newContext` | `locale`, `timezoneId`. Changing these does **not** create a new network vantage |
| `browser.readiness_*`, `challenge_wait_seconds`, `scroll_step_wait_ms` | capture stages | — |
| `browser.body_resource_types` | `NetworkRecorder` | Playwright `request.resourceType()` values |
| `browser.recycle_after_*` | `BrowserPool` | Reconnect or relaunch |
| `browser.alternate_engine` | router, worker stages | `firefox` → `browser_alternate`, `scrapling` → `scrapling` stage, `none` |
| `extraction.*` | `src/extraction/runner.ts` | jsQR; `tesseract` CLI (`--psm 6`, `OMP_THREAD_LIMIT=1`, serialised) |
| `retention.classes`, `default_class` | `attempts.expires_at`, `applyRetention` | Deletion only with `RETENTION_DELETE_ENABLED=true`. Attempts cited by notices or certificates, or linked to open cases, are never expired. API intake defaults to `case_evidence` |
| `web.session_*`, `mfa_required`, `cookie_secure`, `hsts` | `src/web/auth.ts`, `http.ts` | Idle/absolute session expiry, TOTP requirement, cookie and HSTS flags |
| `web.login_attempts_per_minute`, `lockout_*`, `api_requests_per_second` | `src/web/server.ts` rate limiter, login route | Login keyed per account and address (looser per-address cap); API keyed per user |
| `web.intake_max_rows`, `intake_max_mib`, `upload_max_mib` | `/intake-batches`, `/cases/:id/uploads` | Request body limits; XLSX is also bounded by the defensive reader (`src/importer/xlsx.ts`) |
| `web.paginated_list_limit_*`, `sse_*`, `dashboard_aggregation_cache_seconds` | list routes, `/jobs/events`, `/analytics` | Cursor pagination, SSE connection cap and poll interval, analytics cache |
| `governance.*` | `src/actions/legalRoutes.ts`, notice transitions, certificates | Literals: no autosend, no auto-takedown, no autosign, maker-checker, analyst review, override only on new evidence. `section63_template_source_version` names the Schedule text that must be verified |
| `monitoring.*` | `src/monitoring/monitor.ts` | Revisit interval bounds, per-day cap, priority (below first captures), reappearance alerts |
| `enrichment.*` | `src/enrichment/enrich.ts`, gateway `/__dns` | DNS/TLS/RDAP through the gateway, cache hours, response caps, per-cycle budget. `certificate_transparency` (crt.sh) is off by default |

## Environment variables

| Variable | Service | Purpose |
|---|---|---|
| `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSWORD_FILE` | coordinator, worker | Database connection (password from a Compose secret) |
| `DATABASE_URL` | dev/test | Alternative to the `PG*` variables |
| `ARTIFACT_ROOT` | coordinator, worker | Artifact filesystem root (`/data/artifacts`) |
| `COLLECTOR_POLICY_PATH` | all | Policy file (`/app/config/policy.yaml`) |
| `EGRESS_PROXY_URL` | coordinator, worker | Gateway URL. Required unless `COLLECTOR_ALLOW_DIRECT_EGRESS=true` (local tests only) |
| `EGRESS_VANTAGE_LABEL` | coordinator, worker | Recorded vantage description |
| `BROWSER_MODE` | worker | `connect` (hardened) or `local` (development; weaker boundary, recorded) |
| `BROWSER_WS_ENDPOINT` | worker | `ws://browser-engine:3000/<BROWSER_SERVER_PATH>` |
| `CHROMIUM_SANDBOX` | worker | `false` is refused in `connect` mode. In `local` mode it is recorded on every attempt |
| `BROWSER_SERVER_PATH` | engine, worker | Shared secret endpoint path (≥ 24 characters) |
| `GATEWAY_ALLOWED_PORTS`, `GATEWAY_EXTRA_DENY_CIDRS` | gateway | Port allow-list and extra deny ranges |
| `GATEWAY_CONNECT_TIMEOUT_MS`, `GATEWAY_DNS_TIMEOUT_MS`, `GATEWAY_IDLE_TIMEOUT_MS`, `GATEWAY_MAX_TUNNEL_MS`, `GATEWAY_MAX_TUNNELS` | gateway | Connection bounds |
| `RETENTION_DELETE_ENABLED` | coordinator | Enables actual deletion of expired, unheld attempts |
| `MIGRATE_ON_START` | coordinator | Default `true` |
| `HEALTH_PORT`, `HEALTH_BIND` | coordinator, worker | Liveness endpoint (default `127.0.0.1:8081`) |
| `WORKER_MAX_CONCURRENCY`, `WORKER_MEMORY_MBYTES` | worker | Lower the per-replica cap and give Crawlee a memory basis |
| `TESSERACT_BIN`, `TESSERACT_LANG` | coordinator | OCR binary and language |
| `EGRESS_PUBLIC_IP` | coordinator, worker | Operator-declared public egress address, recorded in manifests as declared. Empty means "not observed" |
| `API_BIND`, `API_PORT` | api | Listener (default `127.0.0.1:8080`; `0.0.0.0` inside the Compose container, published on host loopback only) |
| `API_HOST_PORT` | Compose | Host loopback port for the console (default 8080) |
| `METRICS_BEARER_TOKEN` | api | Optional Prometheus scrape token (≥ 24 characters) |
| `CUSTODY_SIGNING_KEY_FILE` | CLI | Ed25519 private key used by `custody checkpoint` (keep it off the artifact volume) |
| `CRAWLEE_STORAGE_DIR` | coordinator, worker | Set to `/tmp/crawlee` (tmpfs). The root filesystem is read-only and Crawlee must never write into `/app` |

## Input format (§6)

CSV with a header row, or JSONL. Recognised columns:

| Column | Notes |
|---|---|
| `target` (or `url` / `domain` / `subdomain`) | Required. An exact URL (scheme required) or a domain-only seed |
| `kind` | `url`, `domain` or `subdomain` (optional hint) |
| `source_ref`, `case_ref`, `priority` | Provenance and ordering. `priority` runs from -1000 to 1000 |
| `profile` | `data_triage` or `browser_evidence` (default from `--profile`) |
| `urgent` | `true` sends the job straight to browser evidence |
| `deadline` | ISO-8601 with an offset |
| `required_artifacts` | `;`-separated list (CSV) or an array (JSONL) of names from `ARTIFACT_TYPES` |
| `allowed_interactions` | `scroll`, `expand`, `dismiss_dialog`, `non_submitting_click` |
| `retention_class` | A key of `retention.classes` |
| `capture_variant` | `desktop` or `mobile` (mobile is a selected extra attempt, Chromium only) |
| `child_pages_max` | ≤ `limits.child_pages_per_target_max` |

Every line becomes a `source_records` row. Rejected lines keep their reason, for example
`userinfo_credentials_in_url`, `unsupported_scheme:ftp`, `port_not_permitted:8443`,
`no_registrable_domain_public_suffix_only_or_unknown` or `data_triage_cannot_require_browser_artifacts`.
Examples are in `examples/`.
