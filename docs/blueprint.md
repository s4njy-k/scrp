# Cybercrime Web Collection — Final Deployment Blueprint

**Version:** 3.0 — 17 October 2026  
**Target:** 4-vCPU CPU-only remote VM; isolated Docker Compose project on the user's rootless daemon.  
**Status:** Implementation specification for an AI coder. The system has not been deployed or benchmarked by preparing this document.  
**Supersedes:** The previous blueprint, including its earlier HyperPod/eight-browser sizing assumptions.

## 1. Decision and operating objective

Build **Crawlee + Playwright as the primary collection system, PostgreSQL as the authoritative job ledger, a controlled egress gateway, and an artifact store on the allocated filesystem**. Add **one optional Scrapling adapter** for selected failures or repeated extraction tasks. Use deterministic parsing, QR decoding and selective OCR before optional AI. Keep paid APIs and hosted classifiers disabled in the baseline.

The objective is high useful-content coverage, bounded collection time, preserved partial evidence, recoverable processing and no silent job disappearance. No software combination guarantees retrieval from every website or access to every possible view. An unavailable origin, deleted content, required authentication, geographic restrictions, an unsupported browser feature, or loss of the sole VM remains a real limit.

Define the caller's required artifacts before execution. If a task requires screenshots, rendered content and network evidence, HTML-only or API-only retrieval must not complete it. A screenshot of a challenge page is valid evidence of the observed challenge, not evidence that the target content was retrieved.

**Default implementation:** Node.js/TypeScript with Crawlee orchestration and direct Playwright APIs in the driver worker. In the hardened profile, connect the driver to a separate private browser-engine container; keep database and coordinator access outside the browser network. Do not put an LLM/MCP agent in the mandatory path for every URL. Use an optional Python Scrapling worker behind the same job and result contract. If the existing project is Python, retain Python and use Scrapling/direct Playwright as primary instead of introducing Crawlee solely to satisfy this document.

The reviewed videos support choosing components by responsibility and using selective escalation. They do not establish that stacking libraries makes collection invincible. Crawlee's Playwright crawler and Scrapling's dynamic fetching share browser infrastructure; Scrapling's documented stealth path uses Patchright. Their failures are not statistically independent. [R1–R5]

## 2. Machine facts and constraints

The supplied machine image shows:

| Resource | Observed snapshot | Design consequence |
|---|---|---|
| CPU | 4 vCPU; Cascade Lake Xeon; one thread/core; VT-x exposed; reported load around 2 | Begin with two browser jobs total; measure actual utilisation, I/O wait and steal time |
| RAM | 30 GiB; approximately 26 GiB available | Adequate for a modest browser pool and supporting services |
| Swap | None | Bound memory/processes and handle OOM without losing queue records |
| Disk | One 168 GB ext4 volume; approximately 148 GB free | Apply quotas, reserve free space, and plan short local retention |
| GPU | No usable NVIDIA GPU; QXL virtual display | Capture and rules-based extraction on CPU; no large local GPU model |

The image does not identify the Linux distribution, existing application stack, Docker configuration, current outbound country/IP, cgroup delegation, backup destination, or permission to consume all resources. Load average around 2 is not proof of 50% CPU utilisation. VT-x exposure does not establish that nested virtualisation is needed or available for this project.

Preflight those details on the real remote machine. Preserve unrelated services. Do not use the cluster controller or assume this VM is the previously discussed H100 machine.

## 3. Review of the six supplied videos

All six video identities/descriptions were checked against their YouTube pages. Available timestamped transcripts for all six were recovered through a public transcript mirror after direct YouTube caption endpoints blocked requests. Review was of transcripts and publisher descriptions, not a frame-by-frame audiovisual audit. Automatic transcripts mis-spell product names; names below were normalised using project/publisher documentation. No full transcripts are reproduced here.

| Ref | Video and reviewed portions | Adopted lesson | Correction or limit |
|---|---|---|---|
| V1 | Shade of Code, *how to actually get good at Web Scraping*; approximately 00:39–01:24 and 02:13–02:31 | Detect silent extraction failure; lightweight retrieval first where sufficient; back off and monitor | Sponsored proxy experience is not a universal success benchmark; the most important bottleneck varies by target |
| V2 | CodeHead, *Learn Web Scraping in 5 Minutes (NO PRIOR KNOWLEDGE)*; approximately 00:55–03:34 | Separate HTTP retrieval, HTML parsing, persistence, pagination and browser rendering | Requests does not behave identically to a real browser; HTTP 200 does not establish usable content; not every 403 is bot detection |
| V3 | Oxylabs, *Best Web Scraping Tools: Which Should You Use?*; approximately 01:01–05:56 and 07:15–11:20 | Libraries, crawler frameworks, browsers and managed APIs solve different layers | Browser auto-waiting does not certify complete page content; provider handling does not remove all failures or evidence limitations |
| V4 | Rob The AI Guy, *I Gave Claude Code the Ability to Scrape ANY Website (Insane Results)*; approximately 00:25–02:56 and 04:27–05:52 | Standardise tool interfaces and routing; monitor outcomes; preserve structured outputs | The demonstration uses Decodo infrastructure. An installable skill/MCP server and free quota are not unlimited free self-hosted acquisition |
| V5 | ByteGrad, *AI Web Scraping with Jev + Playwright is Mind-Blowing!*; approximately 08:39–16:05 and 21:29–24:51 | Inspect real APIs, generate reusable scripts, use browser interaction when required, and classify downstream | API data does not replace original-page screenshots; hosted Jev/Oxylabs/AI coding services are optional dependencies |
| V6 | ScrapeOps, *How to Bypass Cloudflare in Web Scraping*; approximately 00:49–03:24 | Distinguish network/TLS behaviour, browser rendering and managed services; evaluate maintenance costs | Its quoted success percentages describe a vendor test, not this target population; TLS impersonation is not JavaScript rendering or screenshot capture |

**Resulting improvements:** an explicit required-artifact contract; separate cheap data and browser-evidence paths; failure-specific routing; consistent target sessions; staged screenshot salvage; content/schema drift detection; independent artifact validation; and common quotas across all adapters.

Video URLs are in section 20. Primary verification sources are in section 21. Commercial-provider comparisons are treated as descriptions of their services, not neutral accuracy rankings. Do not reuse advertised success percentages, proxy-pool sizes, coupon pricing or trial quotas as operating assumptions.

## 4. Selected architecture and optional components

| Component | Responsibility | Baseline decision |
|---|---|---|
| Crawlee | Worker lifecycle, HTTP/browser acquisition, resource-aware concurrency and handler integration | Primary framework; hard-cap autoscaling. BasicCrawler plus explicit Playwright context ownership is acceptable where built-in browser lifecycle hooks do not preserve the evidence contract |
| Playwright Chromium | Render, interact, capture screenshots/DOM and record network events | Primary browser; verify sandbox and exact dependency/browser match |
| PostgreSQL | Jobs, leases, attempt budgets, global browser permits, metadata, findings and audit | Single authoritative ledger; no Redis/Kafka initially |
| Artifact filesystem | Original HTML, screenshots, network/body artifacts, extracted data and manifests | Quota-controlled, immutable completed attempt directories |
| Egress gateway | Public-destination checks and outbound enforcement | Required for untrusted acquisition; no assumption that a local proxy changes public IP |
| Scrapling adapter | Alternative HTTP/browser behaviour and adaptive extraction for selected monitored sites | Optional profile; enable after benefit and evidence fidelity are measured |
| QR decoder and Tesseract or existing OCR | Recover image-only identifiers | Run on selected crops after capture; one OCR task at a time initially |
| Firefox | Selected engine-specific rendering comparison | Optional alternative to the Scrapling browser attempt, not an additional unconditional tier |
| Lookyloo | Analyst investigation of captured request/domain relationships | Optional, after core collection is reliable |
| Browsertrix Crawler | Replayable WARC/WACZ archiving for selected cases | Optional separate acquisition/archive workflow; do not label existing HAR as WARC |

Do not initially add Selenium, Puppeteer, FlareSolverr, a separate curl_cffi service, Crawl4AI and Firecrawl as additional always-running fallbacks. Additional libraries can duplicate work and increase browser/version and security maintenance. A TLS-capable HTTP adapter can be useful, but first check what the selected HTTP/Scrapling implementation already supplies. TLS-oriented HTTP retrieval produces no browser screenshot. [R5, R12]

FlareSolverr is not a dependable universal CAPTCHA layer: its own README lists CAPTCHA-solver limitations. Firecrawl's reviewed self-host guide describes screenshot/page-action dependencies outside the default stack. These remain release-specific evaluation candidates. [R13, R15]

Decodo/Oxylabs/ScrapeOps-managed acquisition may be evaluated later only if the user changes the no-mandatory-paid-service requirement. Keep external-provider routing, credentials and spending disabled by default. An open-source connector does not include its provider's network infrastructure. [R14, R17]

## 5. Services, isolation and resource envelope

Use the existing rootless daemon if present and the unique Compose project `cyber-web-collector`. Do not disable another daemon or mount any Docker socket. Create an application image, a browser image and pinned supporting-service images; avoid unnecessary host package installations.

| Service | Work | Initial memory ceiling proposal |
|---|---|---|
| coordinator | Import, scheduling, HTTP triage, lease API, extraction/export | 1.5 GiB |
| browser-worker: one driver replica | Acquisition orchestration; private Playwright connection | 0.75 GiB |
| browser-engine | Sandboxed Chromium; private acquisition network only | 5.5 GiB |
| postgres | Durable ledger and relationships | 1.5 GiB |
| egress gateway | Destination policy and connection forwarding | 0.5 GiB |
| optional Scrapling worker | Selective alternate acquisition | Shares the acquisition envelope; do not add unrestricted capacity |

The five services above total 9.75 GiB of proposed memory ceilings. The optional adapter must fit the same envelope through reallocation or pausing other acquisition services.

Start with an **aggregate collector CPU budget of approximately 2 vCPU** and a **10 GiB memory envelope** including optional workers and OCR. These are proposed caps for evaluation, not measured requirements. Prefer a verified delegated collector cgroup with weighted sharing; otherwise derive verified per-service caps whose aggregate respects the allocation. A browser semaphore does not enforce CPU consumption. Do not put unrelated projects under this collector's cap. Rootless cgroup limits require suitable host support and delegation. [R10]

Two global browser permits cover Chromium, Firefox, Scrapling browsers and manual-assisted sessions combined. The alternative adapter may use at most one permit. Rebalance or stop the primary pool before launching an alternative that would exceed the CPU/memory envelope. HTTP concurrency starts at eight; per-domain top-level concurrency starts at one. Reduce pressure automatically on CPU saturation, memory pressure, disk wait or increasing artifact-write latency. Four browser slots are a later experiment; eight are not the starting plan.

Use non-root container users, init handling, a tested browser-compatible seccomp profile, private IPC and appropriately sized private shared memory. Do not copy test-oriented host-IPC/SYS_ADMIN workarounds into this shared-host deployment. Verify that Chromium sandboxing is actually enabled; rootless Docker alone does not establish this. If the host cannot support the required isolation, identify that deployment blocker instead of silently disabling the sandbox. [R9]

Expose no database, browser-debug, fallback or remote-desktop ports publicly. If an operator API is needed, bind it to loopback, authenticate it and use SSH forwarding. Bind existing services unchanged. An optional operator browser must be isolated from personal browsing and available only through a private channel.

## 6. Target, scope and task contract

The importer accepts CSV/JSONL containing domain, subdomain or exact URL plus source/case reference and priority. The task record must state `required_artifacts`, capture profile, scope, deadline, allowed interactions and retention class.

For a domain-only seed, generate explicitly tracked HTTPS/HTTP candidates according to policy. Keep scheme fallback as a separate recorded attempt; never silently relabel HTTP content as an HTTPS observation. Preserve exact supplied paths, query strings, query order and URL fragments: fragments may select a client-side application route even though they are absent from HTTP requests. Store the original input, parsed URL, IDNA/unicode hostname representations and conservative deduplication key separately. Do not strip tracking-looking fields from original evidence; they may be campaign/victim selectors or signed access tokens.

Use a Public Suffix List aware library for registrable-domain grouping. Treat IP-literal URLs and nonstandard public ports as explicit policy cases, not hostname parsing errors. Reject unsupported schemes and user-info credential URLs by default. Preserve rejection reasons. Seed provenance survives acquisition deduplication.

Distinguish:

- A supplied URL that must be visited.
- A link discovered in HTML or script text, which has not necessarily been contacted.
- A domain actually requested by the browser, which is not necessarily owned by the target.
- A candidate generated by typo/subdomain tooling, which is not automatically malicious.

Begin with the supplied page plus up to two relevant same-site pages per target window. External redirect destinations may be followed within bounds after public-destination validation; do not recursively crawl every CDN, payment provider or third-party endpoint. Create bounded child jobs for additional pages. Maintain their provenance and the combined per-target budget.

## 7. Required artifacts and two acquisition paths

Provide at least two task profiles:

| Profile | Required result | Completion rule |
|---|---|---|
| `data_triage` | Recorded HTTP outcome, headers/body where received, links and identifiers | May finish without browser artifacts; never advertise as browser evidence |
| `browser_evidence` | Required screenshots, rendered DOM/text, observed network metadata, manifest and artifact-status records | Cannot finish as successful solely because HTML/API data was retrieved |

Ordinary targets may enter HTTP triage first. Urgent complaint URLs and short-lived high-priority targets should go directly to browser evidence, with parallel/secondary metadata work only within the resource cap. Do not delay the first screenshot behind comprehensive enrichment or AI classification. Conversely, an HTTP timeout, TLS error or 403 is not sufficient proof that a browser visit cannot work.

When a site uses a relevant public API observed in its ordinary page flow, reuse a tested adapter for efficient repeated structured retrieval. Preserve method, endpoint, parameters, response and linkage to the page. Do not assume that direct API results were visible to the captured visitor. If screenshots were requested, the browser job remains required.

Treat a displayed empty contact section as a possible legitimate absence, not automatically failed extraction. For unknown sites there may be no predefined schema; assess page rendering and attempted coverage separately from whether any identifier was found.

## 8. Failure-specific acquisition router

Use a coordinator-owned budget. Disable or constrain nested library retries and automatic session rotations so they cannot multiply attempts invisibly. A top-level acquisition attempt is a visit/fetch; its resources, redirects, subframes and known bounded interactions are tracked separately, not each charged as a top-level retry.

Default per-target window: **up to two HTTP attempts and two browser attempts, four acquisition attempts maximum**, with **180 seconds cumulative active acquisition time**. Skip unnecessary HTTP stages for urgent tasks. Primary browser attempt is capped at 60 seconds; selected fallback at 90 seconds; each includes its finalisation reserve. Queue waiting and future revisit schedules are separate. Exhausted infrastructure attempts are not evidence that the origin is offline.

| Failure classification | Next action | Stop/defer condition |
|---|---|---|
| Static HTML usable | Parse; browser still required for evidence-profile tasks | Required task artifacts satisfied |
| JS shell, hydration/pagination or relevant frame content missing | Standard Playwright visit and bounded recipe | Deadline/recipe scope reached |
| Timeout/reset/5xx with no access-block signal | Backoff with jitter; one selected retry | Shared attempt/time budget reached |
| 429 | Honour `Retry-After`; reduce rate; defer rather than sleeping in an occupied browser slot | Next eligible scheduled time |
| 403/401/denied response | Inspect ACL/login/token/challenge evidence; do not assume all 403s are bot detection | Classified access limitation or one justified alternative |
| Recognised challenge/interstitial | Preserve its screenshot/body; allow bounded ordinary browser completion; one selected alternate profile if justified | Unresolved challenge becomes manual/deferred outcome |
| Chromium rendering incompatibility | One Firefox alternative, instead of an additional Scrapling browser tier | Separate attempt recorded |
| TLS certificate failure | Preserve error; optional explicitly labelled relaxed-TLS inspection profile | Never change the global TLS default |
| DNS/404/410/unavailable origin | Validate input and exact path; schedule according to urgency | Do not run every browser engine against the same confirmed error |
| Missing required artifact after useful content appears | Salvage available artifacts; retry the failing capture operation if safe | Mark partial if the contract remains unmet |
| Worker/browser crash or OOM | Persist interruption, recycle process and reclaim lease | Infrastructure-deferred if budget exhausted |
| Gateway/database/disk failure | Stop new acquisition and preserve work | Resume after verified recovery |

Use `cf-mitigated: challenge` where present and HTML-versus-expected-JSON mismatch to recognise Cloudflare challenge responses; supplement with page/DOM signals. Absence of that header does not prove unrestricted content, and a Cloudflare CDN/server header alone does not prove blocking. [R6]

Preserve cookies, browser identity, locale and egress consistently within the same target session. Do not randomise headers/user-agent/IP at every subrequest. A different engine/vantage is a new attempt. Clearance cookies are visitor/device-bound and not universal reusable tokens. Do not build a global cookie pool shared between targets. [R7]

A local egress gateway protects the host but ordinarily retains the same public IP. A separate approved network vantage may recover IP/country-specific failures; changing browser timezone/geolocation does not create that vantage. The free baseline supplies no residential proxy network. A public free proxy list is not a dependable or appropriate evidence transport.

If an operator-assisted session is needed, release automated permits while awaiting the operator, then reacquire one for the live session. Record operator actions, session identity and capture boundaries. Keep authentication/OTP/challenge outcomes explicit. Do not automatically create accounts, submit credentials, make payments or upload documents as part of a generic capture recipe.

## 9. Browser capture and screenshot protocol

Treat screenshot production as a staged evidence workflow, with independent failure handling from extraction:

1. Acquire a global browser permit and a target-specific isolated context. Register context events, popup/frame observers and network recording **before navigation**. Set a fixed profile and record browser/build, user agent, locale, timezone, viewport/device scale, egress and relevant settings.
2. Navigate with a bounded wait. On a navigation timeout, inspect the surviving page before discarding it. A timeout may leave useful content available. Attempt a best-effort viewport screenshot and DOM snapshot unless the renderer is dead.
3. Save an early viewport as soon as a renderable target or challenge state exists. Do not wait for enrichment or perfect network idleness. This is an observation with its own timestamp, not proof that loading completed.
4. Apply bounded content-readiness checks: visible target content, loader/challenge state, relevant DOM changes, critical image completion and font status. Use a recipe-specific selector only when it actually represents the intended page. Action auto-waiting is not whole-page readiness. Never depend on `networkidle` alone.
5. Save the settled viewport and rendered DOM/text. Keep lazy-load scroll, accordion expansion and permitted non-submitting clicks in an action log; capture the original view before interactions. Treat subsequent navigations as bounded page steps or child jobs.
6. Perform controlled scrolling to trigger lazy images/content, then capture the full page if it fits the limits. Do not assume `fullPage` automatically loads off-screen data or a virtualised list. Preserve viewport tiles for infinite/virtualised pages with positions and timestamps; never label a bounded sample as the entire page.
7. Capture visible relevant elements and their surrounding context: logo, login form, contact block, QR/payment details, suspicious claims. Preserve frame URL, locator, bounding box and source screenshot/DOM references. For canvas/closed shadow content, retain rendered pixels and mark DOM-extraction limits.
8. Check that image files decode, have nonzero dimensions and correspond to the observed page. Near-uniform/blank-image heuristics are warnings, not sole rejection criteria; simple pages can legitimately be sparse. Screenshot checks cannot alone establish semantic completeness.
9. Finalise browser/network artifacts, validate the manifest, close the context and release the permit in `finally`. Save per-artifact errors if closing/flushing times out. Reserve 15 seconds within the attempt for finalisation; if it fails, mark affected artifacts incomplete.

Defaults for evaluation: desktop 1440×1000, scale factor 1; PNG originals; full-image budget 20 megapixels. Above that budget use bounded viewport/scroll tiles with a default maximum of six and record truncation. Do not shrink an unreadable payment screenshot merely to claim full-page coverage. Bound page steps, image decoding and tile sizes to prevent oversized-page memory exhaustion. A mobile profile is a selected additional attempt, not an invisible default duplicate. [R3, R4]

Preserve CSS, images, fonts and relevant first/third-party traffic in evidence mode. Do not enable ad blocking or resource suppression by default. Any deliberate suppression, animation disabling, DOM cleanup, overlay removal or annotation creates a labelled modified observation/derivative; preserve the unmodified observation first. Each screenshot and DOM snapshot records its own time interval because dynamic page artifacts are not simultaneous.

## 10. Network and original-content contract

For each attempt preserve, where observable:

- Initial/exact and final URL; HTTP/meta-refresh/JavaScript navigation history, redirect edges, frame and popup URLs, initiator information where supported, and action timestamps.
- Requests/responses with URLs, methods, status, resource type, headers, timings, failures and relevant bodies; body limits and omission reasons must be explicit.
- HAR plus streamed request-event JSONL, relevant body artifacts and WebSocket open/frame/close events when encountered. HAR is not a complete record of every protocol and is not packet capture or traceroute.
- Raw HTML response separately from rendered DOM, including accessible relevant frame DOM. Store PDF/image/document responses as their own artifact types with capture status; do not pretend every URL is an HTML page.
- DNS/TLS/IP information actually observed by the acquisition path. With a remote proxy, local DNS or an edge IP may not describe the origin chosen upstream; record observation point and uncertainty.

Use browser-context events to include popup/frame/service-worker activity. Retain service workers in normal evidence mode and record their presence. A diagnostic run with service workers blocked must be separately labelled because it can change application behaviour. Do not call `request.frame()` unconditionally on service-worker requests. Chromium-only CDP information must be an optional adapter capability; do not promise identical CDP evidence from Firefox. [R3, R4, R8]

Register body listeners before actions and await bounded body-save tasks before completing the attempt. Close the context to flush HAR and validate the result. A valid HAR file can still omit/truncate bodies; record its actual mode and omissions. A packet trace from a non-decrypting proxy does not supply HTTPS bodies.

Initially cap retained individual HTML/JSON/text bodies at 5 MiB and total attempt artifacts at 50 MiB, with an explicit higher-budget case profile available. Record every truncation, rejected download and size-budget event. Requesting a larger profile consumes disk/CPU and must not overwrite the original partial attempt. Bound event count and decoded content as well as compressed network bytes. Do not execute downloaded files.

The browser records only what its chosen session observes. It cannot reveal hidden backend connections, every victim-specific variant or content never delivered. An archive/managed provider is a separate source and capture, not a replacement falsely attributed to the local session.

## 11. Relevance, identifiers and validation

Extraction runs after original artifacts are preserved. Use an ordered approach: DOM/attributes and relevant observed JSON responses; QR decoding; targeted OCR; optional AI interpretation. Relevant fields include:

- Emails, phones and `tel` links; WhatsApp/Telegram/social destinations.
- UPI/VPAs and UPI URI fields, QR payloads, displayed bank account/IFSC pairs and cryptocurrency addresses.
- Form action destinations, linked/requested domains, API endpoints, analytics identifiers, claimed business identity and relevant fraud-related text.

Store raw and normalised values, method, source URL/frame, locator or pixel bounding box, surrounding text, capture/attempt ID, timestamp, artifact hash and validation state. Keep displayed payment destinations distinct from third-party script examples or unrelated resource strings. Format validation does not establish ownership, operability or criminal involvement. Do not turn ambiguous OCR digits into a confirmed account number.

For adaptive Scrapling matches, retain the saved profile/selector version, relocation flag and matched context. Require semantic/field-type checks and compare against preserved content. A changed displayed payment recipient may be a substantive intelligence finding; it must not be silently normalised into the previous recipient. Correctly record `not_observed` separately from `extraction_failed`. [R5]

Separate three outputs: acquisition completeness, extraction quality and suspected-fraud assessment. A missing identifier does not mean an inaccessible page is benign. Use an explicit unknown/inconclusive classification. Fraud assessment needs corroboration; shared CDN/IP resources and visual similarity alone are not sufficient attribution.

## 12. Durable queue, states and crash-safe commits

Use PostgreSQL as the only scheduler of record. Suggested tables: targets, source_records, jobs, attempts, capture_profiles, sessions, global_permits, artifacts, identifiers, domain_edges, findings, audit_events and exports.

Use conservative target/profile/window deduplication with separate source references. Acquire jobs and browser permits atomically with expiring leases; use `FOR UPDATE SKIP LOCKED` or an equivalent tested transaction. Set heartbeat initially to ten seconds and lease duration to 120 seconds, renewed during active work. Keep transactions short; do not hold database row locks throughout a visit. [R11]

Every lease has a monotonically changing ownership/fencing token. Completion updates must match the current token. A worker that loses its lease stops target activity and cannot overwrite a newer attempt. On restart, reclaim expired jobs and reconcile partial directories. At-least-once execution can still duplicate an external visit after a crash; make result commits idempotent instead of claiming exactly-once website access.

Keep processing state separate from acquisition outcome:

| Processing state | Meaning |
|---|---|
| QUEUED / LEASED / CAPTURING / FINALISING | Lifecycle progress |
| COMPLETE | Required artifact contract satisfied for a content-captured attempt |
| PARTIAL | Useful preserved evidence; one or more required artifacts incomplete |
| DEFERRED / MANUAL_REVIEW | Scheduled retry or operator attention required |
| FAILED_FINAL | Budget exhausted or nonrecoverable processing outcome; reason retained |

Acquisition outcomes include CONTENT_CAPTURED, CONTENT_INCOMPLETE, CHALLENGE_PAGE_CAPTURED, ACCESS_BLOCKED, AUTH_REQUIRED, DNS_FAILURE, TLS_FAILURE, NOT_FOUND, ORIGIN_UNAVAILABLE and INFRASTRUCTURE_DEFERRED. COMPLETE must not mask an access-blocked outcome merely because the error screenshot was saved.

Write attempt artifacts to a unique temporary directory, await writes, hash actual saved bytes and produce a manifest. Use atomic rename on the same filesystem, then commit manifest/path/status metadata. The filesystem and database are not a single transaction: reconcile orphan final directories and stale pending records after a crash. Synchronise durable writes according to recovery requirements and verify backup restoration. Never reuse untrusted URL text as a filesystem path.

Different engines/profiles/vantages have distinct attempt IDs. A case bundle may reference several attempts but must not combine their screenshot, DOM and HAR as if they were one session. Preserve timestamps and action sequences. Hashes support integrity checking; they do not by themselves establish authenticity, lawful acquisition or admissibility.

## 13. Acquisition security and trustworthy automation

Use a separate browser-engine container for the hardened deployment. It joins only a private acquisition network and reaches public targets through the gateway. PostgreSQL/coordinator join a separate control network. The driver worker may join both networks to initiate a private browser-control connection, but must expose no page-reachable listener and must not forward packets between networks. The browser engine has no database credentials or control-network route. Keep driver/engine Playwright versions matched. The private browser-control endpoint is reachable only by the driver; it is never published on the host or Internet.

Use Crawlee BasicCrawler for orchestration and explicit Playwright connect/context management if the pinned PlaywrightCrawler integration cannot guarantee the required isolation, context ownership or finalisation. Do not force unsupported lifecycle hooks into the design. Validate optional patched-engine transport compatibility separately; otherwise run its driver/engine isolation equivalent on demand within the same resource cap. A simpler same-container profile must document its weaker process/network boundary rather than claim equivalence.

Enforce connection-time destination policy for HTTP/HTTPS/WebSocket redirects, subframes and resources. Deny loopback, private, link-local, reserved, metadata and IPv4-mapped IPv6 destinations, plus local-file/non-web protocols. Prevent proxy bypass, direct UDP/QUIC and alternate transport routes from defeating policy; log transport suppression because it may change site behaviour. DNS rebinding and redirect checks must be tested at the gateway/network boundary. Page routing alone is insufficient. Internal coordinator/database communication is a separately permitted application path.

Mount only necessary collector artifacts/configuration. No SSH keys, cloud credentials, personal browser profiles, unrelated repositories, home directory, GPU devices or Docker socket. Bound downloads, PIDs, shared memory, process runtime and disk. Retain captured cookies/tokens as restricted artifacts if required; redact them from general logs and ordinary exports. Restrict raw captured HTML viewing in the analyst UI so hostile scripts cannot execute with the UI's privileges.

Disable unintended telemetry and unconfigured external provider/model calls where supported, and verify actual outbound behaviour. Pin reviewed package/browser/image combinations and record licences and hashes. Keep a tested known-good release and rollback. Test updates against fixtures before promotion. Adapt seccomp/user/sandbox settings to the actual rootless kernel; do not weaken isolation silently. [R9, R10]

AI is optional and downstream. Supply bounded excerpts with headings/labels and references to preserved originals. Treat page text as data, not instructions. Validate structured AI outputs. An AI agent may propose a new capture recipe in development, but page content cannot grant shell access, change egress, install code or invoke payment/credential actions. Script changes require review and fixture validation, not self-modification of a running collector.

## 14. Configuration and resource policy

The following YAML defines **the collector application's policy schema**, not upstream Crawlee/Scrapling options to paste unchanged. The coder must implement schema validation and explicit mappings to the pinned libraries.

```yaml
schema_version: 1
project: cyber-web-collector
profile: browser_evidence
external_providers_enabled: false
ai_required_for_collection: false
limits:
  browser_slots_global: 2
  alternate_browser_slots_max: 1
  http_concurrency_global: 8
  top_level_concurrency_per_domain: 1
  per_domain_delay_seconds: 3
  http_attempts_max: 2
  browser_attempts_max: 2
  acquisition_attempts_max: 4
  active_acquisition_seconds_max: 180
  http_attempt_seconds: 15
  primary_browser_seconds: 60
  alternate_browser_seconds: 90
  finalisation_reserve_seconds: 15
  child_pages_per_target_max: 2
capture:
  viewport: {width: 1440, height: 1000}
  device_scale_factor: 1
  original_format: png
  original_service_workers: allow
  block_ads: false
  suppress_render_resources: false
  full_image_megapixels_max: 20
  scroll_tiles_max: 6
  individual_text_body_mib_max: 5
  attempt_artifacts_mib_max: 50
storage:
  captures_gb_soft_limit: 80
  host_free_gb_pause_below: 30
  host_free_gb_resume_above: 40
  delete_case_hold_artifacts: false
queue:
  heartbeat_seconds: 10
  lease_seconds: 120
  reclaim_expired_leases: true
```

A permit covers browser work through finalisation. Navigation/interaction/screenshot timeouts cannot each consume the entire attempt budget; all use the remaining time. Backoff/operator waiting must not retain a browser slot. `Retry-After` overrides the ordinary revisit delay. Prevent CPU-heavy HTTP parsing/OCR from bypassing resource caps. Derive request/resource/redirect/event-count bounds in the same validated policy before deployment.

For a selected Scrapling adapter, review actual pinned-version defaults. Explicitly disable artificial Google referrers for neutral captures, resource suppression and ad blocking; preserve consistent session settings. Its persistent contexts must not be shared between unrelated targets. Verify screenshot/HAR/body/sandbox behaviour independently rather than assuming normal Playwright compatibility. [R5]

## 15. Storage, provenance, backup and retention

Use the actual confirmed persistent ext4 path, not an assumed host mount. Store one immutable attempt directory containing metadata, raw/rendered content, screenshots/tiles, element crops, requests JSONL, HAR, body artifacts, extraction results, action log and manifest. A valid filename with a failed artifact still requires an explicit status; do not invent missing files.

For every artifact record type, relative path, observed interval, size, SHA-256, source attempt, creation method, completeness and limitations. Original captures remain separate from crops, OCR, annotations, redactions, thumbnails and AI summaries. Derived crops point to source images; if captured directly from a live element at a different time, identify them as separate observations.

The 80 GB artifact limit is a soft starting allocation, subordinate to real host free space. Budget database/WAL, images, temporary files, logs and backup staging as well. Pause at less than 30 GB free and resume above 40 GB. Apply low-priority admission control before urgent tasks exhaust storage. An artifact-directory size check alone is not a hard disk quota: implement enforceable filesystem/service budgets where available, and bounded writers regardless.

Case holds override routine deletion. When holds consume capacity, stop/defer or use an existing approved independent destination; never silently delete held evidence. For ordinary data, retention follows a configured policy and actual byte growth; metadata must record expiry/deletion. Content-addressed deduplication may save space but must preserve attempt attribution and reference counts for held evidence. Do not use screenshot perceptual similarity alone to delete original evidence.

Back up PostgreSQL and manifests and retain required originals on independent storage if available. Test restore with artifact/hash reconciliation. A backup on the same disk is not disaster recovery. Report recovery objectives and last successful backup; if no independent destination exists, explicitly report the remaining single-disk risk. Single-host recovery is not high availability.

## 16. Observability and operating rules

Measure useful results rather than only HTTP status or process uptime:

| Signal | Required interpretation |
|---|---|
| Required-artifact completion rate | Fraction of due evidence-profile jobs with actual validated required artifacts; report blocked/unavailable/infrastructure cases separately |
| Target-content coverage | Content captured versus challenged/login/empty/incomplete outcomes; denominator and target mix disclosed |
| Screenshot yield and failure categories | Valid original/element/full-or-tiled outputs; blank/timeout/truncated states separately |
| Identifier quality | Per-field observed/absent/failed states and audited false matches, especially adaptive/OCR results |
| Adapter benefit | Incremental successful recoveries from fallback divided by its attempts, with CPU/time/bytes cost |
| Schema/content drift | Sudden field-count/text/DOM change on comparable monitored sites; not a global threshold imposed on unrelated sites |
| Queue health | Oldest due job, priority backlog, lease loss, repeated failures and duplicate commits prevented |
| Resource health | Actual CPU/RSS/PIDs/I/O, free disk and artifact growth, worker stalls and backup age |

Keep metrics local initially; a Prometheus/Grafana stack is optional, not mandatory. Emit structured bounded logs and a daily JSONL/CSV status export. If notifications are connected, alert on sustained drift, stalled jobs, resource pause and failed recovery through the configured channel; do not silently send data to new services.

Use Compose restart policy and an in-process watchdog. A Docker healthcheck reports unhealthy status but does not by itself restart an otherwise running unhealthy container. Exit/recycle a demonstrably stuck worker with lease-safe recovery. Recycle long-lived browser processes after a bounded age/job count or abnormal memory growth. A liveness check is not a successful acquisition check.

Run separate controlled canaries: simple static HTML, JS hydration, QR/element screenshot and network recorder. A live target failure should not alone trigger global worker restart. A known-good HTTP canary cannot prove browser screenshot correctness.

## 17. Capacity expectations and scale decisions

Planning arithmetic only; validate on this VM:

- Two browser slots × 86,400 seconds/day × 50% planned utilisation ÷ 30–60 seconds/visit gives approximately **1,440–2,880 browser visit attempts/day**. At 90 seconds, approximately 960.
- These are attempts, not guaranteed successful bundles. If usable yield is `y`, expected useful visits are attempts × `y`; multiple attempts/pages/devices per target reduce distinct-target throughput further.
- Thousands of lightweight HTTP fetches are a different service level from thousands of screenshot/DOM/network bundles. Report both separately.
- At an illustrative 3,000 retained bundles/day averaging 5 MB each, growth is about 15 GB/day; an 80 GB allocation lasts about 5.3 days before overhead/holds. Failed/fallback attempts add bytes too.
- At 10,000 bundles/day at that size, 50 GB/day makes sustained local retention infeasible on this disk. More storage and measured compute capacity are needed.

Benchmark ordinary, JS-heavy, challenge, dead and image-heavy targets separately. Do not infer performance from a vendor's easy-site demo, desktop speed or a GPU specification. If CPU remains busy with other workloads, reduce acquisition slots rather than allowing the collector to damage other projects. If queues grow because of storage or network restrictions, adding browser workers may make the problem worse.

## 18. AI-coder implementation and acceptance plan

### Phase A — inspect and establish the baseline

Inventory the actual OS, existing app/runtime, rootless daemon/context, cgroups/delegation, allocation, mounts, current services, ports and network. Produce a small compatibility record. Reuse existing supported infrastructure. Do not install a large model, change other projects, disable a system daemon, add a paid provider, or assume a fresh machine.

Implement the job ledger, importer/exporter, primary Crawlee/Playwright worker, artifact contract and gateway. Use documented pinned APIs. Keep HTTP and browser modes distinct. Implement guarded exact-URL handling before domain expansion. Provide health endpoints and tested lease recovery.

### Phase B — validate evidence, then add selective alternatives

Implement staged screenshots, deadline salvage, frame/popup/service-worker events, per-artifact outcomes, QR/OCR, conservative extraction and drift checks. Test all against local controlled fixtures. Compare one Scrapling/alternate-browser adapter against baseline on the same required artifacts; enable it only if it adds useful recovery without unacceptable resource/evidence degradation.

Do not run a test against unrelated random sites to claim a universal success rate. Use a representative 100–200 URL pilot plus fixtures, then a 24-hour run within the actual resource allocation. Keep the pilot list and evaluation criteria so results are repeatable.

### Phase C — acceptance checks

| Check | Passing requirement |
|---|---|
| Deep URL and fragment route | Exact supplied location preserved and relevant view attempted; no homepage substitution |
| Urgent task | First browser observation is not blocked behind enrichment/AI |
| HTTP 200 challenge or API returning HTML | Challenge/incomplete outcome; not successful target data |
| JS hydration/lazy/virtual list | Relevant visible content captured within policy; bounded coverage recorded |
| Navigation timeout with usable page | Best-effort screenshot/DOM preserved and incompleteness described |
| Screenshot and element crop | Decodable images, locator/frame/context provenance and correct temporal attribution |
| Multi-frame/popups/service workers/WebSocket | Supported events collected; unsupported gaps explicit; no missing-frame crash |
| Identifier/adaptive/OCR | Known fixture values correct; wrong relocation or uncertain digits not promoted to confirmed identifiers |
| Retry multiplication | Shared caps respected across all engines and their internal retries |
| Cookie isolation/session continuity | Different targets isolated; same target flow retains its own coherent session |
| Lease loss and worker kill | Old worker cannot commit over new ownership; completed artifacts retained and interrupted attempt recorded |
| Crash during artifact/database commit | Reconciler handles both orphan directories and pending records |
| OOM/disk full/database outage | Bounded resource use, admission pause/recovery, no silent job disappearance |
| Internal-access attempts | Redirect/rebinding/subresource/IPv6/alternate-transport tests cannot reach host/internal services |
| Sandbox/cgroup | Actual enabled sandbox and effective resource caps demonstrated |
| Case hold/retention/restore | Held evidence retained; authorised expiry recorded; independent restore verified if available |
| Free baseline | Operates with all commercial-provider/model credentials absent |

The operational target is zero silent result loss and explicit outcomes, subject to testing; do not advertise this as a guarantee against hardware/storage failure or as 100% site retrieval.

### Coder deliverables

Deliver source, dependency lockfiles, pinned Dockerfiles/Compose, `.env.example` without secrets, policy schema/defaults, database migrations, importer/exporter, acquisition adapters, screenshot/network recorder, extraction pipeline, fixture checks, benchmark report, recovery/backup instructions, rollback procedure and an operator runbook. Document every unavailable requirement before labelling the deployment ready.

Define a real CLI contract before documenting commands. The following commands are for the implemented project, not an existing off-the-shelf product. Use the observed rootless context name if different:

```bash
docker --context rootless info
docker --context rootless compose -p cyber-web-collector config
docker --context rootless compose -p cyber-web-collector build
docker --context rootless compose -p cyber-web-collector up -d --scale browser-worker=1
docker --context rootless compose -p cyber-web-collector ps
docker --context rootless compose -p cyber-web-collector exec coordinator node dist/cli.js import /input/urls.csv --profile browser_evidence
docker --context rootless compose -p cyber-web-collector exec coordinator node dist/cli.js export --date 2026-10-17 --format jsonl
```

The coder must supply the actual mounts, CLI implementation and validated configuration. Configure persistence/start-on-boot within the host's existing service policy; do not assume the rootless daemon remains running after logout. Do not use destructive teardown of persistent volumes as an upgrade or rollback step.

## 19. Principal corrections from the preceding version

1. Replaced the implication that more fetchers yield universal access with measured adapter-specific recovery and explicit residual limits.
2. Distinguished mandatory browser evidence from optional API/HTML optimisation; urgent URLs can bypass triage delay.
3. Added staged screenshot salvage, lazy/virtual-page limits, independently timed artifacts and per-artifact validation.
4. Added challenge-header/content validation and session/vantage consistency; a 200 or 403 alone is not a verdict.
5. Made retry budgets phase-specific and shared, preventing nested retries and routine triage from consuming all browser opportunity.
6. Added fencing tokens, at-least-once visit semantics and filesystem/database crash reconciliation.
7. Replaced vague resource sharing with an aggregate CPU/memory envelope and cross-adapter browser permits.
8. Added complete network/DOM/frame/service-worker handling requirements, with Chromium-only capability limits.
9. Separated observed, absent, failed and uncertain identifier states; adaptive matching cannot erase substantive recipient changes.
10. Added concrete pilot/failure-injection checks, quota/backpressure rules and a complete coder delivery contract.

## 20. Video references and review provenance

Reviewed 17 October 2026. Transcripts may contain errors; technical decisions were checked against the primary sources below. The public mirror is a transcription access route, not independent corroboration of a video's claims. Timestamps refer to that retrieved transcript and are approximate.

- **V1:** https://www.youtube.com/watch?v=k-EkfZBVe3U — Shade of Code; approximately 2:47; transcript reviewed.
- **V2:** https://www.youtube.com/watch?v=hHQlcnubuFI — CodeHead; approximately 4:53; transcript reviewed.
- **V3:** https://www.youtube.com/watch?v=lNePj4yxx-c — Oxylabs; approximately 12:24; transcript reviewed.
- **V4:** https://www.youtube.com/watch?v=_VsSbpTXytA — Rob The AI Guy; approximately 11:51; transcript reviewed.
- **V5:** https://www.youtube.com/watch?v=l87PznsmM-g — ByteGrad; approximately 24:53; transcript reviewed.
- **V6:** https://www.youtube.com/watch?v=JaDeNHaBlaU — ScrapeOps; approximately 3:29; transcript reviewed.

Transcript access pages use `https://youtubetotranscript.com/transcript?v=VIDEO_ID` for the six IDs above. Full video transcripts and captured website data are not included in this deliverable.

## 21. Primary references and component review notes

The design recommendations above are engineering judgments for this machine; primary documentation verifies specific capabilities and limitations, not the performance of an unbuilt system. Verify release-specific behaviour when producing the lockfiles.

| Ref | Source | Verified design relevance |
|---|---|---|
| R1 | https://github.com/apify/crawlee | Free open-source crawler framework and browser integration |
| R2 | https://crawlee.dev/js/docs/guides/scaling-crawlers | Explicit concurrency/rate and resource scaling controls |
| R3 | https://playwright.dev/docs/network | Requests/responses, proxy configuration, redirects, WebSocket and interception limits |
| R4 | https://playwright.dev/docs/screenshots and https://playwright.dev/docs/api/class-page | Full-page/element capture and screenshot API settings |
| R5 | https://scrapling.readthedocs.io/en/latest/fetching/dynamic.html ; https://scrapling.readthedocs.io/en/latest/fetching/stealthy.html ; https://scrapling.readthedocs.io/en/latest/parsing/adaptive.html | Browser hooks, profiles, resource settings, session behaviour and adaptive-match limitations |
| R6 | https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/ | `cf-mitigated: challenge` and HTML challenge responses |
| R7 | https://developers.cloudflare.com/cloudflare-challenges/concepts/clearance/ | Visitor/device-bound clearance and its limitations |
| R8 | https://playwright.dev/docs/service-workers and https://playwright.dev/docs/api/class-browsercontext | Context/service-worker events, behaviour changes when disabled, Chromium-only CDP |
| R9 | https://playwright.dev/docs/docker | Non-root/sandbox/seccomp guidance and package/browser version matching |
| R10 | https://docs.docker.com/engine/security/rootless/ and https://docs.docker.com/engine/security/rootless/tips/ | Rootless prerequisites and resource-control/delegation conditions |
| R11 | https://www.postgresql.org/docs/current/sql-select.html | Row-lock/SKIP LOCKED building block; application must implement leases and fencing |
| R12 | https://github.com/lexiforest/curl_cffi | TLS/HTTP fingerprint-oriented client; distinct from a screenshot browser |
| R13 | https://github.com/FlareSolverr/FlareSolverr | Browser helper and documented CAPTCHA limitations; not a required component |
| R14 | https://github.com/Decodo/mcp-server | Connector depends on provider credentials/infrastructure; not unlimited local acquisition |
| R15 | https://docs.firecrawl.dev/contributing/self-host | Release-specific self-hosted capabilities and external engine requirements |
| R16 | https://github.com/webrecorder/browsertrix-crawler and https://github.com/Lookyloo/lookyloo | Optional archiving and analyst investigation components |
| R17 | https://oxylabs.io/blog/best-web-scraping-tools and https://scrapeops.io/web-scraping-playbook/how-to-bypass-cloudflare/ | Provider explanations of acquisition categories; commercial claims are not this deployment's benchmark |
| R18 | https://github.com/projectdiscovery/subfinder ; https://github.com/elceef/dnstwist ; https://github.com/projectdiscovery/katana ; https://github.com/projectdiscovery/httpx | Optional bounded discovery/triage components, not replacements for browser evidence |

Retain licence notices and record actual pinned versions. Crawlee/Playwright use Apache-2.0 licences and Scrapling uses BSD-3-Clause in the reviewed repositories; dependencies/browser binaries require their own notices. A commercial cloud offering does not mean its public connector includes the cloud service. Keep paid/model API credentials absent in the baseline.
