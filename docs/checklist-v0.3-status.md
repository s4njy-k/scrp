# v0.3 Improvement Checklist — implementation status

Status of every item in *Cybercrime Platform v0.3 Improvement & Correction Checklist*, as the
checklist requires (`Done`, `Partially done`, `Not done`, `Not applicable`, each with a code
reference, test evidence and a reason). Read together with
[`deployment-readiness.md`](deployment-readiness.md), which lists what can only be closed on the
target VM.

**Rules applied.** An item is `Done` only when the code exists **and** an automated test exercises
it. Anything that depends on the real host, institutional services, a labelled corpus or a
production baseline is never marked `Done` from the repository alone. Paths are relative to the
repository root. Test names are abbreviated as `file › test`.

**Baseline.** The repository had no earlier web UI or analyst API ("v0.3" here means the collector
delivered in the first two pull requests: queue, gateway, browser capture, extraction, export). No
existing endpoints, CLI commands or data were removed. All database changes are additive,
versioned migrations (`db/migrations/0003`–`0008`). CI runs typecheck, policy-schema and OpenAPI
currency checks, the full unit, integration and browser test suite, an npm audit, an SBOM build, an
image build and compose validation (`.github/workflows/ci.yml`).

---

## 0. Existing project audit and safe change management

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 0.1 | P0 | Inventory routes, schema, engines, queues, services | Done | `docs/architecture.md`, `docs/openapi.json`, `compose.yaml` | `openapi.test.ts › documents every route and nothing else` | The route inventory is generated from the live router and fails CI if it drifts |
| 0.2 | P0 | existing → gap → change → test → rollback matrix | Done | this file, `docs/rollback.md` | — | Rollback: migrations are additive; the console is an opt-in Compose profile |
| 0.3 | P0 | Production baselines (success by failure type, latencies, resources, clicks) | Not done | `docs/benchmark-report.md` (template), `GET /api/v1/analytics`, `/api/v1/metrics` | — | No production deployment was reachable. The instruments now exist; baselines must be recorded on the VM (readiness A7/A8) |
| 0.4 | P0 | Tested backup and restore before migrations | Partially done | `scripts/backup.sh`, `scripts/restore-verify.sh`, `docs/recovery-and-backup.md` | Scripts parse in CI | Needs an independent destination and a real restore on the host (readiness A10) |
| 0.5 | P0 | Small additive changes, versioned migrations, flags, stable contracts | Done | `db/migrations/0003…0008`, `config/policy.default.yaml` (`web`, `governance`, `monitoring`, `enrichment`), Compose profile `console` | Whole suite passes on fresh migrations | Enrichment CT search, autosend and auto-takedown default off; governance literals cannot be switched on |
| 0.6 | P0 | No assumed GPU, extra VM, paid proxy, public domain, private API, unlimited storage | Done | `src/config/policy.ts` (literal `false` for paid providers), `docs/security.md` | `policy.test.ts › refuses … enabling unimplemented providers` | Public egress IP is recorded only if the operator declares it (`EGRESS_PUBLIC_IP`) |
| 0.7 | P0 | Preserve the rootless Compose deployment; isolate changes | Done | `compose.yaml` (`api` under profile `console`, loopback port, resources reallocated) | CI `compose config` with both profiles | Aggregate stays at ~2.0 vCPU / 9.75 GiB |

## 1. Evidence integrity, provenance and admissibility readiness

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 1.1 | P0 | Unique immutable IDs per attempt, revisit, artifact; never overwrite originals | Done | `src/storage/artifactStore.ts`, `src/monitoring/monitor.ts` (revisits are new jobs) | `artifactStore.test.ts › refuses writes after finalisation…`; `monitoring.test.ts › schedules proportionate revisits as new low-priority jobs…` | Files are written `0440`, `wx` |
| 1.2 | P0 | SHA-256 of saved bytes, size/type/path, re-verify after write | Done | `artifactStore.ts` (post-rename re-verification, `verifiedAtCommit`) | `artifactStore.test.ts › hashes saved bytes…`; `evidence.test.ts › writes a v2 manifest…` | `artifacts.verification_state` records the result |
| 1.3 | P0 | Versioned manifest: inputs, final URL, UTC/IST, engine, profile, egress, redirects, failures, limitations | Done | `src/evidence/manifestContext.ts`, manifest v2 | `evidence.test.ts › writes a v2 manifest with the exact original input, capture context, clock and IST time` | — |
| 1.4 | P0 | Seal the manifest without self-reference; parent index; detect modification | Done | `src/evidence/package.ts` (index hash stored outside the index), ledger `manifest_sha256` | `evidence.test.ts › builds a package whose index is hashed outside itself…`; `Verify Evidence … fails on modified or missing files` | — |
| 1.5 | P0 | Originals separate from derivatives; derivatives reference originals with own hash | Done | `src/extraction/thumbnail.ts` (`derived_from`), `annotations` table | `evidence.test.ts › …makes thumbnails…` | Notes never modify evidence (append-only trigger) |
| 1.6 | P0 | Append-only custody trail for import, capture, access, processing, verification, export, hold, deletion | Done | `src/db/pool.ts` `audit()` with actor/object/case/outcome/request id; `0003` trigger | `evidence.test.ts › chains every event, refuses edits and deletes…`; `api-investigation.test.ts › serves evidence only after re-verifying hashes…` | Reads of evidence, searches and downloads are audited |
| 1.7 | P0 | Tamper-evident chained hashes; external checkpoints; no WORM claim | Done | `src/evidence/custody.ts` (seal, Ed25519 checkpoints), `cli custody …` | `evidence.test.ts › …detects rewrites against a signed checkpoint` | Statement in API and docs: tamper-evident relative to externally held checkpoints, not WORM. Storing checkpoints outside admin control is an institutional step (readiness A16) |
| 1.8 | P0 | Verify Evidence action and exported result | Done | `src/evidence/verify.ts`; `POST /api/v1/captures/:id/verify`, `/cases/:id/verify`; UI button | `evidence.test.ts › Verify Evidence passes…`; `ui-smoke.test.ts` | Report is hashed and downloadable |
| 1.9 | P1 | Clock sync status and uncertainty; UTC stored, IST rendered | Partially done | `cli clock record|show`, manifest `clock`, `src/evidence/time.ts` | `evidence.test.ts › renders IST without daylight saving…` | The clock fact is recorded by the operator (`preflight.sh`); without it manifests say "not verified". No timestamp authority (not approved) |
| 1.10 | P1 | BSA s.63 fact sheet and Part A/B worksheet; no auto-fill/sign | Done | `src/actions/certificate.ts`, `/api/v1/certificates…`, UI worksheet | `api-actions.test.ts › prepares Section 63 fact sheets and worksheets without signing or inventing particulars` | Field list was transcribed from the Schedule structure; an approver must record a check against the official text before any worksheet can be completed (readiness A15) |
| 1.11 | P1 | Separate draft/verified/signed/submitted states; signed copy and hash report hashed separately | Done | `certificates`, `certificate_events`, `uploads` | `api-actions.test.ts` (same test) | States: draft → completed → signed → attached_to_submission |
| 1.12 | P1 | Actual WARC/WACZ for selected cases | Not done | — | — | Optional separate workflow (readiness B5). HAR stays HAR and is labelled so |
| 1.13 | P1 | Retention classes and legal holds; exports verifiable after cleanup | Done | `src/coordinator/retention.ts` (`CITED_ATTEMPT_SQL`), `cases/:id/hold`, packages | `retention.test.ts › keeps evidence when a seed merged into the job belongs to a held case`; package offline verification test | Evidence cited by notices, certificates or open cases is never expired |

## 2. Reliable access, capture quality and screenshots

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 2.1 | P0 | Exact URL kept with a separate dedup key | Done | `src/importer/url.ts`, `seeds` provenance | `url.test.ts › preserves exact deep path…`; `queue.test.ts › …merges duplicate seeds without losing provenance` | — |
| 2.2 | P0 | SSRF protection at the egress layer incl. redirects and rebinding | Done | `src/gateway/` | `browserCapture.test.ts › refuses page subresources and redirects aimed at internal/metadata addresses`; `gateway.test.ts` | Network-level isolation on the VM is readiness A5 |
| 2.3 | P0 | Real browser when needed; cheap HTTP path otherwise | Done | `src/router/router.ts`, `src/acquisition/httpTriage.ts` | `router.test.ts › data_triage completes from HTTP alone…` | — |
| 2.4 | P0 | Early viewport screenshot, settled screenshot, salvage | Done | `src/capture/browserCapture.ts`, `recordFirstImage` | `browserCapture.test.ts › preserves a best-effort screenshot and DOM when navigation never finishes`; `api-investigation.test.ts › …serves the first image…` | — |
| 2.5 | P0 | Outputs verified separately; never `complete` with a missing required artifact | Done | `router.ts` contract | `router.test.ts › requires actual validated files…`; `artifactStore.test.ts › downgrades an entry whose file vanished…` | — |
| 2.6 | P0 | Original/final URL, status, DNS/TLS, redirect chain, time, title | Done | manifest v2, `redirects` edges | `evidence.test.ts`; `browserCapture.test.ts` | — |
| 2.7 | P0 | Explicit outcome classes incl. parked/suspended | Done | `router.ts`, `src/router/signals.ts` (`detectPlaceholderPage`) | `router.test.ts › recognises placeholder pages…`; `…keeps placeholders as their own observations…` | ISP block notices are a vantage-specific block |
| 2.8 | P0 | Detect empty, placeholder, CAPTCHA, challenge pages despite HTTP 200 | Done | `signals.ts` | `router.test.ts › HTTP 200 challenge is a challenge outcome…`; `browserCapture.test.ts › records a challenge interstitial…` | — |
| 2.9 | P0 | Bounded timeouts, failure-specific retries, attempt budget | Done | `src/config/policy.ts`, `router.ts`, `queue.ts` | `router.test.ts › caps attempts across phases`; `queue.test.ts › charges the shared budget at lease time…` | — |
| 2.10 | P0 | Capture context: viewport, UA, versions, egress/vantage, locale, interactions | Done | `manifestContext.ts` (`captureContext`, `networkVantage`) | `evidence.test.ts › writes a v2 manifest…` | Public IP only when operator-declared |
| 2.11 | P1 | Full-page or bounded tiles; label incomplete coverage | Done | `browserCapture.ts` (`screenshot_full_or_tiles`) | `browserCapture.test.ts › captures hydrated JS content and lazy content…` | — |
| 2.12 | P1 | Mobile profile as an independent attempt | Done | `capture_variant` mobile/both | `monitoring.test.ts › captures a selected mobile profile as an independently recorded attempt` | Chromium only (readiness B11) |
| 2.13 | P1 | Modals, popups, iframes, lazy images, SPA routes; record interactions | Done | `browserCapture.ts`, `logs/action-log.json` | `browserCapture.test.ts › records frames, popups, service workers…` | — |
| 2.14 | P1 | Compare profiles/vantages on cloaking cases | Partially done | Investigation view *Compare captures*, `src/monitoring/compare.ts` | `ui-smoke.test.ts › renders every screen…` (desktop vs mobile side by side); `enrichment.test.ts › measures text and screenshot change` | Only the one configured vantage exists; a mobile UA is labelled as not a mobile-network vantage |
| 2.15 | P1 | Quarantine downloads; hash; never execute | Partially done | `browserCapture.ts` (`acceptDownloads: false`) | — | Downloads are refused, so nothing executes. APK/document capture into a quarantine store is not implemented |
| 2.16 | P1 | Approved, auditable egress; no unvetted proxies | Done | gateway, `EGRESS_VANTAGE_LABEL`, `EGRESS_PUBLIC_IP` | `gateway.test.ts` | — |
| 2.17 | P1 | Transparent "reason for missing data"; no 100% promise | Done | manifest `limitations`, artifact `error`/`limitations` | `browserCapture.test.ts`; evidence view shows limitations | — |

## 3. Accurate extraction of investigative leads

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 3.1 | P0 | DOM/text/QR first; targeted OCR; LLM unverified | Done | `src/extraction/runner.ts` | `extraction.test.ts › never promotes OCR values to confirmed identifiers` | No LLM (policy forbids) |
| 3.2 | P0 | UPI VPAs and full `upi://pay` QR payloads; QR vs displayed conflicts | Done | `identifiers.ts`, `runner.ts` (`conflicts`) | `evidence.test.ts › preserves a QR payee that differs from the displayed payee, flags the conflict…` | — |
| 3.3 | P0 | Phone, WhatsApp, Telegram, email, social; raw + normalised | Done | `identifiers.ts`, `validators.ts` (libphonenumber max metadata) | `extraction.test.ts › normalises phones…`; `investigation.test.ts › normalises internationalised email domains…` | — |
| 3.4 | P0 | Bank account, IFSC, payment-gateway merchant IDs as candidates | Done | `identifiers.ts` (`bank_account`, `ifsc`, `payment_gateway_id`) | `extraction.test.ts › extracts and validates Indian payment identifiers`; `investigation.test.ts › extracts gateway merchant candidates…` | Razorpay, Paytm, Cashfree, Instamojo references; all unvalidated candidates |
| 3.5 | P1 | Network-aware crypto validation; no EVM chain inference | Done | `validators.ts` (keccak256/EIP-55, base58check) | `investigation.test.ts › checks EIP-55 and never infers an EVM chain` | — |
| 3.6 | P1 | GTM/GA, Pixel, AdSense, widgets, app links, favicon/template hashes as signals | Partially done | `identifiers.ts` (`SIGNAL_ONLY_FIELDS`, `domTemplateHash`) | `investigation.test.ts › extracts operator signals…` | Favicon hashing is not implemented |
| 3.7 | P1 | Brand claims with affiliate/official/parked exemptions | Done | `src/investigation/brands.ts`, `config/brands.yaml`, `risk.ts` benign context | `investigation.test.ts › …exempts official/affiliate domains`; `…applies the benign-context checklist…` | Brand list must be curated by the agency |
| 3.8 | P0 | Provenance per identifier (capture, artifact, locator/bbox, time, raw, normalised, validation, extractor version) | Done | `identifiers` columns (`source_artifact_id`, `extractor_version`, `value_key`, bbox) | `browserCapture.test.ts › captures a QR element crop with locator, frame URL and bounding box` | — |
| 3.9 | P0 | Confidence and unverified/candidate/corroborated/rejected; conflicts visible | Done | `confidenceFor`, `identifier_reviews`, investigation view | `api-investigation.test.ts › captures, streams progress… builds the investigation view` | — |
| 3.10 | P0 | Copyable values that open the exact region/source | Done | investigation view (copy with source, bbox highlight) | `ui-smoke.test.ts` | — |
| 3.11 | P1 | Analyst correction/rejection without editing evidence | Done | `POST /api/v1/identifier-reviews` (append-only) | `api-investigation.test.ts` | — |
| 3.12 | P1 | Regression fixtures for Indian phones, IDN email, UPI QR, OCR errors, IFSC ambiguity, wallets, fake brands | Done | `test/unit/extraction.test.ts`, `investigation.test.ts`, `test/fixtures/` | listed tests | — |

## 4. DNS, domain, hosting and infrastructure enrichment

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 4.1 | P1 | RDAP registrar, abuse contacts, redaction, confidence | Done | `src/enrichment/enrich.ts` (IANA bootstrap) | `enrichment.test.ts › parses RDAP registrar, abuse contact, redaction and CDN heuristics…` | Registrant identity never assumed |
| 4.2 | P1 | Current DNS records and reverse DNS with timestamps; passive DNS only from permitted sources | Partially done | gateway `/__dns`, `enrichment_results` | `enrichment.test.ts › serves bounded DNS lookups…` | No passive DNS source is authorised, so none is used |
| 4.3 | P1 | Live TLS issuer, dates, fingerprint, SANs vs CT history | Done | `fetchCertificate` through a CONNECT tunnel | `enrichment.test.ts › records the live certificate…` | CT search is opt-in (`enrichment.certificate_transparency`), labelled historical |
| 4.4 | P1 | ASN/hosting/CDN classification with contacts and citations | Done | RDAP IP lookup, CDN heuristic, `suggestAddressees` | `enrichment.test.ts` | — |
| 4.5 | P1 | CT subdomain candidates and passive DNS leads, not treated as active | Partially done | opt-in CT | — | Off by default (third-party service); no passive DNS |
| 4.6 | P1 | Historical origin-IP candidates as hypotheses only | Not applicable | — | — | No historical-resolution source is configured. Documentation states any origin IP would be a hypothesis |
| 4.7 | P1 | Asynchronous after first screenshot; cache with TTL and source errors | Done | `enrichPending` (coordinator, 30 s), `enrichment_results` TTL | `enrichment.test.ts` | — |
| 4.8 | P1 | Correct addressee per role | Done | `GET /api/v1/targets/:id/addressees` | `enrichment.test.ts › …suggests role-specific addressees` | — |

## 5. Correlation, campaign discovery and false-positive prevention

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 5.1 | P1 | Search every historical capture by identifier, domain, case, date | Partially done | `GET /api/v1/entities` (exact/contains, case scope), jobs filters | `api-investigation.test.ts › scopes entity search to the viewer…` | No date-range filter on entity search |
| 5.2 | P1 | Explainable relational graph | Partially done | `src/investigation/correlation.ts` (edges with type, strength, rarity, dates) | `correlation.test.ts › groups only on corroborating uncommon identifiers…` | Relational, computed on demand; no graph visualisation (P2, deferred) |
| 5.3 | P1 | Provenance, date, edge type, strength, contradictions per relation | Done | `relatedTargets` output | `correlation.test.ts` | — |
| 5.4 | P1 | Group only on multiple corroborating identifiers; possible vs confirmed | Done | `correlation.ts` (≥2 strong or strong + medium) | `correlation.test.ts` | Always labelled `possible_relationship` |
| 5.5 | P1 | Typosquat, homoglyph, punycode alerts with exemptions | Done | `brands.ts` `findLookalikes` | `investigation.test.ts › detects homoglyph, punycode, typosquat and combosquat…` | — |
| 5.6 | P0 | Separate capture quality, suspicion, legal eligibility; versioned rationale | Done | `risk.ts` (`policy_version`, signals), `legalRoutes.ts` | `investigation.test.ts › scores a payment lure…with labelled evidence for every signal` | — |
| 5.7 | P0 | Mandatory FP/benign/uncertain outcome; suppression; override on new evidence | Done | `src/investigation/decisions.ts` | `api-investigation.test.ts › records append-only decisions, suppresses false positives and requires new evidence to override` | — |
| 5.8 | P0 | Never recommend suspension from weak signals or a score alone | Done | `risk.ts` (infrastructure weight 0), eligibility needs an analyst verdict | `investigation.test.ts › …never lets infrastructure-only signals score`; `api-actions.test.ts` | — |
| 5.9 | P1 | Precision against a labelled corpus | Not done | — | — | No labelled corpus is available. Needs agency-supplied examples (pilot) |

## 6. Case management, official reports and action routing

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 6.1 | P0 | Link to authorised case with NCRP/FIR refs, access control, masking | Done | `0004_access_and_cases.sql`, `src/web/authz.ts` | `api-auth.test.ts › enforces case-level object authorisation and masks restricted references…` | — |
| 6.2 | P1 | Separate draft templates per route | Done | `src/actions/legalRoutes.ts` (10 routes), `report.ts` | `api-actions.test.ts` | — |
| 6.3 | P0 | Facts, exact targets, basis, authority, jurisdiction, recipient, necessity/proportionality, approval before issue | Done | `checkEligibility` | `api-actions.test.ts › blocks ineligible drafts…` | — |
| 6.4 | P0 | s.69A as restricted statutory route with grounds | Done | `SECTION_69A_GROUNDS`, recipient `government_nodal` only | `api-actions.test.ts › …s.69A requests without a prescribed ground` | — |
| 6.5 | P0 | s.79(3)(b) vs voluntary complaints; verify rule text and authority | Done | route `it_act_79_3_b_intimation` (`current_rules_verified`, officer authorisation) | eligibility unit path in `api-actions.test.ts` | Rule text must be re-verified at issuance by people |
| 6.6 | P0 | BNSS s.94 vs voluntary preservation; no compulsory or cross-border demands | Done | routes `bnss_94_production`, `preservation_request` (cross-border channel check) | eligibility checks | The system never issues; it drafts |
| 6.7 | P1 | English/Hindi templates with ref, date, authority, targets, hashes, annexures | Partially done | `report.ts` (`language` en/hi/en_hi) | `api-actions.test.ts` | Hindi headings only; body text needs approved human translation |
| 6.8 | P1 | Batch notices to one recipient with per-target grounds and status | Done | `notice_targets` (legal ground, status per target) | `api-actions.test.ts` | — |
| 6.9 | P0 | Maker-checker; explicit dispatch; no autosend/auto-suspend | Done | `TRANSITIONS` (`notCreator`), governance literals | `api-actions.test.ts`; UI disables self-review | — |
| 6.10 | P1 | Lifecycle with immutable author/approver/time and receipt proof; issued ≠ complied | Done | `notice_events`, dispatch/receipt uploads, verified closure needs a fresh capture | `api-actions.test.ts` | — |
| 6.11 | P1 | Legal deadlines only when applicable and receipt-based; separate internal SLAs | Partially done | `lawful_deadline` (as stated), `received_at`, `internal_followup_at` labelled | `api-actions.test.ts` | Deadlines are recorded, not calculated: the system does not compute statutory periods |
| 6.12 | P1 | PDF/DOCX/JSON/CSV exports with formula-safe CSV | Partially done | `report.ts` (Markdown, script-free HTML, JSON, CSV), `csvCell` | `api-actions.test.ts` (formula injection escaped) | No PDF/DOCX generator (would need a new dependency); the HTML is print-ready |

## 7. Analyst workflow, permissions and accountability

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 7.1 | P0 | Fast single-target investigation view | Done | `web/js/views/investigate.js`, `/targets/:id/investigation` | `ui-smoke.test.ts`; `api-investigation.test.ts` | — |
| 7.2 | P0 | Three separate status fields everywhere | Done | `statusChips` (UI), `src/web/status.ts` | `investigation.test.ts › maps processing state and outcome to an explicit acquisition chip` | — |
| 7.3 | P0 | Review queue with retain/investigate/FP/inconclusive/recapture/escalate and reasons | Done | `/review-queue`, `/decisions` | `api-investigation.test.ts` | — |
| 7.4 | P1 | Side-by-side comparisons across time/profiles/vantages | Done | investigation view *Compare captures* | `ui-smoke.test.ts › renders every screen…` | Original images, unaltered |
| 7.5 | P1 | Bulk triage with preview, confirmation, per-target audit; no mass external action | Done | `/decisions/bulk` | `api-investigation.test.ts` | — |
| 7.6 | P0 | Least-privilege RBAC and object-level authorisation; MFA | Done | `src/web/authz.ts`, `auth.ts` (TOTP) | `api-auth.test.ts` (all four tests) | SSO/OIDC not available; TOTP MFA enforced |
| 7.7 | P0 | Log sensitive reads, downloads, protected searches, decisions, approvals | Done | `auditCtx` throughout routes | `api-investigation.test.ts › …requires a purpose for global searches and audits it` | — |
| 7.8 | P1 | Reason codes, annotations, history without rewriting | Done | `analyst_decisions`, `annotations`, `forbid_mutation()` | `api-investigation.test.ts` | — |
| 7.9 | P1 | NCRP/CFCFRMS/Suspect Registry only via authorised connectors | Not applicable | — | — | No connector is authorised; none is assumed |

## 8. Post-action monitoring and takedown verification

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 8.1 | P1 | Proportionate recaptures as new attempts | Done | `scheduleDueRevisits` | `monitoring.test.ts` | Minimum interval enforced |
| 8.2 | P1 | Before/after comparison incl. payees and acknowledgements | Done | `classifyRevisit` (identifiers, text shingles, dHash) | `enrichment.test.ts › separates still-live, changed payee, parked…` | — |
| 8.3 | P1 | Distinct outcome classes | Done | `monitoring_observations.outcome_class` | same | Provider confirmation requires an upload |
| 8.4 | P1 | Reappearance on new domains with evidence, not attribution | Done | `detectReappearance`, alerts | `correlation.test.ts › raises a reappearance alert…` | — |
| 8.5 | P1 | Urgent first captures above monitoring; pause under pressure | Done | revisit priority −10, admission checks | `queue.test.ts › pauses admission and admits only urgent work…` | — |
| 8.6 | P1 | Measure first-capture time, usable rate, precision, review time, acknowledgement, compliance, FP reversals | Partially done | `GET /api/v1/analytics` | `ui-smoke.test.ts` (analytics renders) | Verified-lead precision and time-to-review need labelled data and are not computed |
| 8.7 | P1 | Receipt-based follow-up histories per case and recipient | Done | `notice_events`, notices list | `api-actions.test.ts` | — |

## 9. Backend reliability, security and resource efficiency

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 9.1 | P0 | Durable intake: transactional enqueue, idempotency, leases, fencing, budget, reconciliation | Done | `queue.ts`, `importer.ts`, `/intake-batches` (Idempotency-Key) | `queue.test.ts`; `pipeline.test.ts › reconciles a crash…`; `api-investigation.test.ts › …durably and idempotently accepts intake` | — |
| 9.2 | P0 | No double commit; stale workers fenced | Done | fencing tokens | `queue.test.ts › fences a worker that lost its lease…`; `…commits idempotently` | — |
| 9.3 | P0 | Global browser permits across all adapters | Done | `global_permits` | `queue.test.ts › caps global browser permits across engines…` | — |
| 9.4 | P0 | Respect real cgroup limits; start at two browser slots | Partially done | `compose.yaml` caps, policy `browser_slots_global: 2` | `policy.test.ts` | Effective caps must be verified on the host (readiness A2/A6) |
| 9.5 | P0 | Reserve capacity for website/API/DB; heavy work async and lower priority | Done | API inside the envelope (0.1 vCPU / 512 MiB reallocated); enrichment, revisits and report generation asynchronous or request-scoped | compose validation in CI | — |
| 9.6 | P0 | Isolate rendering/downloads from DB, secrets, internal networks, Docker socket | Done | separate engine container, internal networks, gateway | `browserCapture.test.ts › routes browser loopback traffic through the gateway…` | Host verification readiness A4/A5 |
| 9.7 | P0 | Sessions, CSRF, validation, safe download headers, XSS-safe viewing, scoped links, no credential leakage | Done | `src/web/http.ts` (CSP, headers), `server.ts` (CSRF, Origin checks), downloads with `sandbox` CSP and attachment disposition; UI builds DOM with `textContent` only | `api-auth.test.ts › refuses requests without a CSRF token…`; `api-investigation.test.ts › …safe content handling`; `ui-smoke.test.ts` (no CSP violations) | Downloads use authenticated, audited, hash-checked endpoints instead of signed links |
| 9.8 | P0 | Safe CSV/XLSX import: malformed, oversized, formulas, bounded rows, per-row errors | Done | `src/importer/xlsx.ts`, `importer.ts` | `xlsx.test.ts › refuses non-XLSX input, zip bombs…`; `queue.test.ts › records every input line…` | — |
| 9.9 | P0 | Storage reservations, caps, disk-pressure pause, cleanup without touching held evidence | Done | admission control, byte budgets, retention | `artifactStore.test.ts › enforces the attempt byte budget…`; `retention.test.ts` | — |
| 9.10 | P0 | Health checks, graceful shutdown, persisted progress, recovery, structured failure codes | Done | Compose healthchecks (incl. `api`), `progress_*` columns, reconciler | `pipeline.test.ts`; `retention.test.ts › waits for an abandoned capture…` | — |
| 9.11 | P0 | Independent backups with real restore tests | Partially done | `scripts/backup.sh`, `restore-verify.sh` | — | Readiness A10 |
| 9.12 | P0 | Pinned versions, vulnerability and secret scans, least privilege, build IDs in evidence | Partially done | digests in Dockerfiles/Compose, exact npm pins, CI `npm audit` + SBOM + committed-secret check, non-root image, manifest `software`/engine version | CI `security` and `image` jobs | No container-image CVE scanner (would add a third-party tool; left to the agency's approved scanner) |
| 9.13 | P1 | Metrics: queue, stalled, errors, screenshots/hour, first-image p50/p95, verification failures | Done | `GET /api/v1/metrics` (Prometheus text) | `openapi.test.ts` (documented); manual check in the admin view | Memory/CPU/disk come from the host's cAdvisor/node exporter, not the app |
| 9.14 | P1 | Selective enrichment, OCR, archives, alternate profiles | Done | policy flags, router escalation rules | `router.test.ts` | — |

## 10. Website usability, speed and presentation

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 10.1 | P0 | Immediate durable acknowledgement of intake | Done | `/intake-batches` returns 202 after commit | `api-investigation.test.ts` | — |
| 10.2 | P0 | Stage-specific live progress via SSE | Done | `/jobs/events`, `liveStage` | `api-investigation.test.ts › captures, streams progress…` | — |
| 10.3 | P0 | First verified screenshot as soon as available, labelled partial/final | Done | `/attempts/:id/first-image` (`X-Evidence-Status`) | same | — |
| 10.4 | P0 | Searchable, filterable, server-paginated tables with chips | Done | `/jobs`, `/cases` (cursor pagination), UI tables | `ui-smoke.test.ts` | — |
| 10.5 | P0 | Thumbnails; lazy-load heavy artifacts | Done | thumbnails, `authImage` (IntersectionObserver), on-demand panels | `ui-smoke.test.ts` | — |
| 10.6 | P1 | Main screen focused on screenshot + identifiers + verdict/action | Done | investigation layout | `ui-smoke.test.ts` | — |
| 10.7 | P1 | Highlight findings in screenshot regions; copy with source | Done | bbox overlay, `copyWithSource` | `ui-smoke.test.ts` | Highlight needs a recorded bounding box (DOM element crops, QR) |
| 10.8 | P1 | Practical filters (case, date, category, brand, provider, risk, queue, state, notice status) | Partially done | jobs: case, state, outcome, verdict, URL; review queues; notices by state | — | No date-range, brand or registrar filters yet |
| 10.9 | P1 | Bulk import with duplicate preview and counts; scoped exports and API | Done | `dry_run=true`, per-line results, case-scoped API | `api-investigation.test.ts › previews, then durably and idempotently accepts intake…` | — |
| 10.10 | P1 | Responsive, accessible layout, consistent status colours, skeletons, keyboard | Done | `web/styles.css` (light/dark tokens, focus ring), skeletons, keyboard-activatable rows | `ui-smoke.test.ts` | No formal WCAG audit performed |
| 10.11 | P1 | Trustworthy charts: refresh time, denominators, scope, definitions, observed/inferred/confirmed/actioned | Done | `/api/v1/analytics`, analytics view | `ui-smoke.test.ts` | — |
| 10.12 | P1 | Benchmark API p95, first thumb, bundle size, memory, clicks vs v0.3 | Not done | — | — | No v0.3 UI existed to compare with; measurements belong to the pilot (readiness A7). The console has no build step or framework (about 140 KB of uncompressed JS and CSS) |
| 10.13 | P2 | Campaign graph/map visualisation | Not done | — | — | Deferred until a real investigative need is shown |

## 11. Final acceptance and regression

| # | P | Item | Status | Where | Evidence | Notes |
|---|---|---|---|---|---|---|
| 11.1 | P0 | Existing features, clients, data and permissions keep working | Done | additive migrations; CLI unchanged | Full suite (unit, integration, browser) | — |
| 11.2 | P0 | Static, SPA, deep links, mobile, popups, lazy, challenges, redirects, DNS failure, unavailable | Done | fixtures `test/fixtures/server.ts` | `browserCapture.test.ts`; `router.test.ts`; `monitoring.test.ts` | — |
| 11.3 | P0 | First-screenshot salvage, partial labelling, missing/corrupted artifacts | Done | — | `browserCapture.test.ts › preserves a best-effort screenshot…`; `evidence.test.ts › Verify Evidence…fails on modified or missing files` | — |
| 11.4 | P0 | Tampered image/HTML/manifest/package fail checks; notes leave originals unchanged | Done | — | `evidence.test.ts` (package tamper, Verify Evidence); append-only triggers | — |
| 11.5 | P0 | Worker kill, duplicate enqueue, concurrent leases, DB restart, gateway failure, low disk, interrupted upload | Partially done | — | `queue.test.ts`, `pipeline.test.ts › reconciles a crash…`, `gateway.test.ts › survives clients that reset…`, `retention.test.ts` | Real failure injection on the VM is readiness A9 |
| 11.6 | P0 | SSRF and rebinding enforced even if the browser ignores policy | Done | gateway | `browserCapture.test.ts › routes browser loopback traffic through the gateway, which refuses it` | — |
| 11.7 | P0 | Object-level access, expiry, cross-case isolation, audit, XSS handling, link restrictions | Done | — | `api-auth.test.ts`; `api-investigation.test.ts`; `ui-smoke.test.ts` | — |
| 11.8 | P0 | FP review blocks escalation; notices reject missing authority/grounds/approval; never auto-send | Done | — | `api-actions.test.ts › blocks notices for false-positive targets and s.69A requests without a prescribed ground` | — |
| 11.9 | P1 | Typed extraction precision against labelled examples | Partially done | unit fixtures | `extraction.test.ts`, `investigation.test.ts` | Fixture tests check correctness; a precision figure needs a labelled corpus |
| 11.10 | P1 | Authorised batch benchmark and 24-hour stability test | Not done | `docs/benchmark-report.md` | — | Readiness A7/A8 |
| 11.11 | P0 | Backup/restore verification, rollback plan, runbook, change log | Partially done | `docs/recovery-and-backup.md`, `docs/rollback.md`, `docs/runbook.md`, `CHANGELOG.md` | — | Restore verification on the host is readiness A10 |
| 11.12 | P0 | Close items only with code, test evidence and outcome; mark unavailable services | Done | this file | — | Unavailable institutional services are listed as N/A or open, never as features |

---

### Summary

| Status | Count |
|---|---|
| Done | 105 |
| Partially done | 20 |
| Not done | 6 |
| Not applicable | 2 |
| **Total** | **133** |

The open items fall into four groups:

1. **Host-only work.** Baselines, cgroup caps, restore, failure injection, the 24-hour run. See
   `deployment-readiness.md` section A.
2. **Data the agency must supply.** A labelled precision corpus and a curated brand list.
3. **Institutional decisions.** Checking the Section 63 template against the official text,
   holding custody checkpoints externally, connectors, passive DNS sources.
4. **Optional features deferred within the dependency rule.** WARC/WACZ, PDF/DOCX generation,
   download quarantine, favicon hashing, a graph visualisation.
