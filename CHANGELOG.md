# Changelog

All notable changes. Dates are UTC. The project has not yet been deployed to the target VM; see
[`docs/deployment-readiness.md`](docs/deployment-readiness.md).

## [Unreleased] — v4 blueprint and v0.3 checklist

Item-by-item status, with code and test references: [`docs/checklist-v0.3-status.md`](docs/checklist-v0.3-status.md).

### Added

- **Evidence integrity.** Manifest v2 (exact original inputs, UTC and IST, clock fact, capture
  context, declared vantage, redirect chain, software versions). Every file is re-verified after the
  atomic commit and gets an `artifacts.verification_state`. *Verify Evidence* covers an attempt,
  job or case and writes a hashed report. Evidence packages hash their index, and the index hash
  lives in the ledger. A ustar archive writer and offline package verification are included.
- **Custody chain.** The audit log is hash-chained and append-only (a trigger allows only the
  one-time seal). It is sealed every 2 s and supports Ed25519-signed checkpoints for storage
  outside the collector (`custody seal|verify|checkpoint|keygen`).
- **Analyst API and console.** A loopback-only `serve api` with TOTP MFA, database sessions,
  CSRF, rate limits, a strict CSP, seven roles and case-level object authorisation. It serves a
  dependency-free single-page console for intake, jobs with live progress, review, investigation,
  evidence, cases and holds, notices, Section 63 worksheets, monitoring, analytics and
  administration. Compose profile `console` publishes it on host loopback only, inside the
  existing resource envelope.
- **Cases.** Membership roles, NCRP/FIR references masked outside the case, legal holds, case
  verification and evidence packages, plus proof uploads with type sniffing.
- **Intake.** XLSX through a defensive reader (no formula evaluation; zip-bomb, traversal and
  size checks) and plain-text lists. Idempotency keys, dry-run previews and per-line results.
- **Extraction.** Typed identifiers with provenance, extractor version, confidence and review
  states. QR-versus-displayed payee conflicts are flagged. New fields: EIP-55 checks,
  libphonenumber normalisation and IDN email. Operator signals (AdSense, chat widgets, template
  hash), app store and APK links, sensitive form fields and brand claims are recorded as signals.
  Payment-gateway merchant references (Razorpay, Paytm, Cashfree, Instamojo) are recorded as
  candidates. Thumbnails are stored as derivatives.
- **Investigation.** Explainable triage scores with benign context (infrastructure signals score
  zero). Append-only analyst decisions with reason codes and concurrency control. False-positive
  suppression can be overridden only by an approver citing newer evidence. Also: identifier
  reviews, annotations, bulk triage with preview, scoped correlation (only on corroborating
  uncommon identifiers), brand lookalike detection with official/affiliate exemptions, and
  side-by-side capture comparison.
- **Legally routed actions.** Ten routes, each with eligibility checks (s.69A grounds, s.79(3)(b)
  conditions, BNSS s.94 versus voluntary preservation, cross-border channel). Maker-checker
  review and approval, an approval snapshot hash re-checked at generation, and report packs in
  Markdown, script-free HTML, JSON and formula-safe CSV. Issuance and receipt need proof
  uploads; verified closure needs a fresh capture. Nothing is ever sent.
- **Section 63 (BSA 2023).** Fact sheet and hash report, plus a Part A/B worksheet that pre-fills
  only computed hashes. Template verification against the official text is required before
  completion. States: draft → completed → signed (upload) → attached to submission.
- **Monitoring.** Proportionate revisits run as new low-priority jobs. Outcomes are classified
  (still live, changed payee, parked, blocked at vantage, DNS, redirect, reported or
  provider-confirmed removal). Reappearance alerts are raised as leads.
- **Enrichment.** DNS, live TLS and RDAP run through the gateway with caches and
  source-specific errors; CT is opt-in. Role-specific addressee suggestions.
- **Placeholder detection.** Parked domains, hosting suspensions and ISP block notices each get
  their own classification.
- **Retention.** Classes `transient_triage`, `case_evidence`, `notice_issued` and
  `litigation_hold`. Evidence cited by notices or certificates, or in open cases, is never
  expired.
- **Operations.** `/api/v1/metrics` (Prometheus) and `/api/v1/analytics`, which states the
  definition, denominator and scope of each figure. OpenAPI 3.1 is generated from the live
  routes (`npm run openapi`). CLI: `verify --job|--case`, `package`, `clock`, `user`.
- **CI.** npm audit (production, high+), CycloneDX SBOM, committed-secret check, application
  image build with a non-root/console smoke test, OpenAPI currency test, and a browser smoke
  test of every console screen under the CSP.

### Changed

- `browser-engine` caps reduced from 1.2 vCPU / 5.5 GiB to 1.1 vCPU / 5 GiB to fund the console
  (0.1 vCPU / 512 MiB) within the ~2 vCPU / 9.75 GiB envelope.
- API intake defaults to retention class `case_evidence`. The CLI default remains
  `transient_triage`.
- `config/brands.yaml` ships only verified official domains. Unverified entries were removed.

### Security

- Case isolation for targets shared by several cases (review findings on PR #3): evidence packages
  accept only jobs or attempts linked to the case they are filed under; notes and monitoring rules
  are shown only to members of their case; revisits are built from, and linked only to, the
  monitoring rule's case; a notice closes as verified only after a fresh capture of every
  non-withdrawn target within its case; monitoring rules are unique per target and case, with the
  daily revisit cap still applied per target across all cases.
- Raw captured HTML is never rendered. Downloads are attachments with a sandbox CSP and are
  re-hashed before they are served.
- Governance safeguards (no autosend, no auto-takedown, no autosign, maker-checker) are schema
  literals and cannot be switched on by configuration.

### Migrations

`0003_evidence_integrity`, `0004_access_and_cases`, `0005_investigation`, `0006_actions`,
`0007_monitoring_enrichment`, `0008_action_details`, `0009_monitoring_rule_per_case`. All are additive (0009 only narrows a unique index from per-target to per-target-and-case). Take a verified backup
first (`docs/recovery-and-backup.md`). Rollback: [`docs/rollback.md`](docs/rollback.md).

## 2026-10-18 — PR review fixes

- The attempt runner waits for an abandoned capture's cleanup before finalising. A popup
  response no longer replaces the captured page's status.

## 2026-10-17 — Initial collector

- Crawlee + Playwright collection, PostgreSQL ledger with leases, fencing and permits, egress
  gateway, immutable artifact store, deterministic extraction, optional Scrapling adapter, rootless
  Compose deployment and operator documentation.
