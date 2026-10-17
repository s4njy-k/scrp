# Pilot and evaluation plan (blueprint §17, §18 Phase B)

Do not test against unrelated random sites to claim a universal success rate. The evaluation has
three parts:

1. **Fixtures.** Run `npm test` and the canaries (runbook §6).
2. **Pilot.** A representative list of 100–200 URLs drawn from real complaint and case
   intake, with authorisation for each target. Keep the list under version control outside
   this public tree (`pilot/pilot-YYYYMMDD.csv`). Record its SHA-256 here so results can be
   repeated.
3. **24-hour run.** Run on the VM within the real resource allocation.

## Pilot list composition

Stratify the list and report every metric per stratum. Do not mix the strata into one success rate.

| Stratum | Target share | Examples |
|---|---|---|
| Ordinary static | 20% | Brochure or phishing pages served as plain HTML |
| JS-heavy / SPA (including fragment routes) | 25% | React/Vue scam portals, deep links with `#/` routes |
| Challenge-protected | 15% | Sites showing Cloudflare/DataDome/hCaptcha interstitials |
| Dead / unavailable | 15% | NXDOMAIN, expired TLS, 404/410, parked |
| Image-heavy / QR / payment | 15% | UPI QR pages, bank-detail images |
| Login-walled | 10% | Fake bank or KYC login pages |

## Metrics (from `cli status` and the ledger)

| Metric | Definition | Notes |
|---|---|---|
| Required-artifact completion rate | `COMPLETE` / finished `browser_evidence` jobs | Report blocked, unavailable and infrastructure cases separately |
| Target-content coverage | `CONTENT_CAPTURED` vs challenge / login / empty / incomplete | Disclose the denominator and stratum mix |
| Screenshot yield | Valid early, settled, full or tiled screenshots and element crops per attempt; failure categories | — |
| Identifier quality | Per-field observed / not observed / failed; **audited** false matches (sample ≥ 50 identifiers per field type, especially OCR) | Record auditor and date |
| Time and cost | p50/p95 active seconds per attempt; bytes per attempt; CPU, RSS and I/O wait from `vmstat`/`docker stats` | — |
| Adapter benefit | Content recoveries by the alternate engine ÷ its attempts, with its CPU, time and bytes | Enable Scrapling only if this is clearly positive **and** evidence fidelity holds (screenshots, HAR, bodies, sandbox) |
| Integrity | Lease losses, reclaims, hash mismatches, recovered orphans, duplicate commits prevented | Must be explainable; zero silent loss |

## Scrapling decision (§4, §14)

Enable `browser.alternate_engine: scrapling` (and `--profile scrapling`) only after:

1. the same pilot subset runs once with Firefox as the alternate and once with Scrapling;
2. Scrapling's screenshots, HAR (`record_har_path` through `additional_args`), event log and DOM
   are checked against the contract on the pinned versions;
3. its incremental recoveries justify its cost inside the **same** 2 vCPU / 10 GiB envelope,
   by lowering other caps rather than adding capacity.

## 24-hour run acceptance

* No job silently disappears: every imported line is either a rejected `source_record` or a job
  in a final or explicitly deferred state.
* The resource caps hold: `docker stats` stays under the caps, there is no host swap (there is
  none), and other projects are unaffected.
* Admission pause and resume are exercised at least once (temporary disk fill).
* Results go into [`benchmark-report.md`](benchmark-report.md).
