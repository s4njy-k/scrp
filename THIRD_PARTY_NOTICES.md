# Third-party notices

Pinned versions are recorded in `package-lock.json`, `docker/browser-engine/package-lock.json`
and `scrapling-worker/requirements.lock`. Container base images are pinned by digest in
`docker/*.Dockerfile`, `scrapling-worker/Dockerfile` and `compose.yaml`.

## Direct runtime dependencies (Node.js)

| Package | Version | Licence | Role |
|---|---|---|---|
| @crawlee/core | 3.18.2 | Apache-2.0 | AutoscaledPool resource-aware concurrency |
| playwright-core | 1.56.1 | Apache-2.0 | Browser automation (driver and engine, versions matched) |
| pg | 8.23.1 | MIT | PostgreSQL client |
| undici | 8.11.2 | MIT | HTTP triage client and gateway lookups |
| zod | 4.6.5 | MIT | Policy schema validation |
| yaml | 2.9.1 | ISC | Policy parsing |
| tldts | 7.4.16 | MIT | Public Suffix List aware domain grouping |
| ipaddr.js | 2.5.0 | MIT | Gateway address classification |
| pino | 10.3.1 | MIT | Structured logs |
| csv-parse | 7.0.3 | MIT | Importer |
| jsqr | 1.4.0 | Apache-2.0 | QR decoding |
| pngjs | 7.0.0 | MIT | PNG validation/decoding |
| commander | 15.0.0 | MIT | CLI |

Transitive production dependency licences (license-checker, 2026-10-17): MIT 118, Apache-2.0 16,
BSD-2-Clause 10, ISC 9, BSD-3-Clause 4, MIT OR CC0-1.0 2, BlueOak-1.0.0 1, 0BSD 1, MIT/Apache-2.0 1,
CC-BY-4.0 1 (`caniuse-lite`, browser usage data pulled in by Crawlee's header tooling),
UNKNOWN 1 (`map-stream@0.1.0`: no licence field in package.json; the upstream repository states MIT).
Re-run `npx license-checker-rseidelsohn --production --summary` after every dependency change.

## Optional Scrapling adapter (Python)

| Package | Version | Licence |
|---|---|---|
| scrapling | 0.4.15 | BSD-3-Clause |
| playwright (Python) | 1.63.0 | Apache-2.0 |
| patchright | 1.63.0 | Apache-2.0 |
| psycopg / psycopg-binary | 3.3.6 | LGPL-3.0-only |
| PyYAML | 6.0.3 | MIT |
| curl_cffi | 0.16.3 | MIT |

Other locked packages: see `scrapling-worker/requirements.lock`; review their licences before enabling the profile.

## System packages in the application image

`tini` (MIT), `tesseract-ocr` and `tesseract-ocr-eng` (Apache-2.0), from Debian bookworm.

## Container images

| Image | Pin |
|---|---|
| node:22.22.0-bookworm-slim | sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94 |
| mcr.microsoft.com/playwright:v1.56.1-noble | sha256:f1e7e01021efd65dd1a2c56064be399f3e4de00fd021ac561325f2bfbb2b837a |
| postgres:16.14-bookworm | sha256:64154d0babcb1741988719e703419af0382b19953706149f9872fbd0f438efa8 |
| python:3.12.12-slim-bookworm | sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c |
