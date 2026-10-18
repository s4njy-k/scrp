# Security model (blueprint §5, §13)

## Isolation boundaries

| Boundary | Mechanism | Verification |
|---|---|---|
| Browser engine ↔ Internet | Engine only on `acquisition` (`internal: true`). The only exit is `egress-gateway` | `docker network inspect`; test `browserCapture.test.ts › routes browser loopback traffic through the gateway` |
| Destination policy | Gateway resolves every name itself. **All** answers must be public. It connects to the checked address (pinning). It denies loopback, RFC1918, CGNAT, link-local and metadata (169.254.169.254, fd00:ec2::254, 168.63.129.16, 100.100.100.200), reserved, multicast, documentation and benchmarking ranges, IPv4-mapped/NAT64/6to4/Teredo IPv6, internal-looking names, and non-allow-listed ports | `test/unit/gatewayPolicy.test.ts`, `test/integration/gateway.test.ts` |
| Redirects, subframes, resources, WebSocket | Every new connection passes through the gateway (CONNECT for HTTPS/WSS, absolute-form for HTTP/WS). The gateway never follows redirects itself | `browserCapture.test.ts › refuses page subresources and redirects aimed at internal/metadata addresses` |
| Gateway robustness | Client sockets get an error handler before any DNS or connect work, so a client reset can never crash the gateway for everyone else. Pending tunnels count towards `GATEWAY_MAX_TUNNELS`, and an upstream socket opened for a client that has since gone away is destroyed. A 30 s positive DNS cache re-classifies every cached answer on use, and connections stay pinned to the checked addresses | `gateway.test.ts › survives clients that reset while DNS or connect is still pending` |
| Proxy bypass | Chromium `--proxy-bypass-list=<-loopback>` (loopback is proxied as well). Firefox `network.proxy.allow_hijacking_localhost` | Same tests |
| UDP/QUIC/alternate transports | `--disable-quic`, `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`, DoH disabled, Firefox `network.http.http3.enable=false`, `media.peerconnection.ice.proxy_only`. The `internal` network gives no UDP route either | Network topology. Suppression may change site behaviour, which is recorded in the attempt settings |
| Database | PostgreSQL only on `control`. No published port. Passwords are Compose secret files (`PGPASSWORD_FILE`), never environment values | `compose.yaml` |
| Driver ↔ engine | The worker opens the Playwright connection. The engine endpoint path is a ≥ 24-character secret. The worker exposes no listener reachable from pages (health binds `127.0.0.1`). Driver and engine versions are pinned to `1.56.1` | `docker/browser-engine/start.sh` refuses to start without the secret |
| Host | Rootless Docker; no Docker socket mounted; `cap_drop: ALL`; `no-new-privileges`; `read_only` root filesystems with tmpfs `/tmp`; `pids_limit`; private IPC; sized `shm_size`. The only mounts are artifacts, read-only input and read-only policy | `compose.yaml` |
| Chromium sandbox | The engine runs as non-root `pwuser` with Playwright's seccomp profile (`docker/seccomp/chromium-seccomp.json`, which adds user-namespace syscalls). No `SYS_ADMIN`, no host IPC. `CHROMIUM_SANDBOX=false` is **refused** in `connect` mode | See [Sandbox verification](#sandbox-verification) |

### Sandbox verification

Rootless Docker alone does not prove that the Chromium sandbox is active. On the real VM, after `up`, run:

```bash
DC="docker --context rootless compose -p cyber-web-collector"
# 1. The engine runs as non-root:
$DC exec browser-engine id
# 2. Chromium sandbox processes exist while a capture is running (zygote/renderer with --type=zygote and no --no-sandbox):
$DC exec browser-engine sh -c 'ps -eo pid,args | grep -E "chrom(e|ium)" | grep -v grep | grep -c -- "--no-sandbox" || true'
#    -> expected output: 0
# 3. Optional: capture chrome://sandbox through the driver (prints "You are adequately sandboxed").
```

If Chromium cannot start with the sandbox (for example because unprivileged user namespaces
are disabled or restricted by AppArmor), treat it as a **deployment blocker** and record it in
`docs/deployment-readiness.md`. Do not disable the sandbox to work around it.

## Weaker profiles (documented, never claimed equivalent)

* **`BROWSER_MODE=local`**: the browser runs inside the driver container, which has database
  credentials and an artifact mount. It is used only for development and fixture tests. Each
  attempt records `browser_mode: local` and a limitation.
* **`scrapling-worker`**: Scrapling's browser runs in the same container as its driver. To
  reduce the damage from a browser compromise, it connects as the restricted
  `collector_scrapling` role (migration `0002`), which cannot read source records,
  identifiers, findings or case holds. It holds at most one global permit and shares the
  acquisition envelope.

## Data handling

* Cookies, authorization headers and storage state are **restricted** artifacts (file mode
  0600, `restricted=true`). Ordinary network event logs redact them. Exports never include
  them. Logs redact cookie, authorization, password and connection-string fields.
* Raw captured HTML is evidence and is never rendered by the analyst console. The console shows
  captured text and identifiers as text only (DOM built with `textContent`; the helper refuses raw
  HTML). Downloads of artifacts, reports and uploads are served as attachments with
  `Content-Security-Policy: default-src 'none'; sandbox`, after re-verifying their hash.
* Downloads are refused (`acceptDownloads: false`) and logged. Downloaded files are never executed.
* CSV exports neutralise spreadsheet formula injection (`=`, `+`, `-`, `@` prefixes).
* Generic recipes never create accounts, submit credentials, make payments, upload documents
  or solve CAPTCHAs. Dialogs are dismissed and logged.

## Analyst console and API

| Control | Implementation |
|---|---|
| Exposure | `serve api` binds to loopback by default. In Compose the `api` service (profile `console`) publishes `127.0.0.1:${API_HOST_PORT}` only, on a bridge without IP masquerade, and joins `control` but neither `acquisition` nor `triage`. Reach it through `ssh -L`. Never put it on a public interface |
| Authentication | scrypt password hashes; database sessions storing only a SHA-256 of the token; idle and absolute expiry; HttpOnly, `SameSite=Strict`, `Secure` cookie (browsers accept `Secure` on `http://localhost` through the tunnel). TOTP MFA (RFC 6238) is required, with replay protection. First sign-in forces a password change. Lockout after repeated failures. Session rotation on MFA and password change |
| Authorisation | Roles `admin`, `intake`, `analyst`, `approver`, `evidence`, `auditor`, `report` per route. Object-level checks on every case, target, attempt, artifact, notice, certificate and upload through case membership. Objects outside your cases return **404**. Admins see every case but NCRP/FIR references are masked unless they are members |
| Request integrity | `X-CSRF-Token` on every mutation, plus `Origin` / `Sec-Fetch-Site` checks. Strict JSON bodies with size limits (`.strict()` zod schemas). Per-user API and per-account+address login rate limits. Request IDs on every response and audit event |
| Browser hardening | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'` (see `src/web/http.ts`), plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, a restrictive `Permissions-Policy` and optional HSTS (`web.hsts`). The console has no third-party code; the browser smoke test fails on any CSP violation |
| Accountability | Reads of manifests, artifacts and reports, searches of protected identifiers, decisions, approvals, uploads and downloads are written to the hash-chained audit log with actor, case, object, outcome and request ID |
| Governance | Maker-checker on review and approval (the author cannot approve). Notices are never sent, documents never signed, nothing taken down by the system: `governance.external_notice_autosend_enabled`, `auto_takedown_enabled` and `certificate_autosign` are literal `false`, and `maker_checker_for_external_actions`, `analyst_review_required` and `false_positive_override_requires_new_evidence` literal `true`, in the policy schema |
| Metrics | `/api/v1/metrics` needs a bearer token (`METRICS_BEARER_TOKEN`, ≥ 24 characters) or an admin/auditor session. It exposes counts and latencies, never identifiers |

## Custody chain

Audit events are sealed into a SHA-256 hash chain every few seconds (`custody seal` runs in the
coordinator). A database trigger refuses updates and deletes except the one-time seal. `custody
checkpoint` writes a signed (Ed25519) checkpoint of the chain head. **Store checkpoint files
outside the collector's administrative control** (for example, email them to the case officer or
keep them on separate institutional storage). `custody verify --checkpoint <file>` then detects a
rewrite of the history before that point. This is tamper-evident storage. It is not WORM storage and
must not be described as legally immutable.

## Telemetry and outbound behaviour

Chromium starts with background networking, component updates, pings and domain reliability
reporting disabled. Firefox telemetry, Normandy and Safe Browsing prefs are disabled. Even so,
only the gateway can reach the Internet, so any leftover browser traffic shows up in the
gateway decision log (`egress decision` lines) and can be checked during the pilot. No
provider or model API is configured. The baseline runs with every commercial credential absent.

## AI

AI is optional, downstream, and not implemented in this release (`extraction.ai_enabled` must be
`false`). If it is added, page text is data, never instructions. Outputs must be validated
against a schema. Page content can never change egress, install code or trigger actions.

## Supply chain

* npm dependencies are pinned exactly in `package-lock.json` and were resolved with
  `--before=2026-10-01` to leave a review buffer. `npm audit` was clean at commit time.
* Container bases are pinned by digest. Python adapter dependencies are hash-locked
  (`--require-hashes`).
* CI runs `npm audit --omit=dev --audit-level=high`, builds a CycloneDX SBOM (kept as a build
  artifact), checks that no private key, `.env`, secret file or live policy is committed, and
  builds the application image as a non-root user. Container-image CVE scanning is left to the
  agency's approved scanner.
* Updates are tested against the fixtures (`npm test`) before promotion. See [`rollback.md`](rollback.md).
