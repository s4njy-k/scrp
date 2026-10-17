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
* Raw captured HTML is evidence and must not be rendered in an analyst UI with that UI's
  privileges. View it as text, or in a sandboxed iframe without script permission on a separate
  origin. No analyst UI ships in this release.
* Downloads are refused (`acceptDownloads: false`) and logged. Downloaded files are never executed.
* CSV exports neutralise spreadsheet formula injection (`=`, `+`, `-`, `@` prefixes).
* Generic recipes never create accounts, submit credentials, make payments, upload documents
  or solve CAPTCHAs. Dialogs are dismissed and logged.

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
* Updates are tested against the fixtures (`npm test`) before promotion. See [`rollback.md`](rollback.md).
