# Benchmark report

> **Not yet run.** The system has not been benchmarked on the target VM. This file is the template
> that the pilot and the 24-hour run must fill in (see [`pilot-evaluation.md`](pilot-evaluation.md)).
> Until it is filled in, do not quote capacity or success figures. Vendor demos, desktop speed and GPU
> specifications are not substitutes.

## Environment

| Item | Value |
|---|---|
| Date / operator | |
| Release (`APP_VERSION`, git commit) | |
| Compatibility record | link to the `preflight.sh` output |
| Granted allocation (vCPU / GiB / disk) | |
| cgroup caps enforced? | yes / no (evidence) |
| Chromium sandbox active? | yes / no (evidence) |
| Pilot list SHA-256 and size | |
| Egress vantage label | |

## Planning arithmetic (blueprint §17, to be validated)

Two browser slots × 86,400 s × 50% utilisation ÷ 30–60 s per visit gives roughly **1,440–2,880
browser visit attempts per day**, or about 960 at 90 s. These are attempts, not successful
bundles. Expected useful visits are attempts × measured yield `y`. At 3,000 bundles a day of
5 MB each, the 80 GB soft limit lasts about 5.3 days before overhead and holds.

## Results

| Stratum | Jobs | COMPLETE | PARTIAL | Challenge | Auth | Blocked | Unavailable | Infra-deferred | p50 s | p95 s | MB/attempt |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Ordinary static | | | | | | | | | | | |
| JS-heavy / SPA | | | | | | | | | | | |
| Challenge-protected | | | | | | | | | | | |
| Dead / unavailable | | | | | | | | | | | |
| Image / QR / payment | | | | | | | | | | | |
| Login-walled | | | | | | | | | | | |

### Resource health

| Metric | p50 | p95 | Max | Cap |
|---|---|---|---|---|
| CPU (collector aggregate) | | | | ~2 vCPU |
| RSS browser-engine | | | | 5.5 GiB |
| I/O wait / steal (`vmstat`) | | | | — |
| Artifact growth GB/day | | | | 80 GB soft |

### Identifier audit

| Field | Sample | True | False | Uncertain correctly flagged |
|---|---|---|---|---|

### Alternate adapter

| Adapter | Attempts | Recoveries | Benefit rate | Avg s | MB |
|---|---|---|---|---|---|

## Conclusions and scale decision

(Change slots only after measuring. If CPU is busy with other workloads, reduce slots. If queues
grow because of storage or network limits, adding workers makes things worse.)
