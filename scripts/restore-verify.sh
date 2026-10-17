#!/usr/bin/env bash
# Verify a backup can be restored, without touching the live database:
#  1. restore the dump into a scratch database inside the postgres container;
#  2. compare row counts of key tables with the live ledger;
#  3. re-hash a sample of committed attempt directories against their manifests.
#   scripts/restore-verify.sh <backup-dir> [--context rootless] [--sample 25]
set -euo pipefail
BK="${1:?backup directory}"; shift
CTX=rootless; SAMPLE=25
while [ $# -gt 0 ]; do
  case "$1" in --context) CTX="$2"; shift 2 ;; --sample) SAMPLE="$2"; shift 2 ;; *) echo "unknown $1" >&2; exit 64 ;; esac
done
DC=(docker --context "$CTX" compose -p cyber-web-collector)
( cd "$BK" && sha256sum --quiet -c SHA256SUMS ) && echo "backup checksums OK"
"${DC[@]}" exec -T postgres psql -U postgres -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS collector_restore_check' -c 'CREATE DATABASE collector_restore_check'
"${DC[@]}" exec -T postgres pg_restore -U postgres -d collector_restore_check --no-owner < "$BK/collector.dump"
for t in jobs attempts artifacts identifiers audit_events; do
  live=$("${DC[@]}" exec -T postgres psql -U postgres -d collector -Atc "SELECT count(*) FROM $t")
  rest=$("${DC[@]}" exec -T postgres psql -U postgres -d collector_restore_check -Atc "SELECT count(*) FROM $t")
  echo "$t live=$live restored=$rest"
done
ids=$("${DC[@]}" exec -T postgres psql -U postgres -d collector_restore_check -Atc \
  "SELECT id FROM attempts WHERE status IN ('committed','recovered') AND deleted_at IS NULL ORDER BY random() LIMIT $SAMPLE")
fail=0
for id in $ids; do
  if "${DC[@]}" exec -T coordinator node dist/cli.js verify "$id" | grep -q '"all_ok": true'; then echo "ok $id"; else echo "MISMATCH $id"; fail=1; fi
done
"${DC[@]}" exec -T postgres psql -U postgres -c 'DROP DATABASE collector_restore_check'
[ $fail -eq 0 ] && echo "restore verification passed" || { echo "restore verification found mismatches" >&2; exit 1; }
