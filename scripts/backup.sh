#!/usr/bin/env bash
# Back up the PostgreSQL ledger and all attempt manifests; optionally mirror the
# original captures to an independent destination (blueprint §15).
#   BACKUP_DEST=/mnt/independent-disk scripts/backup.sh [--context rootless] [--with-originals]
# A backup on the same disk is NOT disaster recovery; this script says so and
# records the fact in the ledger.
set -euo pipefail
CTX=rootless
ORIGINALS=0
while [ $# -gt 0 ]; do
  case "$1" in --context) CTX="$2"; shift 2 ;; --with-originals) ORIGINALS=1; shift ;; *) echo "unknown $1" >&2; exit 64 ;; esac
done
: "${COLLECTOR_DATA_DIR:?set COLLECTOR_DATA_DIR}"
DC=(docker --context "$CTX" compose -p cyber-web-collector)
TS=$(date -u +%Y%m%dT%H%M%SZ)
DEST_BASE="${BACKUP_DEST:-$COLLECTOR_DATA_DIR/backups}"
OUT="$DEST_BASE/$TS"
mkdir -p "$OUT"
umask 077

echo "== ledger dump"
"${DC[@]}" exec -T postgres pg_dump -U postgres -d collector -Fc --no-owner > "$OUT/collector.dump"
"${DC[@]}" exec -T postgres pg_restore --list /dev/stdin < "$OUT/collector.dump" > /dev/null

echo "== manifests"
( cd "$COLLECTOR_DATA_DIR/artifacts" && find captures incomplete derived -name manifest.json -print0 2>/dev/null | tar --null -czf "$OUT/manifests.tar.gz" -T - )

if [ "$ORIGINALS" = 1 ]; then
  echo "== originals (rsync, no deletions at destination)"
  rsync -a --info=stats1 "$COLLECTOR_DATA_DIR/artifacts/captures" "$COLLECTOR_DATA_DIR/artifacts/incomplete" "$OUT/originals/"
fi

( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | xargs -0 sha256sum > SHA256SUMS )

independent=no
if [ -n "${BACKUP_DEST:-}" ] && [ "$(stat -c %d "$BACKUP_DEST")" != "$(stat -c %d "$COLLECTOR_DATA_DIR")" ]; then independent=yes; fi
"${DC[@]}" exec -T coordinator node dist/cli.js backup record --destination "$OUT" --independent "$independent" --note "originals=$ORIGINALS"
echo "backup written to $OUT (independent storage: $independent)"
[ "$independent" = yes ] || echo "WARNING: backup is on the same device as the data. Single-disk risk remains." >&2
