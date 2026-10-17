#!/usr/bin/env bash
# Create the persistent data layout and give container user 10001 ownership of
# the writable parts. Under rootless Docker, container UIDs map to subordinate
# UIDs on the host, so ownership is set from inside a container.
#   scripts/prepare-host-dirs.sh [--context rootless]
set -euo pipefail
CTX=rootless
[ "${1:-}" = "--context" ] && CTX="$2"
: "${COLLECTOR_DATA_DIR:?set COLLECTOR_DATA_DIR (see .env)}"
mkdir -p "$COLLECTOR_DATA_DIR"/{postgres,artifacts,input,backups}
chmod 750 "$COLLECTOR_DATA_DIR"
docker --context "$CTX" run --rm --user 0 --entrypoint chown \
  -v "$COLLECTOR_DATA_DIR/artifacts:/data/artifacts" \
  "cyber-web-collector/app:${APP_VERSION:-0.1.0}" -R 10001:10001 /data/artifacts
echo "prepared $COLLECTOR_DATA_DIR (artifacts owned by container uid 10001; postgres initialises its own directory)"
