#!/bin/sh
# The endpoint path is a shared secret between driver and engine (defence in depth
# on top of network isolation). Refuse to start without it.
set -eu
if [ -z "${BROWSER_SERVER_PATH:-}" ] || [ "${#BROWSER_SERVER_PATH}" -lt 24 ]; then
  echo "BROWSER_SERVER_PATH must be set to a random token of at least 24 characters" >&2
  exit 64
fi
exec node /srv/engine/node_modules/playwright-core/cli.js run-server \
  --port 3000 --host 0.0.0.0 --path "/${BROWSER_SERVER_PATH}" --max-clients "${BROWSER_MAX_CLIENTS:-4}"
