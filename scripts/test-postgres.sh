#!/usr/bin/env bash
# Start a throwaway local PostgreSQL cluster for integration tests and print
# the TEST_DATABASE_URL to use. Development/CI helper only; production uses
# the pinned postgres image in compose.yaml.
set -euo pipefail
PGBIN="${PGBIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"
DATA="${PGDATA_DIR:-${TMPDIR:-/tmp}/cwc-test-pg}"
PORT="${PGPORT_TEST:-55432}"
RUN_AS=()
if [ "$(id -u)" = "0" ]; then RUN_AS=(runuser -u postgres --); fi
if [ ! -s "$DATA/PG_VERSION" ]; then
  mkdir -p "$DATA"; [ "$(id -u)" = "0" ] && chown postgres "$DATA"
  "${RUN_AS[@]}" "$PGBIN/initdb" -D "$DATA" -U collector --auth=trust >/dev/null
fi
if ! "${RUN_AS[@]}" "$PGBIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
  "${RUN_AS[@]}" "$PGBIN/pg_ctl" -D "$DATA" -o "-p $PORT -k $DATA -c listen_addresses=127.0.0.1 -c fsync=off" -l "$DATA/log" -w start >/dev/null
fi
"$PGBIN/createdb" -h 127.0.0.1 -p "$PORT" -U collector collector_test 2>/dev/null || true
echo "postgres://collector@127.0.0.1:$PORT/collector_test"
