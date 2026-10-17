#!/usr/bin/env bash
# Create Compose secret files with random passwords (mode 0600). Idempotent:
# existing files are never overwritten.
set -euo pipefail
DIR="${COLLECTOR_SECRETS_DIR:-$(dirname "$0")/../secrets}"
mkdir -p "$DIR"
chmod 700 "$DIR"
for name in postgres_superuser_password collector_db_password scrapling_db_password; do
  f="$DIR/$name"
  if [ -s "$f" ]; then echo "exists: $f"; continue; fi
  umask 077
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$f"
  echo "created: $f"
done
