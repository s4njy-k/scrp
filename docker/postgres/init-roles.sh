#!/bin/bash
# Runs once on first initialisation of the PostgreSQL data directory.
# Creates the application owner role and (optionally) the restricted Scrapling
# role from Compose secret files. The superuser password is separate.
set -euo pipefail
app_pw="$(cat /run/secrets/collector_db_password)"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=app_pw="$app_pw" <<'SQL'
CREATE ROLE collector LOGIN PASSWORD :'app_pw';
CREATE DATABASE collector OWNER collector;
REVOKE ALL ON DATABASE collector FROM PUBLIC;
SQL
if [ -s /run/secrets/scrapling_db_password ]; then
  scr_pw="$(cat /run/secrets/scrapling_db_password)"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname collector --set=scr_pw="$scr_pw" <<'SQL'
CREATE ROLE collector_scrapling LOGIN PASSWORD :'scr_pw';
GRANT CONNECT ON DATABASE collector TO collector_scrapling;
SQL
fi
