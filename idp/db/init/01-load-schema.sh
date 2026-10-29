#!/bin/bash
# Loads the schema (db/schema/, mounted at /schema-source: one file per area, listed in load order by load.sql) into the
# freshly created database on first container start. Every later schema change is a numbered file in db/migrations/ and is
# also written into the matching file of db/schema/, so a fresh database and a migrated one end up the same.
set -euo pipefail

echo "[01-load-schema] Loading /schema-source/load.sql into database '${POSTGRES_DB}'..."
cd /schema-source
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" -f load.sql
echo "[01-load-schema] Schema load complete."
