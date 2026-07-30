#!/bin/sh
# aegis-seed — prepare the persistent data dir, then exec the given command.
#
# AEGIS_DATA_DIR is expected to be a mounted volume so the working DB and any
# fetched plugins persist across --rm containers. On first use the volume is
# empty, so we seed the DB from the image's canonical dump and make sure the
# plugins dir exists. All steps are idempotent — safe on every run.
set -e

DATA_DIR="${AEGIS_DATA_DIR:-/home/aegis/data}"
DB="${AEGIS_DB:-$DATA_DIR/ccss.db}"
PLUGINS_DIR="${AEGIS_PLUGINS_DIR:-$DATA_DIR/plugins}"
SEED_DB="/home/aegis/app/ccss.seed.db"

mkdir -p "$DATA_DIR" "$PLUGINS_DIR" 2>/dev/null || true

# Guard against a stale volume owned by another uid (e.g. created by an older
# image as root): if the data dir is not writable by us, we can't chown it
# (we run unprivileged), so fall back to a writable in-container location. The
# DB/plugins then don't persist, but the scan works instead of crashing with
# "attempt to write a readonly database". A one-line note tells the user how to
# restore persistence.
if [ ! -w "$DATA_DIR" ] || ! ( : > "$DATA_DIR/.aegis-write-test" 2>/dev/null ); then
    echo "sca: data volume '$DATA_DIR' is not writable (likely owned by another user)." >&2
    echo "sca: falling back to non-persistent /tmp; to fix, run: docker volume rm aegis_data" >&2
    DATA_DIR=/tmp/aegis-data
    DB="$DATA_DIR/ccss.db"
    PLUGINS_DIR="$DATA_DIR/plugins"
    mkdir -p "$PLUGINS_DIR"
    export AEGIS_DATA_DIR="$DATA_DIR" AEGIS_DB="$DB" AEGIS_PLUGINS_DIR="$PLUGINS_DIR"
else
    rm -f "$DATA_DIR/.aegis-write-test" 2>/dev/null || true
fi

# Seed the working DB from the baked canonical DB the first time only. Never
# overwrite an existing DB — that would wipe plugins the user already installed.
if [ ! -f "$DB" ] && [ -f "$SEED_DB" ]; then
    cp "$SEED_DB" "$DB"
fi

# Refresh the built-in knowledge base in an EXISTING volume when the image ships
# a newer base-DB version (e.g. corrected chain justifications), preserving any
# user-installed plugins. No-op on a fresh seed or when already current.
AEGIS_DB="$DB" python3 - "$DB" "$SEED_DB" <<'PY' 2>/dev/null || true
import sys
from config_assessment.core.db.reseed import refresh_builtins_if_stale
refresh_builtins_if_stale(sys.argv[1], sys.argv[2])
PY

exec "$@"
