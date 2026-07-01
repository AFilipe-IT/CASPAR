#!/bin/sh
# caspar-seed — prepare the persistent data dir, then exec the given command.
#
# CASPAR_DATA_DIR is expected to be a mounted volume so the working DB and any
# fetched plugins persist across --rm containers. On first use the volume is
# empty, so we seed the DB from the image's canonical dump and make sure the
# plugins dir exists. All steps are idempotent — safe on every run.
set -e

DATA_DIR="${CASPAR_DATA_DIR:-/home/caspar/data}"
DB="${CASPAR_DB:-$DATA_DIR/ccss.db}"
PLUGINS_DIR="${CASPAR_PLUGINS_DIR:-$DATA_DIR/plugins}"
SEED_DB="/home/caspar/app/ccss.seed.db"

mkdir -p "$DATA_DIR" "$PLUGINS_DIR"

# Seed the working DB from the baked canonical DB the first time only. Never
# overwrite an existing DB — that would wipe plugins the user already installed.
if [ ! -f "$DB" ] && [ -f "$SEED_DB" ]; then
    cp "$SEED_DB" "$DB"
fi

exec "$@"
