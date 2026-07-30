"""
config_assessment/core/db/reseed.py
-----------------------------------
Keep a persistent (volume-mounted) working DB in sync with the image's canonical
DB, WITHOUT wiping plugins the user installed themselves.

The container seeds the working DB from a baked canonical DB on first run, but
never overwrites an existing DB (that would delete user-installed plugins). The
side effect: updates to the built-in knowledge base (e.g. corrected attack-chain
justifications) never reached an existing volume.

This module closes that gap with a versioned, targeted refresh:

  * a `aegis_meta` table records the base-DB version present in the working DB;
  * when the image ships a newer base version, we refresh ONLY the built-in
    targets (their misconfigurations + attack_chains) from the seed DB, and bump
    the recorded version — user-installed targets are left untouched.

Deterministic and idempotent: running it when already up to date is a no-op.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# Bump this whenever data/ccss_canonical.sql changes in a way that should reach
# existing volumes (e.g. corrected justifications, new built-in misconfigs).
BASE_DB_VERSION = 2

# The targets shipped in the image. Anything else in a working DB was installed
# by the user (plugin add / fetch) and must be preserved across a refresh.
BUILTIN_TARGETS = (
    "apache-httpd", "docker", "mysql", "nginx", "redis", "ssh", "tomcat",
)


def _ensure_meta(conn: sqlite3.Connection) -> int:
    """Ensure aegis_meta exists; return the stored base version (0 if unset)."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS aegis_meta "
        "(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    row = conn.execute(
        "SELECT value FROM aegis_meta WHERE key='base_db_version'").fetchone()
    return int(row[0]) if row else 0


def _set_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        "INSERT INTO aegis_meta(key, value) VALUES('base_db_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(version),))


def refresh_builtins_if_stale(db_path: str | Path, seed_path: str | Path) -> bool:
    """Refresh built-in targets from the seed DB if the working DB's base version
    is older than the image's. Preserves user-installed targets.

    Returns True if a refresh happened, False if already current or seed missing.
    """
    db_path, seed_path = Path(db_path), Path(seed_path)
    if not db_path.exists() or not seed_path.exists():
        return False

    conn = sqlite3.connect(str(db_path))
    try:
        current = _ensure_meta(conn)
        if current >= BASE_DB_VERSION:
            return False  # already up to date

        # Pull the built-in rows from the seed DB and replace them in the volume
        # DB, leaving user targets (not in BUILTIN_TARGETS) alone.
        conn.execute("ATTACH DATABASE ? AS seed", (str(seed_path),))
        placeholders = ",".join("?" for _ in BUILTIN_TARGETS)
        try:
            conn.execute("BEGIN")
            for table in ("misconfigurations", "attack_chains"):
                conn.execute(
                    f"DELETE FROM {table} WHERE target_name IN ({placeholders})",
                    BUILTIN_TARGETS)
                # Column lists match (same schema in seed and working DB).
                cols = [r[1] for r in conn.execute(
                    f"PRAGMA table_info({table})").fetchall()]
                collist = ",".join(cols)
                conn.execute(
                    f"INSERT INTO {table} ({collist}) "
                    f"SELECT {collist} FROM seed.{table} "
                    f"WHERE target_name IN ({placeholders})", BUILTIN_TARGETS)
            _set_version(conn, BASE_DB_VERSION)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.execute("DETACH DATABASE seed")
        return True
    finally:
        conn.commit()
        conn.close()
