"""
tests/test_reseed.py
--------------------
Versioned built-in refresh: when the image ships a newer base DB, an existing
volume's built-in targets are updated while user-installed plugins are kept.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from config_assessment.core.db.reseed import (
    refresh_builtins_if_stale, BASE_DB_VERSION, BUILTIN_TARGETS)

CANONICAL = Path("data/ccss_canonical.sql")


def _seed_db(path):
    sqlite3.connect(str(path)).executescript(CANONICAL.read_text())


def _add_user_plugin(conn, name="mongodb"):
    tid = conn.execute(
        "INSERT INTO targets(name,display_name,version,benchmark_source) "
        "VALUES(?,?,?,?)", (name, name.title(), "1.0", "STIG")).lastrowid
    conn.execute(
        "INSERT INTO attack_chains(target_id,target_name,chain_id,"
        "misconfig_directives,amplification,justification) "
        "VALUES(?,?,?,?,?,?)", (tid, name, f"{name}-chain", "[]", 1.5, "user"))
    conn.commit()


@pytest.fixture
def seed(tmp_path):
    p = tmp_path / "seed.db"
    _seed_db(p)
    return p


def test_fresh_seed_is_already_current(seed, tmp_path):
    # A DB just copied from seed carries the current version → no refresh.
    work = tmp_path / "work.db"
    work.write_bytes(seed.read_bytes())
    assert refresh_builtins_if_stale(work, seed) is False


def test_stale_volume_gets_builtins_refreshed(seed, tmp_path):
    work = tmp_path / "work.db"
    work.write_bytes(seed.read_bytes())
    conn = sqlite3.connect(str(work))
    # Simulate an OLD volume: stale justification + no version stamp.
    conn.execute("UPDATE attack_chains SET justification='OLD privilege escalation' "
                 "WHERE chain_id='load-module-status-userdir'")
    conn.execute("DELETE FROM caspar_meta")           # pretend pre-versioning
    conn.commit(); conn.close()

    assert refresh_builtins_if_stale(work, seed) is True

    conn = sqlite3.connect(str(work))
    j = conn.execute("SELECT justification FROM attack_chains "
                     "WHERE chain_id='load-module-status-userdir'").fetchone()[0]
    assert "OLD privilege escalation" not in j        # refreshed from seed
    ver = conn.execute("SELECT value FROM caspar_meta "
                       "WHERE key='base_db_version'").fetchone()[0]
    assert int(ver) == BASE_DB_VERSION
    conn.close()


def test_refresh_preserves_user_plugins(seed, tmp_path):
    work = tmp_path / "work.db"
    work.write_bytes(seed.read_bytes())
    conn = sqlite3.connect(str(work))
    conn.execute("DELETE FROM caspar_meta")           # force stale
    _add_user_plugin(conn, "mongodb")
    conn.close()

    refresh_builtins_if_stale(work, seed)

    conn = sqlite3.connect(str(work))
    assert conn.execute("SELECT COUNT(*) FROM targets WHERE name='mongodb'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM attack_chains "
                        "WHERE target_name='mongodb'").fetchone()[0] == 1
    # Built-ins are all still present too.
    n = conn.execute("SELECT COUNT(DISTINCT target_name) FROM misconfigurations "
                     "WHERE target_name IN (%s)" %
                     ",".join("?" * len(BUILTIN_TARGETS)), BUILTIN_TARGETS).fetchone()[0]
    assert n == len(BUILTIN_TARGETS)
    conn.close()


def test_idempotent(seed, tmp_path):
    work = tmp_path / "work.db"
    work.write_bytes(seed.read_bytes())
    conn = sqlite3.connect(str(work)); conn.execute("DELETE FROM caspar_meta"); conn.commit(); conn.close()
    assert refresh_builtins_if_stale(work, seed) is True    # first: refreshes
    assert refresh_builtins_if_stale(work, seed) is False   # second: no-op


def test_missing_files_are_safe(tmp_path):
    assert refresh_builtins_if_stale(tmp_path / "nope.db", tmp_path / "no-seed.db") is False
