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


class TestCanonicalShipsNoScans:
    """A fresh install starts with an empty history.

    The canonical dump used to carry 54 development scans, so the console's
    Dashboard showed scores, findings and attack chains to someone who had
    never run an assessment — and any number a user took from that screen
    silently mixed their own results with ours. The knowledge base (rules,
    chains, targets) is the product and must stay; the scan history is not.
    """

    def test_no_scan_results_in_the_canonical_dump(self, seed):
        conn = sqlite3.connect(str(seed))
        assert conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0] == 0

    def test_the_knowledge_base_is_still_there(self, seed):
        """The counterpart assertion: stripping scans must not strip content."""
        conn = sqlite3.connect(str(seed))
        misconfigs = conn.execute("SELECT COUNT(*) FROM misconfigurations").fetchone()[0]
        chains = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
        targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
        assert misconfigs > 400
        assert chains > 20
        assert targets >= 11

    def test_the_first_user_scan_gets_id_one(self, seed):
        """sqlite_sequence must not remember the stripped rows.

        Leaving scan_results' sequence behind would start a user's first scan
        at id 55 — harmless in effect, but it is a leftover of data that is no
        longer there, and it shows in URLs.
        """
        conn = sqlite3.connect(str(seed))
        row = conn.execute(
            "SELECT seq FROM sqlite_sequence WHERE name='scan_results'").fetchone()
        assert row is None
