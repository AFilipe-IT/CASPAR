"""
tests/test_doctor.py
--------------------
DB integrity checks: orphan rules, chains pointing at non-existent directives,
out-of-range scores, missing reseed metadata. Read-only.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from config_assessment.core.db.doctor import check

CANONICAL = Path("data/ccss_canonical.sql")


@pytest.fixture
def db(tmp_path):
    p = tmp_path / "t.db"
    sqlite3.connect(str(p)).executescript(CANONICAL.read_text())
    return p


def test_canonical_db_is_clean(db):
    # The shipped canonical DB must pass with no errors (warnings tolerated).
    findings = check(db)
    assert [f for f in findings if f.severity == "error"] == []


def test_detects_orphan_misconfig(db):
    conn = sqlite3.connect(str(db))
    conn.execute("INSERT INTO misconfigurations "
                 "(target_id,target_name,directive,bad_value,good_value,"
                 "av,au,ac,c,i,a,base_score,temporal_score,gel,grl) "
                 "VALUES(999,'ghost','x','b','g','N','N','L','P','N','N',5,5,'ND','ND')")
    conn.commit(); conn.close()
    errs = [f for f in check(db) if f.category == "orphan"]
    assert errs and "ghost" in errs[0].message


def test_detects_chain_with_unknown_directive(db):
    conn = sqlite3.connect(str(db))
    tid = conn.execute("SELECT id FROM targets WHERE name='nginx'").fetchone()[0]
    conn.execute("INSERT INTO attack_chains "
                 "(target_id,target_name,chain_id,misconfig_directives,"
                 "amplification,justification) "
                 "VALUES(?,?,?,?,?,?)",
                 (tid, "nginx", "bad-chain", '["nonexistent_directive"]', 1.5, "x"))
    conn.commit(); conn.close()
    warns = [f for f in check(db) if f.category == "chain"]
    assert any("nonexistent_directive" in w.message for w in warns)


def test_detects_out_of_range_score(db):
    conn = sqlite3.connect(str(db))
    conn.execute("UPDATE misconfigurations SET temporal_score=42 "
                 "WHERE target_name='nginx' LIMIT 1"
                 if False else
                 "UPDATE misconfigurations SET temporal_score=42 "
                 "WHERE rowid=(SELECT rowid FROM misconfigurations "
                 "WHERE target_name='nginx' LIMIT 1)")
    conn.commit(); conn.close()
    errs = [f for f in check(db) if f.category == "score"]
    assert errs and "out of range" in errs[0].message


def test_flags_missing_meta(db):
    # Canonical has caspar_meta; drop it to simulate an old DB.
    conn = sqlite3.connect(str(db))
    conn.execute("DROP TABLE IF EXISTS caspar_meta")
    conn.commit(); conn.close()
    warns = [f for f in check(db) if f.category == "meta"]
    assert warns and warns[0].severity == "warning"


# ── narrative audit (--strict) ─────────────────────────────────────────

def _set_narrative(conn, target, directive, narrative):
    conn.execute("UPDATE misconfigurations SET narrative=? "
                 "WHERE rowid=(SELECT rowid FROM misconfigurations "
                 "WHERE target_name=? AND directive=? LIMIT 1)",
                 (narrative, target, directive))
    conn.commit()


def test_strict_flags_categorical_claim(db):
    conn = sqlite3.connect(str(db))
    d = conn.execute("SELECT directive FROM misconfigurations "
                     "WHERE target_name='nginx' LIMIT 1").fetchone()[0]
    _set_narrative(conn, "nginx", d,
                   '{"description": "This enables remote code execution on the server."}')
    conn.close()
    warns = [f for f in check(db, strict=True) if f.category == "narrative"]
    assert any("remote code execution" in w.message for w in warns)


def test_strict_ignores_hedged_claim(db):
    conn = sqlite3.connect(str(db))
    d = conn.execute("SELECT directive FROM misconfigurations "
                     "WHERE target_name='nginx' LIMIT 1").fetchone()[0]
    _set_narrative(conn, "nginx", d,
                   '{"description": "This could lead to remote code execution if chained with another flaw."}')
    conn.close()
    warns = [f for f in check(db, strict=True) if f.category == "narrative"]
    assert not any(d in w.message for w in warns)   # hedged → not flagged


def test_strict_audit_is_opt_in(db):
    conn = sqlite3.connect(str(db))
    d = conn.execute("SELECT directive FROM misconfigurations "
                     "WHERE target_name='nginx' LIMIT 1").fetchone()[0]
    _set_narrative(conn, "nginx", d,
                   '{"description": "arbitrary code execution."}')
    conn.close()
    # Without --strict, narratives are not audited.
    assert not [f for f in check(db, strict=False) if f.category == "narrative"]
    assert [f for f in check(db, strict=True) if f.category == "narrative"]
