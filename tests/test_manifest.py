"""
tests/test_manifest.py
----------------------
Reproducibility manifest: every ScanResult records what produced its scores
(CASPAR version, SHA-256 of the knowledge base content, target + rule count,
Python). Matching manifests + matching input_hash ⇒ identical scores — the
auditable form of the build-time/runtime determinism claim.

db_sha256 hashes only the content tables (targets, misconfigurations,
attack_chains, version_exploits) — never scan_results, which every scan
appends to and would otherwise make the hash change on every run even
though the rules themselves never changed.
"""

from __future__ import annotations

import sqlite3

import pytest

from config_assessment.core.manifest import build_manifest


def _make_db(tmp_path, name="kb.db"):
    """A minimal real ccss.db with the tables build_manifest reads."""
    path = tmp_path / name
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY, name TEXT, display_name TEXT,
            version TEXT, benchmark_source TEXT,
            created_at TEXT, updated_at TEXT
        );
        CREATE TABLE misconfigurations (
            id INTEGER PRIMARY KEY, target_id INTEGER, target_name TEXT,
            directive TEXT, bad_value TEXT, good_value TEXT,
            av TEXT, au TEXT, ac TEXT, c TEXT, i TEXT, a TEXT,
            base_score REAL, temporal_score REAL, gel TEXT, grl TEXT,
            cves TEXT, cce_id TEXT, cis_section TEXT, justification TEXT,
            recommendation TEXT, rule_type TEXT, required_when TEXT,
            expected_value_prefix TEXT, narrative TEXT,
            created_at TEXT, updated_at TEXT, confidence REAL
        );
        CREATE TABLE attack_chains (
            id INTEGER PRIMARY KEY, target_id INTEGER, target_name TEXT,
            chain_id TEXT, misconfig_directives TEXT, amplification REAL,
            justification TEXT, cross_target INTEGER, created_at TEXT
        );
        CREATE TABLE version_exploits (
            product TEXT, version TEXT, cve_count INTEGER, kev_count INTEGER,
            max_cvss REAL, cve_ids TEXT, exploits TEXT, fetched_at TEXT
        );
        CREATE TABLE scan_results (
            id TEXT PRIMARY KEY, target_name TEXT, input_path TEXT,
            input_hash TEXT, global_temporal_score REAL, created_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO targets (id, name, display_name, version, "
        "benchmark_source, created_at, updated_at) VALUES "
        "(1,'nginx','NGINX','1.0','CIS','t1','t1')"
    )
    conn.execute(
        "INSERT INTO misconfigurations "
        "(id, target_id, target_name, directive, bad_value, good_value, "
        "av, au, ac, c, i, a, base_score, temporal_score, gel, grl, cves, "
        "cce_id, cis_section, justification, recommendation, rule_type, "
        "required_when, expected_value_prefix, narrative, created_at, "
        "updated_at, confidence) VALUES "
        "(1,1,'nginx','server_tokens','on','off','N','N','L','P','N','N',"
        "5.0,5.0,'','','[]','CCE-1','4.1','why','fix','value',NULL,NULL,"
        "'narrative','t1','t1',1.0)"
    )
    conn.commit()
    conn.close()
    return path


def test_same_content_same_hash(tmp_path):
    db = _make_db(tmp_path)
    m1 = build_manifest(db, "nginx", rules_count=1)
    m2 = build_manifest(db, "nginx", rules_count=1)
    assert m1["db_sha256"] == m2["db_sha256"] is not None
    assert m1 == m2


def test_changed_rule_changes_hash(tmp_path):
    """The point: a modified knowledge base is DETECTABLE from the manifest."""
    db = _make_db(tmp_path)
    before = build_manifest(db, "nginx")["db_sha256"]
    conn = sqlite3.connect(db)
    conn.execute("UPDATE misconfigurations SET base_score = 9.0 WHERE id = 1")
    conn.commit()
    conn.close()
    after = build_manifest(db, "nginx")["db_sha256"]
    assert before != after


def test_new_scan_result_does_not_change_hash(tmp_path):
    """The bug this test guards against: writing scan history must NOT
    perturb the manifest hash of an otherwise-unchanged knowledge base."""
    db = _make_db(tmp_path)
    before = build_manifest(db, "nginx")["db_sha256"]
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO scan_results VALUES ('scan-1','nginx','x.conf','h1',5.0,'t1')"
    )
    conn.commit()
    conn.close()
    after = build_manifest(db, "nginx")["db_sha256"]
    assert before == after


def test_repeated_scans_yield_stable_hash(tmp_path):
    """Integration: two real runtime.scan calls against the same repo DB
    must report the SAME kb sha256 — this is the guarantee the guide and
    the thesis document as 'reproducible: sca <ver> · kb sha256:<hash>'."""
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    dbf = repo / "ccss.db"
    cfg = repo / "test_target" / "test_nginx.conf"
    if not dbf.exists() or not cfg.exists():
        pytest.skip("repo ccss.db / test_target/test_nginx.conf not available")

    import cli.main as m  # discover plugins the way the CLI does
    m._discover_plugins()
    from config_assessment.core.db.database import Database
    from config_assessment.core import runtime

    with Database(str(dbf)) as db:
        result1 = runtime.scan(str(cfg), db)
        hash1 = result1.manifest["db_sha256"]
        result2 = runtime.scan(str(cfg), db)
        hash2 = result2.manifest["db_sha256"]

    assert hash1 == hash2 is not None


def test_memory_db_yields_no_error(tmp_path):
    m = build_manifest(":memory:", "dummy")
    assert m["caspar_version"]


def test_manifest_fields_complete(tmp_path):
    db = _make_db(tmp_path)
    m = build_manifest(db, "apache-httpd", rules_count=42)
    assert set(m) == {"caspar_version", "python", "db_file", "db_sha256",
                      "target", "rules_for_target"}
    assert m["target"] == "apache-httpd"
    assert m["rules_for_target"] == 42
    assert m["db_file"] == "kb.db"


def test_scan_result_carries_manifest(tmp_path):
    """Integration: runtime.scan stamps the manifest onto the result."""
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    dbf = repo / "ccss.db"
    cfg = repo / "test_target" / "test_nginx.conf"
    if not dbf.exists() or not cfg.exists():
        pytest.skip("repo ccss.db / test_target/test_nginx.conf not available")

    import cli.main as m  # discover plugins the way the CLI does
    m._discover_plugins()
    from config_assessment.core.db.database import Database
    from config_assessment.core import runtime

    with Database(str(dbf)) as db:
        result = runtime.scan(str(cfg), db)

    man = result.manifest
    assert man["db_sha256"] is not None
    assert man["target"] == result.target_name
    assert man["rules_for_target"] and man["rules_for_target"] > 0
    # The manifest must survive the JSON report (that's where auditors read it).
    import json
    assert json.loads(result.model_dump_json())["manifest"] == man
