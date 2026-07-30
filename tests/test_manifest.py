"""
tests/test_manifest.py
----------------------
Reproducibility manifest: every ScanResult records what produced its scores
(AEGIS version, SHA-256 of the knowledge base, target + rule count, Python).
Matching manifests + matching input_hash ⇒ identical scores — the auditable
form of the build-time/runtime determinism claim.
"""

from __future__ import annotations

from pathlib import Path

from config_assessment.core.manifest import build_manifest, _sha256_file


def test_same_file_same_hash(tmp_path):
    db = tmp_path / "kb.db"
    db.write_bytes(b"rules v1")
    m1 = build_manifest(db, "nginx", rules_count=10)
    m2 = build_manifest(db, "nginx", rules_count=10)
    assert m1["db_sha256"] == m2["db_sha256"] is not None
    assert m1 == m2  # fully deterministic for the same inputs


def test_changed_kb_changes_hash(tmp_path):
    """The point: a modified knowledge base is DETECTABLE from the manifest."""
    db = tmp_path / "kb.db"
    db.write_bytes(b"rules v1")
    before = build_manifest(db, "nginx")["db_sha256"]
    db.write_bytes(b"rules v2 - one score changed")
    after = build_manifest(db, "nginx")["db_sha256"]
    assert before != after


def test_memory_db_yields_no_hash():
    m = build_manifest(":memory:", "dummy")
    assert m["db_sha256"] is None          # nothing on disk to attest
    assert m["caspar_version"]             # but code version is still stamped


def test_manifest_fields_complete(tmp_path):
    db = tmp_path / "kb.db"
    db.write_bytes(b"x")
    m = build_manifest(db, "apache-httpd", rules_count=42)
    assert set(m) == {"caspar_version", "python", "db_file", "db_sha256",
                      "target", "rules_for_target"}
    assert m["target"] == "apache-httpd"
    assert m["rules_for_target"] == 42
    assert m["db_file"] == "kb.db"


def test_sha256_streams_large_file(tmp_path):
    big = tmp_path / "big.db"
    big.write_bytes(b"a" * (2 << 20))      # 2 MiB — crosses the chunk boundary
    import hashlib
    assert _sha256_file(big) == hashlib.sha256(b"a" * (2 << 20)).hexdigest()


def test_scan_result_carries_manifest(tmp_path):
    """Integration: runtime.scan stamps the manifest onto the result."""
    import pytest
    repo = Path(__file__).resolve().parent.parent
    dbf = repo / "ccss.db"
    cfg = repo / "test_nginx.conf"
    if not dbf.exists() or not cfg.exists():
        pytest.skip("repo ccss.db / test_nginx.conf not available")

    import cli.main as m  # discover plugins the way the CLI does
    m._discover_plugins()
    from config_assessment.core.db.database import Database
    from config_assessment.core import runtime

    with Database(str(dbf)) as db:
        result = runtime.scan(str(cfg), db)

    man = result.manifest
    assert man["db_sha256"] == _sha256_file(dbf)
    assert man["target"] == result.target_name
    assert man["rules_for_target"] and man["rules_for_target"] > 0
    # The manifest must survive the JSON report (that's where auditors read it).
    import json
    assert json.loads(result.model_dump_json())["manifest"] == man
