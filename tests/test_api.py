"""
tests/test_api.py
------------------
REST API integration tests (FastAPI TestClient). Mirrors test_runtime.py's
dummy-plugin fixture pattern: the API must call the exact same CVM Core as
the CLI and produce identical results (`caspar scan` vs `POST /api/v1/scans`).

Uses a real file-backed DB (not :memory:) because config_assessment.api.deps
opens one Database(db_path) connection per request — an in-memory DB would
not be shared across requests.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from config_assessment.core import runtime
from config_assessment.core.db.database import Database
from config_assessment.core.engines.scoring import base_score, temporal_score
from config_assessment.core.models import AttackChain, Misconfiguration, TargetMetadata


@pytest.fixture(autouse=True)
def clear_registry():
    original = list(runtime._REGISTRY)
    runtime._REGISTRY.clear()
    yield
    runtime._REGISTRY.clear()
    runtime._REGISTRY.extend(original)


@pytest.fixture
def db_path():
    """File-backed DB, pre-loaded with dummy target data (mirrors
    test_runtime.py's `db` fixture, but on disk so the API's per-request
    connections all see the same data)."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # Database() creates the schema fresh

    database = Database(path)
    meta = TargetMetadata(
        name="dummy", display_name="Dummy Test Target", version="1.0",
        benchmark_source="CCSS-Scan Phase 1 test fixture",
    )
    database.upsert_target(meta)

    bs = base_score("N", "N", "L", "P", "P", "P")
    ts = temporal_score(bs, "M", "H")
    database.upsert_misconfiguration(Misconfiguration(
        target_name="dummy", directive="DangerousOption", bad_value="on",
        good_value="off", av="N", au="N", ac="L", c="P", i="P", a="P",
        base_score=bs, temporal_score=ts, gel="M", grl="H",
        cves=["CVE-2023-00001"], cce_id="CCE-TEST-001", cis_section="1.1",
        justification="DangerousOption=on exposes the system.",
        recommendation="Set DangerousOption=off in the config.",
    ))
    database.upsert_attack_chain(AttackChain(
        chain_id="test-chain", target_name="dummy",
        misconfig_directives=["DangerousOption", "Listen"],
        amplification=1.5, justification="Combined attack path.",
    ))
    database.close()

    yield path
    os.unlink(path)


@pytest.fixture
def dummy_config_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dummy", delete=False) as f:
        f.write("# Dummy config\n")
        f.write("Listen=0.0.0.0:80\n")
        f.write("DangerousOption=on\n")
        f.write("LogLevel=warn\n")
        path = f.name
    yield path
    os.unlink(path)


@pytest.fixture
def client(db_path):
    from config_assessment.plugins.dummy import DummyPlugin
    runtime.register_plugin(DummyPlugin())

    from config_assessment.api.app import create_app
    app = create_app(db_path=db_path)
    with TestClient(app) as c:
        yield c


# ------------------------------------------------------------------ #
# Health / targets                                                     #
# ------------------------------------------------------------------ #

class TestHealthAndTargets:
    def test_health(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["db_reachable"] is True
        assert body["plugins_registered"] >= 1

    def test_list_targets(self, client):
        r = client.get("/api/v1/targets")
        assert r.status_code == 200
        names = [t["name"] for t in r.json()]
        assert "dummy" in names


# ------------------------------------------------------------------ #
# Scans                                                                #
# ------------------------------------------------------------------ #

class TestScans:
    def test_create_scan(self, client, dummy_config_file):
        r = client.post("/api/v1/scans", json={"input_path": dummy_config_file})
        assert r.status_code == 201
        body = r.json()
        assert body["target_name"] == "dummy"
        assert body["total_issues_found"] >= 1
        assert body["global_temporal_score"] > 0

    def test_create_scan_unknown_path_404s_as_400(self, client):
        r = client.post("/api/v1/scans", json={"input_path": "/no/such/file.dummy"})
        assert r.status_code == 400

    def test_get_scan_roundtrip(self, client, dummy_config_file):
        created = client.post("/api/v1/scans", json={"input_path": dummy_config_file}).json()
        r = client.get(f"/api/v1/scans/{created['scan_id']}")
        assert r.status_code == 200
        assert r.json()["global_temporal_score"] == created["global_temporal_score"]

    def test_get_scan_not_found(self, client):
        r = client.get("/api/v1/scans/does-not-exist")
        assert r.status_code == 404

    def test_list_scans(self, client, dummy_config_file):
        client.post("/api/v1/scans", json={"input_path": dummy_config_file})
        r = client.get("/api/v1/scans")
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_get_scan_chains(self, client, dummy_config_file):
        created = client.post("/api/v1/scans", json={"input_path": dummy_config_file}).json()
        r = client.get(f"/api/v1/scans/{created['scan_id']}/chains")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_delete_scan(self, client, dummy_config_file):
        created = client.post("/api/v1/scans", json={"input_path": dummy_config_file}).json()
        r = client.delete(f"/api/v1/scans/{created['scan_id']}")
        assert r.status_code == 204
        assert client.get(f"/api/v1/scans/{created['scan_id']}").status_code == 404

    def test_delete_scan_not_found(self, client):
        r = client.delete("/api/v1/scans/does-not-exist")
        assert r.status_code == 404

    def test_scan_passed_threshold_default_true(self, client, dummy_config_file):
        r = client.post("/api/v1/scans", json={"input_path": dummy_config_file})
        assert r.status_code == 201
        assert r.json()["passed_threshold"] is True
        assert r.json()["suppressed_count"] == 0

    def test_scan_threshold_gating(self, client, dummy_config_file):
        r = client.post(
            "/api/v1/scans",
            json={"input_path": dummy_config_file, "threshold": 0.1},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["global_temporal_score"] > 0.1
        assert body["passed_threshold"] is False

    def test_scan_suppress_file_hides_and_counts(self, client, dummy_config_file, tmp_path):
        supp = tmp_path / "suppress.json"
        supp.write_text(
            '{"suppressions": [{"directive": "DangerousOption", '
            '"reason": "accepted risk", "bad_value": "on", "date": ""}]}',
            encoding="utf-8",
        )
        r = client.post(
            "/api/v1/scans",
            json={"input_path": dummy_config_file, "suppress_file": str(supp)},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["suppressed_count"] == 1
        assert all(i["directive"] != "DangerousOption" for i in body["issues"])


# ------------------------------------------------------------------ #
# Scan upload (a browser has no server-side path to send)            #
# ------------------------------------------------------------------ #

class TestScanUpload:
    def test_upload_scan(self, client, dummy_config_file):
        with open(dummy_config_file, "rb") as f:
            r = client.post(
                "/api/v1/scans/upload",
                files={"file": ("httpd.dummy", f, "application/octet-stream")},
            )
        assert r.status_code == 201
        body = r.json()
        assert body["target_name"] == "dummy"
        assert body["total_issues_found"] >= 1

    def test_upload_scan_with_threshold(self, client, dummy_config_file):
        with open(dummy_config_file, "rb") as f:
            r = client.post(
                "/api/v1/scans/upload",
                files={"file": ("httpd.dummy", f, "application/octet-stream")},
                data={"threshold": "0.1"},
            )
        assert r.status_code == 201
        assert r.json()["passed_threshold"] is False

    def test_upload_scan_with_host(self, client, dummy_config_file):
        with open(dummy_config_file, "rb") as f:
            r = client.post(
                "/api/v1/scans/upload",
                files={"file": ("httpd.dummy", f, "application/octet-stream")},
                data={"host": "web01"},
            )
        assert r.status_code == 201
        registry = client.get("/api/v1/hosts/registry").json()
        assert any(h["label"] == "web01" for h in registry)


# ------------------------------------------------------------------ #
# Reports / diff                                                       #
# ------------------------------------------------------------------ #

class TestReports:
    def test_export_html_report(self, client, dummy_config_file):
        created = client.post("/api/v1/scans", json={"input_path": dummy_config_file}).json()
        r = client.post(f"/api/v1/scans/{created['scan_id']}/report", json={"format": "html"})
        assert r.status_code == 200
        assert "<html" in r.text.lower()

    def test_export_json_report(self, client, dummy_config_file):
        created = client.post("/api/v1/scans", json={"input_path": dummy_config_file}).json()
        r = client.post(f"/api/v1/scans/{created['scan_id']}/report", json={"format": "json"})
        assert r.status_code == 200
        assert r.json()["scan_id"] == created["scan_id"]

    def test_diff_scans(self, client, dummy_config_file):
        created = client.post("/api/v1/scans", json={"input_path": dummy_config_file}).json()
        r = client.post(f"/api/v1/scans/{created['scan_id']}/diff/{created['scan_id']}")
        assert r.status_code == 200
        body = r.json()
        assert body["score_delta"] == 0.0
        assert body["new_issues"] == []


# ------------------------------------------------------------------ #
# Knowledge / trends / hosts                                          #
# ------------------------------------------------------------------ #

class TestKnowledgeTrendsHosts:
    def test_list_rules(self, client):
        r = client.get("/api/v1/knowledge/targets/dummy/rules")
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_get_rule_not_found(self, client):
        r = client.get("/api/v1/knowledge/targets/dummy/rules/does-not-exist")
        assert r.status_code == 404

    def test_list_chains(self, client):
        r = client.get("/api/v1/knowledge/targets/dummy/chains")
        assert r.status_code == 200

    def test_list_benchmarks(self, client):
        r = client.get("/api/v1/knowledge/benchmarks")
        assert r.status_code == 200

    def test_trends_empty_ok(self, client):
        r = client.get("/api/v1/trends")
        assert r.status_code == 200
        assert r.json() == []

    def test_hosts_after_scan(self, client, dummy_config_file):
        client.post("/api/v1/scans", json={"input_path": dummy_config_file})
        r = client.get("/api/v1/hosts")
        assert r.status_code == 200
        assert "scans" in r.json()


# ------------------------------------------------------------------ #
# Host registry (Operating System entity)                             #
# ------------------------------------------------------------------ #

class TestHostRegistry:
    def test_registry_empty_by_default(self, client):
        r = client.get("/api/v1/hosts/registry")
        assert r.status_code == 200
        assert r.json() == []

    def test_create_host(self, client):
        r = client.post("/api/v1/hosts/registry", json={"label": "web01"})
        assert r.status_code == 201
        assert r.json()["label"] == "web01"

    def test_registry_lists_created_host(self, client):
        client.post("/api/v1/hosts/registry", json={"label": "web01"})
        r = client.get("/api/v1/hosts/registry")
        assert r.status_code == 200
        labels = [h["label"] for h in r.json()]
        assert "web01" in labels

    def test_registry_detail_not_found(self, client):
        r = client.get("/api/v1/hosts/registry/999")
        assert r.status_code == 404

    def test_scan_with_host_resolves_to_registry_detail(self, client, dummy_config_file):
        r = client.post(
            "/api/v1/scans", json={"input_path": dummy_config_file, "host": "web01"},
        )
        assert r.status_code == 201

        registry = client.get("/api/v1/hosts/registry").json()
        host_id = next(h["id"] for h in registry if h["label"] == "web01")

        detail = client.get(f"/api/v1/hosts/registry/{host_id}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["label"] == "web01"
        assert body["rollup"]["scans"]
        assert "categories" in body
        assert body["categories"]  # at least one category populated


# ------------------------------------------------------------------ #
# CLI / API parity                                                     #
# ------------------------------------------------------------------ #

class TestCliApiParity:
    def test_same_input_same_score(self, client, dummy_config_file, db_path):
        api_score = client.post(
            "/api/v1/scans", json={"input_path": dummy_config_file},
        ).json()["global_temporal_score"]

        with Database(db_path) as db:
            cli_result = runtime.scan(dummy_config_file, db)

        assert cli_result.global_temporal_score == api_score
