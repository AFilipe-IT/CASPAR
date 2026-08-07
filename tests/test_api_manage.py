"""
tests/test_api_manage.py
--------------------------
Management surface: settings, doctor, suppressions, fix previews,
promote, badges, and the job-backed maintenance commands.

Two behaviours here are deliberately *narrower* than the CLI, and the tests
assert that narrowness rather than treating it as a gap:
  * fix never writes — the CLI's --in-place would overwrite a live config;
  * suppressions require an explicit file path — the CLI's cwd-relative
    default is meaningless for a long-running server.
Network/LLM-bound commands (promote, refresh, fetch-exploits) are
monkeypatched: what's under test is the wiring, not the enrichment logic.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from config_assessment.core import runtime
from config_assessment.core.db.database import Database
from config_assessment.core.engines.scoring import base_score, temporal_score
from config_assessment.core.models import Misconfiguration, TargetMetadata


@pytest.fixture(autouse=True)
def clear_registry():
    original = list(runtime._REGISTRY)
    runtime._REGISTRY.clear()
    yield
    runtime._REGISTRY.clear()
    runtime._REGISTRY.extend(original)


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)

    database = Database(path)
    database.upsert_target(TargetMetadata(
        name="dummy", display_name="Dummy Test Target", version="1.0",
        benchmark_source="CCSS-Scan Phase 1 test fixture",
    ))
    bs = base_score("N", "N", "L", "P", "P", "P")
    database.upsert_misconfiguration(Misconfiguration(
        target_name="dummy", directive="DangerousOption", bad_value="on",
        good_value="off", av="N", au="N", ac="L", c="P", i="P", a="P",
        base_score=bs, temporal_score=temporal_score(bs, "M", "H"),
        gel="M", grl="H", cves=["CVE-2023-00001"], cce_id="CCE-TEST-001",
        cis_section="1.1",
        justification="DangerousOption=on exposes the system.",
        recommendation="Set DangerousOption=off in the config.",
    ))
    database.close()
    yield path
    os.unlink(path)


@pytest.fixture
def dummy_config_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dummy",
                                      delete=False) as f:
        f.write("# Dummy config\nListen=0.0.0.0:80\nDangerousOption=on\n")
        path = f.name
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def suppress_file():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.unlink(path)          # the store creates it on save
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def client(db_path):
    from config_assessment.plugins.dummy import DummyPlugin
    runtime.register_plugin(DummyPlugin())

    from config_assessment.api.app import create_app
    with TestClient(create_app(db_path=db_path)) as c:
        yield c


class TestSettings:

    def test_reports_effective_config(self, client, db_path):
        body = client.get("/api/v1/settings").json()
        assert body["db_path"] == db_path
        assert body["caspar_version"]
        assert "dummy" in body["registered_plugins"]

    def test_never_leaks_the_api_key(self, client, monkeypatch):
        """Only whether a key is enforced, never its value."""
        monkeypatch.setenv("CASPAR_API_KEY", "super-secret-value")
        body = client.get("/api/v1/settings").json()
        assert body["api_key_required"] is True
        assert "super-secret-value" not in json.dumps(body)


class TestDoctor:

    def test_clean_db_reports_no_errors(self, client):
        """The fixture DB has no caspar_meta (that table is created by the
        reseed path), so doctor correctly emits one 'meta' warning — the
        contract under test is that nothing is reported as an *error*."""
        body = client.get("/api/v1/doctor").json()
        assert body["errors"] == 0
        assert all(f["severity"] == "warning" for f in body["findings"])

    def test_strict_mode_runs(self, client):
        assert client.get("/api/v1/doctor?strict=true").status_code == 200

    def test_findings_are_counted_not_signalled_by_status(self, client,
                                                           db_path):
        """A dirty DB is still a successful check — the counts carry the
        verdict, since 500 would mean 'the check failed to run'.

        Both severities are seeded on purpose: an orphan chain is a *warning*
        (the chain can never fire, but nothing is corrupt), while a score
        outside 0..10 is an *error*. The endpoint must report each as doctor
        classifies it, not flatten them into one verdict.
        """
        from config_assessment.core.models import AttackChain
        with Database(db_path) as db:
            db.upsert_attack_chain(AttackChain(
                chain_id="orphan-chain", target_name="dummy",
                misconfig_directives=["NoSuchDirective"], amplification=1.5,
                justification="references a directive that does not exist"))
            db.conn.execute(
                "UPDATE misconfigurations SET base_score = 99.0 "
                "WHERE directive = 'DangerousOption'")
            db.conn.commit()

        resp = client.get("/api/v1/doctor")
        assert resp.status_code == 200      # the check ran, and said so
        body = resp.json()
        assert body["healthy"] is False
        assert body["errors"] >= 1          # the out-of-range score
        assert body["warnings"] >= 1        # the orphan chain
        assert any("NoSuchDirective" in f["message"] for f in body["findings"])
        assert any(f["severity"] == "error" and f["category"] == "score"
                   for f in body["findings"])


class TestSuppressions:

    def test_requires_an_explicit_file(self, client):
        """No cwd-relative fallback — see the module docstring."""
        assert client.get("/api/v1/suppressions").status_code == 400
        assert client.post("/api/v1/suppressions", json={
            "directive": "X", "reason": "because"}).status_code == 400

    def test_reason_is_mandatory(self, client, suppress_file):
        resp = client.post("/api/v1/suppressions", json={
            "directive": "DangerousOption", "reason": "",
            "suppress_file": suppress_file})
        assert resp.status_code == 422

    def test_create_list_delete_roundtrip(self, client, suppress_file):
        created = client.post("/api/v1/suppressions", json={
            "directive": "DangerousOption",
            "reason": "Accepted by architecture",
            "suppress_file": suppress_file})
        assert created.status_code == 201
        assert created.json()["date"]

        listed = client.get(
            f"/api/v1/suppressions?suppress_file={suppress_file}").json()
        assert [s["directive"] for s in listed] == ["DangerousOption"]

        removed = client.delete(
            f"/api/v1/suppressions/DangerousOption"
            f"?suppress_file={suppress_file}")
        assert removed.json()["removed"] == 1
        assert client.get(
            f"/api/v1/suppressions?suppress_file={suppress_file}").json() == []


class TestFixPreview:

    def test_returns_edits_without_writing(self, client, dummy_config_file):
        """The whole point: a diff, and the file untouched."""
        before = open(dummy_config_file).read()
        resp = client.post("/api/v1/fix/preview",
                            json={"input_path": dummy_config_file})
        assert resp.status_code == 200

        body = resp.json()
        assert body["applied"] is False
        assert open(dummy_config_file).read() == before

    def test_no_fixed_sidecar_file_is_created(self, client,
                                               dummy_config_file):
        """`caspar fix` writes <file>.fixed by default; the API must not."""
        client.post("/api/v1/fix/preview",
                    json={"input_path": dummy_config_file})
        assert not os.path.exists(dummy_config_file + ".fixed")

    def test_unknown_path_is_400(self, client):
        resp = client.post("/api/v1/fix/preview",
                            json={"input_path": "/no/such/file.dummy"})
        assert resp.status_code == 400


class TestPromote:

    def test_stats_scoreboard(self, client):
        rows = client.get("/api/v1/promote/stats").json()
        assert rows == [{"target": "dummy", "rules": 1, "promoted": 0,
                         "needs_review": 0}]

    def test_counts_promoted_rules(self, client, db_path):
        with Database(db_path) as db:
            bs = base_score("N", "N", "L", "P", "P", "P")
            db.upsert_misconfiguration(Misconfiguration(
                target_name="dummy", directive="LearnedFlag", bad_value="on",
                good_value="", av="N", au="N", ac="L", c="P", i="P", a="P",
                base_score=bs, temporal_score=temporal_score(bs, "M", "H"),
                gel="M", grl="H",
                justification="promoted from unknown-directive assessment",
            ))

        row = client.get("/api/v1/promote/stats").json()[0]
        assert row["promoted"] == 1
        assert row["needs_review"] == 1     # empty good_value

    def test_start_returns_202(self, client, dummy_config_file, monkeypatch):
        import click
        monkeypatch.setattr(click.Context, "invoke",
                            lambda self, *a, **k: None)
        resp = client.post("/api/v1/promote",
                            json={"input_path": dummy_config_file})
        assert resp.status_code == 202
        assert resp.json()["job_id"]

    def test_unknown_path_is_400_not_a_job(self, client):
        resp = client.post("/api/v1/promote",
                            json={"input_path": "/no/such/file.dummy"})
        assert resp.status_code == 400


class TestBadge:

    def test_badge_for_a_scan(self, client, dummy_config_file):
        scan_id = client.post("/api/v1/scans",
                               json={"input_path": dummy_config_file}).json()["scan_id"]
        body = client.get(f"/api/v1/scans/{scan_id}/badge").json()
        assert body["url"].startswith("https://img.shields.io/")
        assert "](" in body["markdown"]

    def test_unknown_scan_is_404(self, client):
        assert client.get("/api/v1/scans/nope/badge").status_code == 404


class TestMaintenanceJobs:
    """refresh / fetch-exploits go through the job runner."""

    @pytest.fixture(autouse=True)
    def no_network(self, monkeypatch):
        import click
        monkeypatch.setattr(click.Context, "invoke", lambda self, *a, **k: None)

    def test_refresh_returns_202(self, client):
        resp = client.post("/api/v1/maintenance/refresh", json={})
        assert resp.status_code == 202
        assert resp.json()["job_id"]

    def test_refresh_never_persists_the_nvd_key(self, client):
        """params_json is served back by GET /jobs — a credential must not
        be in it."""
        job_id = client.post("/api/v1/maintenance/refresh", json={
            "nvd_key": "super-secret-nvd-key"}).json()["job_id"]

        job = client.get(f"/api/v1/jobs/{job_id}").json()
        assert "super-secret-nvd-key" not in job["params_json"]
        assert json.loads(job["params_json"])["nvd_key_supplied"] is True

    def test_a_cli_sys_exit_fails_the_job_instead_of_hanging_it(
            self, client, monkeypatch):
        """CLI commands signal failure with sys.exit(N), which is a
        BaseException — if the runner only caught Exception the job would stay
        `running` forever with no error recorded."""
        import time

        import click

        def _boom(self, *a, **k):
            raise SystemExit(2)

        monkeypatch.setattr(click.Context, "invoke", _boom)

        job_id = client.post("/api/v1/maintenance/refresh",
                              json={}).json()["job_id"]
        # Poll for a *terminal* status: 'queued' also means "not running yet",
        # so waiting for != 'running' would pass on the very first read.
        for _ in range(50):
            job = client.get(f"/api/v1/jobs/{job_id}").json()
            if job["status"] in ("succeeded", "failed", "cancelled"):
                break
            time.sleep(0.1)

        assert job["status"] == "failed"
        assert "status 2" in job["error"]

    def test_fetch_exploits_returns_202(self, client):
        resp = client.post("/api/v1/maintenance/fetch-exploits",
                            json={"product": "apache-httpd",
                                  "versions": ["2.4.49"]})
        assert resp.status_code == 202
        assert resp.json()["job_id"]
