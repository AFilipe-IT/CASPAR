"""
tests/test_api_jobs.py
------------------------
Background job infrastructure: the generic job/log polling
surface (config_assessment/api/routers/jobs.py) and the two kinds that use
it today (builds, plugin installs). Job target functions are fast fakes /
monkeypatched here — a real `caspar build` is LLM/network-bound and would
make this suite slow and flaky; job_runner.py's own contract (status
transitions, seq-ordered logs, restart reconciliation) is what's under test,
not the build/plugin_add business logic itself (covered elsewhere).
"""

from __future__ import annotations

import os
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from config_assessment.api import job_runner
from config_assessment.core import runtime
from config_assessment.core.db.database import Database


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
    Database(path).close()
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


def _wait_for_terminal(db_path: str, job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    with Database(db_path) as db:
        while time.monotonic() < deadline:
            job = db.get_job(job_id)
            if job["status"] in ("succeeded", "failed", "cancelled"):
                return job
            time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not reach a terminal state in {timeout}s")


class TestJobRunner:
    def test_job_lifecycle_success(self, db_path):
        def target_fn(_db_path, emit):
            emit("step 1")
            emit("step 2")
            return {"ok": True}

        job_id = job_runner.start_job(db_path, kind="test", params={}, target_fn=target_fn)
        job = _wait_for_terminal(db_path, job_id)

        assert job["status"] == "succeeded"
        assert job["started_at"] is not None
        assert job["finished_at"] is not None
        assert '"ok": true' in job["result_json"]

    def test_job_lifecycle_failure_records_error(self, db_path):
        def target_fn(_db_path, emit):
            emit("about to fail")
            raise RuntimeError("boom")

        job_id = job_runner.start_job(db_path, kind="test", params={}, target_fn=target_fn)
        job = _wait_for_terminal(db_path, job_id)

        assert job["status"] == "failed"
        assert "boom" in job["error"]

    def test_job_logs_ordered_by_seq(self, db_path):
        def target_fn(_db_path, emit):
            for i in range(5):
                emit(f"line {i}")
            return {}

        job_id = job_runner.start_job(db_path, kind="test", params={}, target_fn=target_fn)
        _wait_for_terminal(db_path, job_id)

        with Database(db_path) as db:
            logs = db.get_job_logs(job_id)
        assert [l["line"] for l in logs] == [f"line {i}" for i in range(5)]
        assert [l["seq"] for l in logs] == sorted(l["seq"] for l in logs)

    def test_job_logs_after_seq_only_returns_new_lines(self, db_path):
        def target_fn(_db_path, emit):
            for i in range(3):
                emit(f"line {i}")
            return {}

        job_id = job_runner.start_job(db_path, kind="test", params={}, target_fn=target_fn)
        _wait_for_terminal(db_path, job_id)

        with Database(db_path) as db:
            all_logs = db.get_job_logs(job_id)
            tail = db.get_job_logs(job_id, after=all_logs[0]["seq"])
        assert [l["line"] for l in tail] == ["line 1", "line 2"]

    def test_reconcile_on_startup_marks_stuck_jobs_failed(self, db_path):
        with Database(db_path) as db:
            db.create_job("orphan-job", kind="test", params={})
            db.mark_job_started("orphan-job")

        job_runner.reconcile_on_startup(db_path)

        with Database(db_path) as db:
            job = db.get_job("orphan-job")
        assert job["status"] == "failed"
        assert "restart" in job["error"]


class TestJobsRouter:
    def test_get_unknown_job_404s(self, client):
        r = client.get("/api/v1/jobs/does-not-exist")
        assert r.status_code == 404

    def test_get_unknown_job_logs_404s(self, client):
        r = client.get("/api/v1/jobs/does-not-exist/logs")
        assert r.status_code == 404

    def test_list_jobs_filters_by_kind(self, client, db_path):
        with Database(db_path) as db:
            db.create_job("job-a", kind="build", params={})
            db.create_job("job-b", kind="plugin_add", params={})

        r = client.get("/api/v1/jobs", params={"kind": "build"})
        assert r.status_code == 200
        ids = [j["id"] for j in r.json()]
        assert ids == ["job-a"]


class TestBuildsRouter:
    def test_create_build_returns_job_id_and_completes(self, client, db_path, monkeypatch):
        calls = []

        def fake_run_build_job(benchmark, model, ollama_url, target, dry_run, db_path, emit):
            calls.append(benchmark)
            emit("building...")
            return 7

        monkeypatch.setattr("cli.commands.build_cmds.run_build_job", fake_run_build_job)

        r = client.post("/api/v1/builds", json={
            "benchmark": "fake.pdf", "target": "apache-httpd", "dry_run": True,
        })
        assert r.status_code == 202
        job_id = r.json()["job_id"]

        job = _wait_for_terminal(db_path, job_id)
        assert job["status"] == "succeeded"
        assert calls == ["fake.pdf"]

        logs = client.get(f"/api/v1/jobs/{job_id}/logs").json()
        assert any(l["line"] == "building..." for l in logs)

    def test_list_builds_only_returns_build_kind(self, client, db_path):
        with Database(db_path) as db:
            db.create_job("b1", kind="build", params={})
            db.create_job("p1", kind="plugin_add", params={})

        r = client.get("/api/v1/builds")
        assert r.status_code == 200
        ids = [j["id"] for j in r.json()]
        assert ids == ["b1"]


class TestPluginsRouter:
    def test_list_plugins_shows_installed_and_available(self, client):
        r = client.get("/api/v1/plugins")
        assert r.status_code == 200
        body = r.json()
        assert any(p["name"] == "dummy" for p in body["installed"])
        assert isinstance(body["available"], list)

    def test_install_plugin_from_source_path_runs_as_job(self, client, db_path, monkeypatch):
        invoked = {}

        def fake_ctx_invoke(self, callback, **kwargs):
            invoked.update(kwargs)

        monkeypatch.setattr("click.Context.invoke", fake_ctx_invoke)

        r = client.post("/api/v1/plugins/install", json={
            "source": "/tmp/fake-benchmark.pdf", "dry_run": True,
        })
        assert r.status_code == 202
        job_id = r.json()["job_id"]

        job = _wait_for_terminal(db_path, job_id)
        assert job["status"] == "succeeded"
        assert invoked["source"] == "/tmp/fake-benchmark.pdf"
        assert invoked["yes"] is True

    def test_add_manual_to_installed_plugin_runs_as_job(self, client, db_path,
                                                         monkeypatch):
        """The retroactive RAG path — `plugin add --manual` only covers
        install time, so this is a distinct command, not a flag on install."""
        invoked = {}

        def fake_ctx_invoke(self, callback, **kwargs):
            invoked.update(kwargs)

        monkeypatch.setattr("click.Context.invoke", fake_ctx_invoke)

        r = client.post("/api/v1/plugins/manual", json={
            "target": "dummy", "manual": "https://example.invalid/docs.pdf",
        })
        assert r.status_code == 202

        job = _wait_for_terminal(db_path, r.json()["job_id"])
        assert job["status"] == "succeeded"
        assert invoked["target"] == "dummy"
        assert invoked["manual"] == "https://example.invalid/docs.pdf"
