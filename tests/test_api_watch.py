"""
tests/test_api_watch.py
-------------------------
Watch REST surface: server-driven watch sessions and their lifecycle controls
(config_assessment/api/routers/watch.py + api/watch_runner.py), plus the
shared liveness rules in core/watch_session.py.

Liveness is time-based, so these tests use a deliberately short --interval
and sleep just past the 2x window rather than mocking the clock — the
heartbeat/staleness contract is exactly what's under test, and faking time
here would test the mock instead of the behaviour.
"""

from __future__ import annotations

import os
import tempfile
import time
from datetime import datetime, timedelta, timezone

import pytest
pytest.importorskip("fastapi", reason="API tests need the [api] extra "
                    "(pip install -e '.[dev]')")

from fastapi.testclient import TestClient  # noqa: E402

from config_assessment.api import watch_runner
from config_assessment.core import runtime
from config_assessment.core.db.database import Database
from config_assessment.core.engines.scoring import base_score, temporal_score
from config_assessment.core.models import Misconfiguration, TargetMetadata
from config_assessment.core.watch_session import is_live, session_context

INTERVAL = 0.3          # poll cadence for the runner under test
STALE_AFTER = 1.2       # comfortably past 2 x INTERVAL


def _wait_until(fetch, predicate, timeout: float = 10.0, step: float = 0.1):
    """Poll `fetch()` until `predicate` holds, then return the last value.

    Liveness here ages in wall-clock time, so a fixed sleep is a race on a
    loaded machine. Returns the final value either way — the caller still
    asserts, so a timeout surfaces as that assertion failing rather than as
    an opaque error from in here.
    """
    deadline = time.monotonic() + timeout
    value = fetch()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(step)
        value = fetch()
    return value


@pytest.fixture(autouse=True)
def clear_watch_registry():
    """No session may outlive its test — these are real daemon threads."""
    yield
    watch_runner.clear_registry()


@pytest.fixture(autouse=True)
def clear_registry():
    original = list(runtime._REGISTRY)
    runtime._REGISTRY.clear()
    yield
    runtime._REGISTRY.clear()
    runtime._REGISTRY.extend(original)


@pytest.fixture
def db_path():
    """File-backed DB seeded with the dummy target, as in test_api.py — the
    watch loop runs real scans, so the knowledge base must be populated."""
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
def config_file():
    """A .dummy config the DummyPlugin claims (see test_api.py)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dummy",
                                      delete=False) as f:
        f.write("# Dummy config\nListen=0.0.0.0:80\nDangerousOption=on\n")
        path = f.name
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def client(db_path):
    from config_assessment.plugins.dummy import DummyPlugin
    runtime.register_plugin(DummyPlugin())

    from config_assessment.api.app import create_app
    app = create_app(db_path=db_path)
    with TestClient(app) as c:
        yield c


def _wait_for_events(client, session_id: str, minimum: int,
                      timeout: float = 6.0) -> int:
    """Poll until the session has at least `minimum` persisted events."""
    deadline = time.time() + timeout
    count = 0
    while time.time() < deadline:
        resp = client.get(f"/api/v1/watch/{session_id}")
        if resp.status_code == 200:
            count = len(resp.json()["events"])
            if count >= minimum:
                return count
        time.sleep(0.1)
    return count


class TestLivenessRules:
    """core/watch_session.py — the logic both UIs now share."""

    def test_fresh_heartbeat_is_live(self):
        now = datetime.now(timezone.utc).isoformat()
        assert is_live({"last_seen": now, "watch_interval": 1.0}) is True

    def test_heartbeat_older_than_two_intervals_is_stale(self):
        old = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        assert is_live({"last_seen": old, "watch_interval": 1.0}) is False

    def test_falls_back_to_scan_timestamp_without_heartbeat(self):
        now = datetime.now(timezone.utc).isoformat()
        assert is_live({"last_seen": None, "timestamp": now,
                        "watch_interval": 5.0}) is True

    def test_unparseable_timestamp_is_not_live(self):
        assert is_live({"last_seen": "not-a-date", "watch_interval": 1.0}) is False
        assert is_live({"watch_interval": 1.0}) is False

    def test_session_context_returns_none_when_unknown(self, db_path):
        with Database(db_path) as db:
            assert session_context("does-not-exist", db) is None


class TestWatchStart:

    def test_start_returns_202_and_session_id(self, client, config_file):
        resp = client.post("/api/v1/watch",
                            json={"path": config_file, "interval": INTERVAL})
        assert resp.status_code == 202
        body = resp.json()
        assert body["watch_session"]
        assert body["interval"] == INTERVAL

    def test_start_creates_a_live_session_immediately(self, client, config_file):
        """Live from the moment it starts, not only after the first tick.

        Both facts are read from a single response on purpose. Waiting for the
        event and then re-fetching to check liveness splits the assertion
        across two requests, and the heartbeat can age past its 2x window in
        between — the test then failed intermittently on a loaded machine
        while the runner was behaving correctly.
        """
        session_id = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]

        # Before the first event the session is a 404, whose body has no
        # "events" key at all — hence .get() rather than indexing.
        body = _wait_until(
            lambda: client.get(f"/api/v1/watch/{session_id}").json(),
            lambda b: b.get("events") and b["latest"]["live"],
        )
        latest = body["latest"]
        assert latest["live"] is True
        assert latest["runner_state"] == "running"

    def test_baseline_scan_is_persisted(self, client, config_file):
        session_id = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        assert _wait_for_events(client, session_id, 1) >= 1

    def test_unknown_path_is_400_not_a_dead_thread(self, client):
        resp = client.post("/api/v1/watch",
                            json={"path": "/no/such/config.conf"})
        assert resp.status_code == 400

    def test_a_session_that_dies_surfaces_with_its_reason(self, client, tmp_path):
        """Uma sessão que rebenta ao primeiro ciclo tem de aparecer na lista.

        O caso real: um ficheiro cujo nome nenhum plugin reconhece. O POST
        devolvia 202, a thread morria, e como nunca se escreveu resultado
        nenhum a sessão não vinha da base de dados — a consola aceitava o
        pedido e depois não mostrava nem a sessão nem o erro. Existir o
        ficheiro é o que distingue este caso do 400 de caminho inexistente:
        aqui a validação passa e a falha só acontece dentro da thread.
        """
        doomed = tmp_path / "sem-plugin-nenhum.conf"
        doomed.write_text("irrelevante\n")

        resp = client.post("/api/v1/watch",
                            json={"path": str(doomed), "interval": INTERVAL})
        assert resp.status_code == 202
        session_id = resp.json()["watch_session"]

        entry = _wait_until(
            lambda: next((s for s in client.get("/api/v1/watch").json()
                          if s["watch_session"] == session_id), None),
            lambda e: e is not None and e["runner_state"] == "failed",
        )
        assert entry["runner_state"] == "failed"
        # A mensagem é o que torna isto accionável — diz qual é o problema.
        assert entry["error"]
        assert "plugin" in entry["error"].lower()

    def test_session_appears_in_the_list(self, client, config_file):
        session_id = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        _wait_for_events(client, session_id, 1)

        sessions = client.get("/api/v1/watch").json()
        assert session_id in [s["watch_session"] for s in sessions]

    def test_starting_the_same_path_twice_reuses_the_session(
            self, client, config_file):
        """Carregar em "Start watching" outra vez não abre um segundo
        observador do mesmo ficheiro.

        Duas sessões sobre a mesma configuração produzem dois históricos
        concorrentes do mesmo alvo, e a consola mostra a mais recente — que
        nasce com um evento só e sem histórico. Na prática isso lia-se como o
        watch a perder o fio às edições, quando o que havia era a vista a
        saltar entre sessões que discordam.
        """
        first = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        second = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]

        assert second == first
        # Só depois do primeiro evento: a sessão aparece na lista quando
        # tiver escrito um resultado, e ler antes disso mede a corrida, não
        # o comportamento.
        _wait_for_events(client, first, 1)
        rows = [s for s in client.get("/api/v1/watch").json()
                if s["input_path"] == config_file]
        assert len(rows) == 1

    def test_a_stopped_path_can_be_watched_again(self, client, config_file):
        """A reutilização é só de sessões vivas: parar e recomeçar tem de
        dar uma sessão nova, senão o botão deixava de funcionar depois de se
        parar uma."""
        first = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        client.post(f"/api/v1/watch/{first}/stop")

        second = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        assert second != first


class TestWatchLifecycle:

    def _start(self, client, config_file) -> str:
        session_id = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        _wait_for_events(client, session_id, 1)
        return session_id

    def test_pause_stops_scanning_but_stays_live(self, client, config_file):
        """A paused session is idle on purpose, not dead: it must keep
        beating, or the console would show it as stopped."""
        session_id = self._start(client, config_file)
        assert client.post(f"/api/v1/watch/{session_id}/pause").json()[
            "runner_state"] == "paused"

        before = len(client.get(f"/api/v1/watch/{session_id}").json()["events"])
        with open(config_file, "a") as fh:
            fh.write("\nServerSignature On\n")
        time.sleep(STALE_AFTER)

        detail = client.get(f"/api/v1/watch/{session_id}").json()
        assert len(detail["events"]) == before      # the edit was NOT scanned
        assert detail["latest"]["live"] is True     # ...but it is still alive
        assert detail["latest"]["runner_state"] == "paused"

    def test_resume_picks_up_the_pending_change(self, client, config_file):
        session_id = self._start(client, config_file)
        client.post(f"/api/v1/watch/{session_id}/pause")
        before = len(client.get(f"/api/v1/watch/{session_id}").json()["events"])

        with open(config_file, "a") as fh:
            fh.write("\nServerSignature On\n")
        time.sleep(STALE_AFTER)

        assert client.post(f"/api/v1/watch/{session_id}/resume").json()[
            "runner_state"] == "running"
        assert _wait_for_events(client, session_id, before + 1) > before

    def test_stop_ends_the_loop_and_goes_stale(self, client, config_file):
        session_id = self._start(client, config_file)
        assert client.post(f"/api/v1/watch/{session_id}/stop").json()[
            "runner_state"] == "stopped"

        before = len(client.get(f"/api/v1/watch/{session_id}").json()["events"])
        with open(config_file, "a") as fh:
            fh.write("\nServerSignature On\n")

        # Poll for staleness instead of sleeping a fixed STALE_AFTER: the
        # heartbeat ages in wall-clock time, so a loaded machine can still be
        # inside the 2x-interval window when a fixed sleep expires. Waiting
        # for the condition keeps the fast path fast and the slow path honest.
        detail = _wait_until(
            lambda: client.get(f"/api/v1/watch/{session_id}").json(),
            lambda d: d["latest"]["live"] is False,
        )
        assert len(detail["events"]) == before      # stopped means stopped
        assert detail["latest"]["live"] is False    # no beats -> stale

    def test_stop_is_idempotent(self, client, config_file):
        session_id = self._start(client, config_file)
        assert client.post(f"/api/v1/watch/{session_id}/stop").status_code == 200
        assert client.post(f"/api/v1/watch/{session_id}/stop").status_code == 200


class TestWatchDeletion:
    """Limpar sessões antigas.

    Uma máquina de validação acumula sessões paradas depressa e a lista deixa
    de ser navegável — mas uma sessão viva apagada continuaria a escrever
    eventos para um histórico que já não existe, portanto essa é protegida.
    """

    def _start(self, client, config_file) -> str:
        session_id = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        _wait_for_events(client, session_id, 1)
        return session_id

    def test_delete_removes_a_stopped_session(self, client, config_file):
        session_id = self._start(client, config_file)
        client.post(f"/api/v1/watch/{session_id}/stop")

        resp = client.delete(f"/api/v1/watch/{session_id}")
        assert resp.status_code == 200
        assert resp.json()["events_removed"] >= 1
        # Some do histórico e da lista, não de uma só das duas tabelas.
        assert client.get(f"/api/v1/watch/{session_id}").status_code == 404
        assert session_id not in [s["watch_session"]
                                  for s in client.get("/api/v1/watch").json()]

    def test_delete_of_a_running_session_is_409(self, client, config_file):
        session_id = self._start(client, config_file)
        assert client.delete(f"/api/v1/watch/{session_id}").status_code == 409
        # E não apagou nada por engano.
        assert client.get(f"/api/v1/watch/{session_id}").status_code == 200

    def test_delete_of_unknown_session_is_404(self, client):
        assert client.delete("/api/v1/watch/unknown-session").status_code == 404

    def test_clear_keeps_the_running_session(self, client, config_file):
        stopped = self._start(client, config_file)
        client.post(f"/api/v1/watch/{stopped}/stop")
        running = self._start(client, config_file)

        body = client.delete("/api/v1/watch").json()
        assert body["kept_running"] == 1
        assert body["sessions_removed"] >= 1

        remaining = [s["watch_session"] for s in client.get("/api/v1/watch").json()]
        assert running in remaining
        assert stopped not in remaining


class TestWatchEventDetail:
    """Um evento tem de dar acesso às directivas que moveram o score.

    Sem a chave do scan, a sessão mostrava um número global e mais nada —
    não havia como saber que configuração o produziu.
    """

    def test_events_carry_the_scan_id(self, client, config_file):
        session_id = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        _wait_for_events(client, session_id, 1)

        detail = client.get(f"/api/v1/watch/{session_id}").json()
        scan_id = detail["events"][0]["scan_id"]
        assert scan_id

        # E a chave abre mesmo o scan completo, com os achados lá dentro.
        scan = client.get(f"/api/v1/scans/{scan_id}")
        assert scan.status_code == 200
        assert "issues" in scan.json()


class TestWatchControlErrors:
    """A session this process doesn't own can't be controlled — say so with a
    409 rather than reporting a pause that never happened."""

    @pytest.mark.parametrize("action", ["pause", "resume", "stop"])
    def test_control_of_unknown_session_is_409(self, client, action):
        resp = client.post(f"/api/v1/watch/unknown-session/{action}")
        assert resp.status_code == 409

    def test_detail_of_unknown_session_is_404(self, client):
        assert client.get("/api/v1/watch/unknown-session").status_code == 404

    def test_pause_after_stop_is_409(self, client, config_file):
        session_id = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        _wait_for_events(client, session_id, 1)
        client.post(f"/api/v1/watch/{session_id}/stop")

        assert client.post(f"/api/v1/watch/{session_id}/pause").status_code == 409


class TestSharedHelperParity:
    """The REST layer must not grow its own liveness logic: it and any other
    caller have to get the same answer out of core/watch_session.py. This
    guarded the Jinja2 dashboard before it was removed; it still guards the
    helper against the router quietly reimplementing it."""

    def test_helper_and_api_agree_on_liveness(self, client, config_file,
                                               db_path):
        session_id = client.post(
            "/api/v1/watch", json={"path": config_file, "interval": INTERVAL},
        ).json()["watch_session"]
        _wait_for_events(client, session_id, 1)

        api_live = client.get(
            f"/api/v1/watch/{session_id}").json()["latest"]["live"]
        with Database(db_path) as db:
            shared_live = session_context(session_id, db)["latest"]["live"]
        assert api_live == shared_live
