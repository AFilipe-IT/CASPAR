"""
config_assessment/api/watch_runner.py
-------------------------------------
Server-driven watch sessions for the REST API.

A watch session is a *long-running loop*, not a one-shot job, so it does not
use the `jobs` table: its state is already fully expressed by the
existing watch_heartbeats/scan_results mechanism, and "stopped" is simply
"the loop stopped touching the heartbeat" — exactly how a CLI `caspar watch`
run reads today. Adding a parallel job row would give the same session two
sources of truth.

What *is* new here is lifecycle control. `caspar watch` is a blocking loop
killed only by Ctrl-C; a session started through the API carries a pause and
a stop `threading.Event`, so the console can pause, resume, and stop it. The
scan-and-persist work per tick is `core.watch_loop.run_watch_tick`, shared
verbatim with the CLI so the two paths cannot drift.

Like the job runner, sessions live in this process only: a server restart
ends them, after which they simply go stale on their own (no reconciliation
pass is needed — a heartbeat that stops being touched *is* the stopped state).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from uuid import uuid4

from config_assessment.core.db.database import Database
from config_assessment.core.watch_loop import included_files, run_watch_tick

logger = logging.getLogger(__name__)


@dataclass
class _Session:
    """A live watch loop owned by this process."""
    session_id: str
    path: str
    label: str
    interval: float
    thread: threading.Thread | None = None
    # `pause` is set while RUNNING (so wait() falls through) and cleared to
    # pause — an Event used as a gate, which is the standard shape and avoids
    # a busy-wait while paused.
    resumed: threading.Event = field(default_factory=threading.Event)
    stop: threading.Event = field(default_factory=threading.Event)
    error: str | None = None


_SESSIONS: dict[str, _Session] = {}
_LOCK = threading.Lock()


def existing_session_for(path: str) -> str | None:
    """A sessão viva que já vigia *path* neste processo, se houver.

    Carregar em "Start watching" duas vezes no mesmo serviço criava duas
    sessões a scanear o mesmo ficheiro, e a página passava a mostrar a mais
    recente — que começa com um único evento e sem histórico. Com várias
    dessas acumuladas, a vista saltava entre sessões que dizem coisas
    diferentes sobre a mesma configuração, e o score parecia não acompanhar
    as edições. Uma configuração só precisa de um observador.
    """
    with _LOCK:
        sessions = list(_SESSIONS.values())
    for s in sessions:
        if s.path == path and runner_state(s.session_id) in {"running", "paused"}:
            return s.session_id
    return None


def start_watch(db_path: str, *, path: str, label: str, interval: float,
                 version: str | None = None, env_profile: str | None = None,
                 host_label: str | None = None) -> str:
    """Start a watch loop in a daemon thread; return its session id.

    The heartbeat is touched before returning, so the session reads as live
    immediately rather than only after the first poll tick — matching what
    the CLI does at startup.
    """
    session_id = str(uuid4())

    with Database(db_path) as db:
        host_id = db.upsert_host(host_label) if host_label else None
        db.touch_watch_heartbeat(session_id)

    session = _Session(session_id=session_id, path=path, label=label,
                       interval=interval)
    session.resumed.set()   # starts running, not paused

    def _run() -> None:
        from config_assessment.core.watch import watch as watch_loop
        import time

        def _beat() -> None:
            if not session.stop.is_set():
                with Database(db_path) as db:
                    db.touch_watch_heartbeat(session_id)

        def _sleep_and_heartbeat(seconds: float) -> None:
            # Piggyback the heartbeat on the poll tick, as the CLI does: an
            # unchanged config yields no event, and without this the session
            # would read as stale within one interval while still running.
            time.sleep(seconds)
            _beat()
            # A paused session is alive and deliberately idle, not dead, so it
            # must KEEP beating while it waits — blocking here without beating
            # would make `live` flip false within 2x interval and the console
            # would show a paused session as stopped. Wait in interval-sized
            # slices, beating each time, until resumed or stopped.
            while not session.resumed.wait(timeout=seconds):
                if session.stop.is_set():
                    return
                _beat()

        try:
            for _event in watch_loop(path, interval=interval,
                                     stop=session.stop.is_set,
                                     sleep=_sleep_and_heartbeat,
                                     included_files=lambda: included_files(path)):
                if session.stop.is_set():
                    break
                session.resumed.wait()
                with Database(db_path) as db:
                    run_watch_tick(db, path, session_id=session_id,
                                   interval=interval, host_id=host_id,
                                   version=version, env_profile=env_profile)
        except Exception as exc:                      # noqa: BLE001
            logger.exception("Watch session %s failed", session_id)
            session.error = str(exc)

    thread = threading.Thread(target=_run, name=f"watch-{session_id}",
                              daemon=True)
    session.thread = thread
    with _LOCK:
        _SESSIONS[session_id] = session
    thread.start()
    return session_id


def pause_watch(session_id: str) -> bool:
    """Stop scanning without ending the session. False if not owned here."""
    session = _SESSIONS.get(session_id)
    if session is None or session.stop.is_set():
        return False
    session.resumed.clear()
    return True


def resume_watch(session_id: str) -> bool:
    session = _SESSIONS.get(session_id)
    if session is None or session.stop.is_set():
        return False
    session.resumed.set()
    return True


def stop_watch(session_id: str) -> bool:
    """End the loop. The heartbeat stops being touched, so the session goes
    stale on its own within 2x its interval — the same signal a killed CLI
    run produces."""
    session = _SESSIONS.get(session_id)
    if session is None:
        return False
    session.stop.set()
    session.resumed.set()   # release a paused loop so it can observe the stop
    return True


def runner_state(session_id: str) -> str | None:
    """'running' | 'paused' | 'stopped' | 'failed' for a session owned by this
    process, or None for one this process doesn't own (a CLI run, or a session
    from before a restart) — whose liveness is then heartbeat-derived only."""
    session = _SESSIONS.get(session_id)
    if session is None:
        return None
    # 'failed' antes de 'stopped': uma sessão que rebentou também tem a thread
    # morta, e reportá-la como parada faz uma avaria passar por uma paragem
    # normal. Era o que acontecia com um caminho sem plugin correspondente —
    # o POST devolvia 202, a sessão desaparecia, e o painel não dizia nada.
    if session.error is not None:
        return "failed"
    if session.stop.is_set() or (session.thread and not session.thread.is_alive()):
        return "stopped"
    return "running" if session.resumed.is_set() else "paused"


def runner_error(session_id: str) -> str | None:
    """A mensagem que derrubou a sessão, ou None se não houve nenhuma."""
    session = _SESSIONS.get(session_id)
    return session.error if session else None


def failed_sessions() -> list[dict]:
    """Sessões que rebentaram antes de escreverem qualquer resultado.

    A lista da consola é construída a partir da base de dados, e uma sessão
    que morreu ao primeiro ciclo nunca lá chegou a escrever nada — ficava
    invisível. O caso real: um caminho cujo nome nenhum plugin reconhece
    (`demo.conf`), em que o POST devolvia 202 e depois não havia sessão
    nenhuma para ver, nem erro que explicasse porquê.
    """
    with _LOCK:
        sessions = list(_SESSIONS.values())
    return [
        {"watch_session": s.session_id, "input_path": s.path,
         "target_name": s.label, "watch_interval": s.interval,
         "live": False, "runner_state": "failed", "error": s.error}
        for s in sessions if s.error is not None
    ]


def live_session_ids() -> set[str]:
    """Sessões que este processo ainda está a correr (a correr ou em pausa).

    A limpeza em lote da consola precisa de saber o que não pode apagar: uma
    sessão viva apagada continuaria a escrever eventos de um histórico que já
    não existe. Só este módulo sabe quais são — a base de dados vê batimentos,
    não threads.
    """
    with _LOCK:
        ids = list(_SESSIONS)
    return {sid for sid in ids if runner_state(sid) in {"running", "paused"}}


def clear_registry(timeout: float = 5.0) -> None:
    """Stop every session and wait for its thread, then forget them all.

    Signalling alone returns while the threads are still mid-tick. A tick that
    outlives its caller keeps scanning and writing to a database the caller
    believes it is done with — under test that surfaced as a session running
    on after its fixtures had torn the plugin registry down, failing an
    unrelated test; at shutdown it is a scan racing the interpreter.

    The join is bounded because these are daemon threads: a stuck one must not
    hang the process, and the sleep between ticks is interruptible, so a
    healthy thread returns well inside the timeout.
    """
    with _LOCK:
        sessions = list(_SESSIONS.values())
        for session in sessions:
            session.stop.set()
            session.resumed.set()   # release a paused thread so it sees stop
        _SESSIONS.clear()

    # Outside the lock: a thread finishing its tick may still need it.
    for session in sessions:
        if session.thread is not None:
            session.thread.join(timeout=timeout)
