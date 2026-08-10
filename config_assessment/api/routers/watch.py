"""
config_assessment/api/routers/watch.py
-----------------------------------------
POST   /api/v1/watch              — start a server-driven watch session (202)
GET    /api/v1/watch              — every persisted session, newest first
GET    /api/v1/watch/{id}         — one session: latest state, sparkline, events
POST   /api/v1/watch/{id}/pause   — stop scanning, keep the session alive
POST   /api/v1/watch/{id}/resume  — resume scanning
POST   /api/v1/watch/{id}/stop    — end the loop; it then goes stale on its own

Liveness is computed through core.watch_session rather than here, so a
session started by `caspar watch` on the CLI shows up in this list and reads
identically to one this server started.

Lifecycle control only applies to sessions this process started — a CLI
`caspar watch` run has no pause signal to receive, so pause/resume/stop on
one returns 409 rather than silently pretending to work.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from config_assessment.api import watch_runner
from config_assessment.api.deps import get_db, require_api_key
from config_assessment.api.schemas_watch import (WatchDetail, WatchSession,
                                                  WatchStartRequest,
                                                  WatchStartResponse)
from config_assessment.core.db.database import Database
from config_assessment.core.watch_session import is_live, session_context

router = APIRouter(prefix="/api/v1/watch", tags=["watch"])


@router.post("", status_code=status.HTTP_202_ACCEPTED,
             response_model=WatchStartResponse)
def start_watch(body: WatchStartRequest, request: Request,
                 _auth: None = Depends(require_api_key)) -> dict:
    """Start watching a configuration file, re-scanning it on every change.

    Returns 202 and a `watch_session` id immediately; the loop runs in this
    server process until stopped. Poll GET /api/v1/watch/{watch_session} for
    the score history. The session dies with the process — it is not resumed
    after a restart.
    """
    from config_assessment.core.input_resolver import resolve

    # Resolve up front so a bad path fails as a 400 here rather than as a
    # thread that dies silently a moment later. With live=True the path is a
    # service name resolved to its config dir, exactly as `scan --live` does.
    try:
        resolved = resolve(body.path, live=body.live)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail=str(exc)) from exc

    if body.live:
        label = resolved.metadata.get("service") or body.path
    else:
        label = resolved.path.rsplit("/", 1)[-1]

    version = body.service_version or resolved.metadata.get("version") or None
    if version == "unknown":
        version = None

    session_id = watch_runner.start_watch(
        request.app.state.db_path, path=resolved.path, label=label,
        interval=body.interval, version=version,
        env_profile=body.env_profile, host_label=body.host,
    )
    return {"watch_session": session_id, "path": resolved.path,
            "interval": body.interval}


def _decorate(row: dict) -> dict:
    row = dict(row)
    row["live"] = is_live(row)
    row["runner_state"] = watch_runner.runner_state(row["watch_session"])
    if row["runner_state"] == "failed":
        row["error"] = watch_runner.runner_error(row["watch_session"])
    return row


@router.get("", response_model=list[WatchSession])
def list_watch_sessions(limit: int = 50,
                         db: Database = Depends(get_db)) -> list[dict]:
    """Every known watch session, including ones started by `caspar watch` on
    the command line.

    Two fields describe state, and they are not the same thing: `live` is
    derived from the heartbeat and is true for any session still scanning,
    whoever started it. `runner_state` is set only for sessions this server
    process owns, and is null otherwise — those cannot be paused or stopped
    here. A paused session deliberately keeps beating, so `runner_state`
    takes precedence over `live` when both are present.
    """
    rows = [_decorate(r) for r in db.get_active_watches(limit=limit)]
    # Uma sessão que rebentou ao primeiro ciclo nunca escreveu resultado
    # nenhum, portanto não vem da base de dados. Sem a juntar aqui, a consola
    # aceitava o pedido e depois não mostrava nem a sessão nem o erro.
    known = {r["watch_session"] for r in rows}
    rows.extend(s for s in watch_runner.failed_sessions()
                if s["watch_session"] not in known)
    return rows


@router.get("/{watch_session}", response_model=WatchDetail)
def get_watch_session(watch_session: str,
                       db: Database = Depends(get_db)) -> dict:
    """One session's current state plus its event history — every re-scan
    since it started, so a score can be plotted against the edits that moved
    it."""
    ctx = session_context(watch_session, db)
    if ctx is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                             detail="Watch session not found")
    latest = dict(ctx["latest"])
    latest["watch_session"] = watch_session
    latest["runner_state"] = watch_runner.runner_state(watch_session)
    ctx["latest"] = latest
    return ctx


@router.delete("/{watch_session}")
def delete_session(watch_session: str, db: Database = Depends(get_db),
                    _auth: None = Depends(require_api_key)) -> dict:
    """Apagar uma sessão e o seu histórico.

    Recusa uma sessão ainda viva: apagar debaixo dos pés do loop deixaria a
    thread a escrever eventos de uma sessão que já não existe. Pára-a primeiro.
    """
    if watch_runner.runner_state(watch_session) in {"running", "paused"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Session is still running — stop it before deleting.")
    removed = db.delete_watch_session(watch_session)
    if removed == 0 and watch_runner.runner_state(watch_session) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                             detail="Watch session not found")
    return {"watch_session": watch_session, "events_removed": removed}


@router.delete("")
def clear_sessions(db: Database = Depends(get_db),
                    _auth: None = Depends(require_api_key)) -> dict:
    """Limpar todas as sessões paradas, preservando as que estão a correr.

    Uma máquina de validação acumula sessões antigas depressa, e a lista
    deixa de ser utilizável. As vivas ficam: são as únicas que ainda têm
    alguma coisa para dizer.
    """
    alive = watch_runner.live_session_ids()
    removed = db.delete_stale_watch_sessions(keep=alive)
    return {"sessions_removed": removed, "kept_running": len(alive)}


def _control(action, watch_session: str, verb: str) -> dict:
    if not action(watch_session):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"Cannot {verb}: no live watch session '{watch_session}' "
                    "in this server process. Sessions started by the CLI, or "
                    "before a server restart, cannot be controlled here."))
    return {"watch_session": watch_session,
            "runner_state": watch_runner.runner_state(watch_session)}


@router.post("/{watch_session}/pause")
def pause(watch_session: str, _auth: None = Depends(require_api_key)) -> dict:
    """Stop re-scanning without ending the session. It keeps its heartbeat, so
    it stays `live`; changes made while paused are picked up on resume. 409 if
    this process does not own the session."""
    return _control(watch_runner.pause_watch, watch_session, "pause")


@router.post("/{watch_session}/resume")
def resume(watch_session: str, _auth: None = Depends(require_api_key)) -> dict:
    """Resume a paused session, scanning immediately if the file changed while
    it was paused. 409 if this process does not own the session."""
    return _control(watch_runner.resume_watch, watch_session, "resume")


@router.post("/{watch_session}/stop")
def stop(watch_session: str, _auth: None = Depends(require_api_key)) -> dict:
    """End the session for good. It stops beating and goes stale on its own
    within two intervals; its history is kept. Idempotent. A stopped session
    cannot be resumed — start a new one. 409 if this process does not own
    it."""
    return _control(watch_runner.stop_watch, watch_session, "stop")
