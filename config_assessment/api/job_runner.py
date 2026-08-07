"""
config_assessment/api/job_runner.py
-------------------------------------
Background job execution for the REST API (build / plugin_add today,
extensible to other long-running CLI operations). Job state lives in the
same ccss.db as everything else — new `jobs`/`job_logs` tables — rather than
Redis/Celery, matching "simplest thing that works for a single-process app".

Execution model: one daemon threading.Thread per job, started synchronously
inside the POST handler (which returns 202 + job_id immediately), tracked in
a module-level registry for is_alive() checks. Jobs run one at a time behind
_RUN_LOCK: their target functions are existing CLI code that writes to
click.echo / sys.stdout, and capturing that output per-job means redirecting
process-global sys.stdout for the duration of the call — safe only if calls
never overlap.
"""

from __future__ import annotations

import logging
import sys
import threading
import uuid
from typing import Callable

from config_assessment.core.db.database import Database

logger = logging.getLogger(__name__)

# job_id -> Thread, so callers can check is_alive() (e.g. a future /cancel).
_REGISTRY: dict[str, threading.Thread] = {}

# Job target functions call into existing CLI code that writes to stdout
# (click.echo with no explicit file goes to sys.stdout). Only one job's
# output can be captured at a time since the redirect is process-global.
_RUN_LOCK = threading.Lock()


class _LineCallbackStream:
    """A stdout-shaped object that forwards completed lines to a callback.
    Used to capture click.echo(...) output from existing CLI code without
    modifying it, and to store logs incrementally (not just as one blob at
    the end) so a poller sees a build's progress as it happens."""

    def __init__(self, on_line: Callable[[str], None]) -> None:
        self._on_line = on_line
        self._buf = ""

    def write(self, s: str) -> int:
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._on_line(line)
        return len(s)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


def start_job(db_path: str, kind: str, params: dict,
              target_fn: Callable[[str, Callable[[str], None]], dict]) -> str:
    """Create a `queued` job row and start it in a background thread.
    target_fn(db_path, emit) -> result dict; may raise, which is recorded as
    a failure. Returns the new job_id immediately (the thread has not
    necessarily started running yet)."""
    job_id = str(uuid.uuid4())
    with Database(db_path) as db:
        db.create_job(job_id, kind, params)

    def _run() -> None:
        with Database(db_path) as db:
            db.mark_job_started(job_id)

        def emit(line: str) -> None:
            with Database(db_path) as db:
                db.append_job_log(job_id, line)

        old_stdout = sys.stdout
        try:
            with _RUN_LOCK:
                sys.stdout = _LineCallbackStream(emit)
                try:
                    result = target_fn(db_path, emit)
                finally:
                    sys.stdout = old_stdout
            with Database(db_path) as db:
                db.finish_job(job_id, "succeeded", result=result)
        except SystemExit as exc:
            # A job wraps CLI commands, and a CLI command signals failure with
            # sys.exit(N). That's BaseException, so without this branch it
            # would escape silently and leave the job stuck in `running`
            # forever with no error recorded.
            code = exc.code if exc.code is not None else 0
            if code == 0:
                with Database(db_path) as db:
                    db.finish_job(job_id, "succeeded", result={})
            else:
                message = f"command exited with status {code}"
                logger.warning("Job %s (%s): %s", job_id, kind, message)
                try:
                    emit(f"ERROR: {message}")
                except Exception:
                    pass
                with Database(db_path) as db:
                    db.finish_job(job_id, "failed", error=message)
        except Exception as exc:
            logger.exception("Job %s (%s) failed", job_id, kind)
            try:
                emit(f"ERROR: {exc}")
            except Exception:
                pass
            with Database(db_path) as db:
                db.finish_job(job_id, "failed", error=str(exc))

    thread = threading.Thread(target=_run, name=f"job-{job_id}", daemon=True)
    _REGISTRY[job_id] = thread
    thread.start()
    return job_id


def is_alive(job_id: str) -> bool:
    thread = _REGISTRY.get(job_id)
    return thread is not None and thread.is_alive()


def reconcile_on_startup(db_path: str) -> None:
    """Called from create_app(): any job left `queued`/`running` from a
    previous process (a real restart, not --reload survival — no thread
    ever resumes) is honestly marked failed rather than left stuck forever."""
    with Database(db_path) as db:
        stale = db.get_running_jobs()
        for job in stale:
            db.finish_job(job["id"], "failed",
                          error="interrupted by server restart")
        if stale:
            logger.info("Reconciled %d stale job(s) on startup", len(stale))
