"""
config_assessment/core/watch_loop.py
------------------------------------
The work one watch tick does: re-scan the config and persist the result under
the session id.

`core/watch.py` decides *when* a re-scan is due (change detection); this module
is *what happens* when one is. It exists so the CLI's `caspar watch` and the
API's server-driven watch runner share one implementation rather than two
copies of the same three lines drifting apart — a divergence would show up as
the two UIs disagreeing about a session's history.
"""

from __future__ import annotations

from config_assessment.core import runtime
from config_assessment.core.db.database import Database
from config_assessment.core.models import ScanResult


def run_watch_tick(db: Database, path: str, *, session_id: str,
                    interval: float, host_id: int | None = None,
                    version: str | None = None,
                    env_profile: str | None = None) -> ScanResult:
    """Scan *path* and persist the result as one event of *session_id*."""
    result = runtime.scan(path, db, version=version, env_profile=env_profile)
    db.save_scan_result(result, host_id=host_id, watch_session=session_id,
                        watch_interval=interval)
    return result
