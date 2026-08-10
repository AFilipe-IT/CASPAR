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

import logging

from config_assessment.core import runtime
from config_assessment.core.db.database import Database
from config_assessment.core.engines import assessment
from config_assessment.core.models import ScanResult

logger = logging.getLogger(__name__)


def included_files(path: str) -> list[str]:
    """Every file a scan of *path* actually reads, beyond the entry point.

    A scan follows `Include` directives, so the file the user names is rarely
    the whole story: a stock `/etc/apache2/apache2.conf` pulls in ~36 others,
    and `ServerTokens` lives in one of them (`conf-available/security.conf`).
    Watching only the entry point meant a real fix could leave the score
    frozen — the edited file was never hashed.

    Derived from the parsed directives rather than re-implementing include
    resolution here: the parser already did that work, and any second copy of
    it would drift from what the scan really reads. Directives are taken
    pre-scoring, so a file whose directives are all clean still counts —
    otherwise fixing the last finding in a file would stop it being watched.
    """
    try:
        plugin = assessment.select_plugin(path)
        directives = plugin.parse_config(path)
    except Exception as exc:                           # noqa: BLE001
        # Unparseable (mid-edit) or unsupported: the caller falls back to the
        # entry point alone. Never fatal — a watch session outliving a
        # momentarily broken config is the whole point.
        logger.debug("Could not resolve includes for %s: %s", path, exc)
        return []
    return sorted({d.source_file for d in directives if d.source_file})


def run_watch_tick(db: Database, path: str, *, session_id: str,
                    interval: float, host_id: int | None = None,
                    version: str | None = None,
                    env_profile: str | None = None) -> ScanResult:
    """Scan *path* and persist the result as one event of *session_id*."""
    result = runtime.scan(path, db, version=version, env_profile=env_profile)
    db.save_scan_result(result, host_id=host_id, watch_session=session_id,
                        watch_interval=interval)
    return result
