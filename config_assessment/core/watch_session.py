"""
config_assessment/core/watch_session.py
---------------------------------------
Shared watch-session semantics: liveness and the per-session view model.

Kept separate from the REST router that consumes it so that "is this session
live?" has exactly one definition. It was extracted when two web surfaces
needed it; only /api/v1/watch (behind the CVM Console) remains, but the split
is what keeps the rule from being quietly reimplemented inside a handler.

Liveness has no explicit stop signal by design: a session reads as "live" while
its heartbeat (touched every poll tick, whether or not the config changed) is
younger than twice its own --interval, and "stopped" once that window passes,
since the process driving it has plainly gone away. That holds equally for a
`caspar watch` CLI run and for a session driven by the REST runner.
"""

from __future__ import annotations

from datetime import datetime, timezone

from config_assessment.core.db.database import Database
from config_assessment.core.engines.aggregation import sparkline


def is_live(row: dict) -> bool:
    """A session is live if its heartbeat is within 2x its own interval.

    Falls back to the latest scan_results row's timestamp when no heartbeat
    is on record (a session persisted before watch_heartbeats existed) —
    stricter, since a quiet config then reads as stale sooner, but never
    crashes on old data."""
    interval = row.get("watch_interval") or 1.0
    raw_ts = row.get("last_seen") or row.get("timestamp")
    try:
        ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age < 2 * interval


def session_context(watch_session: str, db: Database) -> dict | None:
    """The full view model for one session, or None if it has no events.

    Callers decide how "not found" is reported (a 404 in both current
    callers), so this stays free of HTTP concerns.
    """
    events = db.get_watch_events(watch_session)
    if not events:
        return None
    latest = dict(events[0])
    latest["last_seen"] = db.get_watch_heartbeat(watch_session)
    latest["live"] = is_live(latest)
    scores = [e["global_temporal_score"] for e in reversed(events)]
    return {
        "watch_session": watch_session,
        "latest": latest,
        "events": events,
        "sparkline": sparkline(scores),
        "first_score": scores[0] if scores else 0.0,
        "last_score": scores[-1] if scores else 0.0,
    }
