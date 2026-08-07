"""
config_assessment/api/schemas_watch.py
--------------------------------------
Request/response schemas for the watch surface (/api/v1/watch).

Kept apart from schemas_jobs.py because a watch session is not a job: it has
no terminal result, its state is derived from heartbeat freshness rather than
a status column, and it carries lifecycle controls (pause/resume) that jobs
do not have.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class WatchStartRequest(BaseModel):
    """Mirrors `caspar watch`'s options."""
    path: str
    live: bool = False
    interval: float = Field(default=1.0, gt=0)
    service_version: str | None = None
    env_profile: Literal["production", "internal", "dev"] | None = None
    host: str | None = None


class WatchSession(BaseModel):
    """One session's summary, as shown in the sessions list."""
    watch_session: str
    target_name: str | None = None
    input_path: str | None = None
    host_id: int | None = None
    global_temporal_score: float = 0.0
    severity: str | None = None
    total_issues: int = 0
    total_chains: int = 0
    watch_interval: float | None = None
    timestamp: str | None = None
    last_seen: str | None = None
    live: bool = False
    # 'running' | 'paused' | 'stopped' when this process owns the loop;
    # None for a CLI-started session, whose state is heartbeat-derived only.
    runner_state: str | None = None


class WatchEvent(BaseModel):
    timestamp: str | None = None
    target_name: str | None = None
    input_path: str | None = None
    global_temporal_score: float = 0.0
    severity: str | None = None
    total_issues: int = 0
    total_chains: int = 0
    watch_interval: float | None = None


class WatchDetail(BaseModel):
    watch_session: str
    latest: WatchSession
    events: list[WatchEvent]
    sparkline: str
    first_score: float
    last_score: float


class WatchStartResponse(BaseModel):
    watch_session: str
    path: str
    interval: float
