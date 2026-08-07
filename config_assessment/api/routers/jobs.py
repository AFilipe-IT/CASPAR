"""
config_assessment/api/routers/jobs.py
----------------------------------------
GET /api/v1/jobs, /jobs/{id}, /jobs/{id}/logs — generic polling surface
shared by builds and plugin installs (and any future job kind). The
contract (status transitions, seq-ordered log tailing) is identical
regardless of what the job actually runs, so it lives here once rather
than being duplicated per-kind.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from config_assessment.api.deps import get_db
from config_assessment.api.schemas_jobs import JobLogLine, JobResponse
from config_assessment.core.db.database import Database

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"])


@router.get("", response_model=list[JobResponse])
def list_jobs(kind: str | None = None, limit: int = 50,
              db: Database = Depends(get_db)) -> list[dict]:
    """Background jobs, newest first. Filter by `kind` (build, plugin_add,
    plugin_manual, promote, refresh, fetch_exploits) to watch one pipeline.

    Jobs do not survive a server restart: one still marked `running` when the
    process died is reconciled to `failed` at startup rather than resumed.
    """
    return db.list_jobs(kind=kind, limit=limit)


@router.get("/{job_id}", response_model=JobResponse)
def get_job(job_id: str, db: Database = Depends(get_db)) -> dict:
    """One job's status. Poll this after any 202 response; the job is finished
    when `status` is succeeded, failed, or cancelled. On success `result_json`
    carries the outcome, on failure `error` carries the reason."""
    job = db.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job


@router.get("/{job_id}/logs", response_model=list[JobLogLine])
def get_job_logs(job_id: str, after: int = -1,
                  db: Database = Depends(get_db)) -> list[dict]:
    """A job's output, as the lines the CLI would have printed.

    Pass `after` with the highest `seq` already seen to fetch only new lines —
    a knowledge-base build can emit thousands over an hour, and re-sending the
    whole log on every poll would be wasteful. Lines are ordered by `seq`.
    """
    if db.get_job(job_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return db.get_job_logs(job_id, after=after)
