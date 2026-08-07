"""
config_assessment/api/routers/builds.py
------------------------------------------
POST /api/v1/builds — kick off `caspar build` (LLM-driven knowledge-base
population) as a background job; GET /api/v1/builds lists past build jobs.
Wraps the exact same run_build_job() the CLI command calls — no build logic
duplicated here, just job bookkeeping (202 + job_id, poll via /api/v1/jobs).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from config_assessment.api import job_runner
from config_assessment.api.deps import require_api_key
from config_assessment.api.schemas_jobs import BuildRequest

router = APIRouter(prefix="/api/v1/builds", tags=["builds"])


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def create_build(body: BuildRequest, request: Request,
                  _auth: None = Depends(require_api_key)) -> dict:
    """Build a knowledge base from a security benchmark, as a background job.

    Returns 202 and a `job_id` immediately — a real build runs an LLM over
    every benchmark rule and can take hours. Poll GET /api/v1/jobs/{job_id}
    for status and .../logs to follow progress. Requires a reachable Ollama at
    `ollama_url`. Use `dry_run` to validate the inputs without writing rules.
    """
    from cli.commands.build_cmds import run_build_job

    def target_fn(db_path: str, emit) -> dict:
        count = run_build_job(
            benchmark=body.benchmark, model=body.model, ollama_url=body.ollama_url,
            target=body.target, dry_run=body.dry_run, db_path=db_path, emit=emit,
        )
        return {"misconfigurations": count}

    job_id = job_runner.start_job(
        request.app.state.db_path, kind="build", params=body.model_dump(),
        target_fn=target_fn,
    )
    return {"job_id": job_id}


@router.get("")
def list_builds(request: Request) -> list[dict]:
    """Build history — GET /api/v1/jobs?kind=build, kept here so the build
    surface is self-contained."""
    from config_assessment.core.db.database import Database
    with Database(request.app.state.db_path) as db:
        return db.list_jobs(kind="build")
