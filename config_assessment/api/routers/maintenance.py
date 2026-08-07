"""
config_assessment/api/routers/maintenance.py
-----------------------------------------------
POST /api/v1/maintenance/refresh         — update GEL/GRL from NVD + CISA KEV
POST /api/v1/maintenance/fetch-exploits  — pre-fetch version exploitability

Both are network-bound over many CVEs, with the same duration profile as a
build, so they run through the job runner (202 + job_id, poll via
/api/v1/jobs) rather than blocking a request or inventing a second execution
pattern. Each wraps the existing CLI command through ctx.invoke — the job
runner captures its click.echo output as the job's log.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from config_assessment.api import job_runner
from config_assessment.api.deps import require_api_key
from config_assessment.api.schemas_maintenance import (FetchExploitsRequest,
                                                        RefreshRequest)

router = APIRouter(prefix="/api/v1/maintenance", tags=["maintenance"])


@router.post("/refresh", status_code=status.HTTP_202_ACCEPTED)
def start_refresh(body: RefreshRequest, request: Request,
                   _auth: None = Depends(require_api_key)) -> dict:
    """Re-score an existing knowledge base against current threat data.

    Re-reads NVD and CISA KEV for every CVE a rule references and updates its
    GEL/GRL temporal metrics, so a rule whose exploit became public scores
    higher without the benchmark changing. Returns 202 + a `job_id`; poll
    GET /api/v1/jobs/{job_id}. Use `dry_run` to see what would change.

    An `nvd_key` may be supplied per request to raise the NVD rate limit; it
    is used for the call and never persisted to the job record.
    """
    def target_fn(db_path: str, emit) -> dict:
        import click
        from cli.commands.build_cmds import refresh

        ctx = click.Context(refresh, obj={"db_path": db_path})
        ctx.invoke(refresh, target=body.target, nvd_key=body.nvd_key or "",
                   dry_run=body.dry_run)
        return {"target": body.target, "dry_run": body.dry_run}

    # params_json is persisted in the jobs table and served back by
    # GET /jobs — the NVD key must never land there.
    params = body.model_dump(exclude={"nvd_key"})
    params["nvd_key_supplied"] = bool(body.nvd_key)

    job_id = job_runner.start_job(request.app.state.db_path, kind="refresh",
                                   params=params, target_fn=target_fn)
    return {"job_id": job_id}


@router.post("/fetch-exploits", status_code=status.HTTP_202_ACCEPTED)
def start_fetch_exploits(body: FetchExploitsRequest, request: Request,
                          _auth: None = Depends(require_api_key)) -> dict:
    """Pre-fetch exploit availability for specific product versions.

    Populates the cache that lets a scan report version-specific exploits
    without a live lookup, so an air-gapped or rate-limited scan still knows.
    Returns 202 + a `job_id`; poll GET /api/v1/jobs/{job_id}.
    """
    def target_fn(db_path: str, emit) -> dict:
        import click
        from cli.commands.build_cmds import fetch_exploits

        ctx = click.Context(fetch_exploits, obj={"db_path": db_path})
        ctx.invoke(fetch_exploits, product=body.product,
                   versions=tuple(body.versions))
        return {"product": body.product, "versions": body.versions}

    job_id = job_runner.start_job(request.app.state.db_path,
                                   kind="fetch_exploits",
                                   params=body.model_dump(),
                                   target_fn=target_fn)
    return {"job_id": job_id}
