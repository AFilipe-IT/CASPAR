"""
config_assessment/api/routers/plugins.py
-------------------------------------------
GET /api/v1/plugins — installed plugins (registered_plugins(), same as
GET /targets) plus the catalog of services fetchable via `caspar plugin
fetch` (config_assessment/fetch/catalog.json) that aren't installed yet.
POST /api/v1/plugins/install runs `plugin add` (optionally preceded by a
fetch, mirroring `plugin fetch --then-install`) as a background job.
POST /api/v1/plugins/manual runs `plugin manual` — the retroactive
RAG-ingest path for an already-installed plugin — as a background job.
"""

from __future__ import annotations

import click
from fastapi import APIRouter, Depends, Request, status

from config_assessment.api import job_runner
from config_assessment.api.deps import require_api_key
from config_assessment.api.schemas_jobs import (PluginInstallRequest,
                                                 PluginManualRequest)
from config_assessment.core.engines import assessment

router = APIRouter(prefix="/api/v1/plugins", tags=["plugins"])


@router.get("")
def list_plugins() -> dict:
    """What can be assessed now, and what could be. `installed` is the plugins
    registered in this process; `available` is the benchmark catalog minus
    those, i.e. the services installable via POST /plugins/install."""
    from config_assessment.fetch.benchmark_fetcher import BenchmarkFetcher

    installed = [p.metadata().name for p in assessment.registered_plugins()]
    catalog = BenchmarkFetcher().list_available()
    available = [c for c in catalog if c["service"] not in installed]

    return {
        "installed": [
            {
                "name": p.metadata().name,
                "display_name": p.metadata().display_name,
                "version": p.metadata().version,
                "benchmark_source": p.metadata().benchmark_source,
            }
            for p in assessment.registered_plugins()
        ],
        "available": available,
    }


@router.post("/install", status_code=status.HTTP_202_ACCEPTED)
def install_plugin(body: PluginInstallRequest, request: Request,
                    _auth: None = Depends(require_api_key)) -> dict:
    """Install from either a server-side benchmark path (body.source is a
    path) or a catalog service name (body.source has no path separator and
    matches a fetchable service — fetched to a temp dir first, mirroring
    `plugin fetch <service> --then-install`)."""
    from pathlib import Path

    def target_fn(db_path: str, emit) -> dict:
        from cli.commands.plugin_cmds import plugin_add

        source = body.source
        if "/" not in source and not Path(source).exists():
            import tempfile
            from config_assessment.fetch.benchmark_fetcher import BenchmarkFetcher, FetchError
            try:
                source = BenchmarkFetcher().fetch(source, tempfile.mkdtemp(prefix="caspar-fetch-"))
            except FetchError as exc:
                raise RuntimeError(str(exc)) from exc

        ctx = click.Context(plugin_add, obj={"db_path": db_path})
        ctx.invoke(
            plugin_add, source=source, manual=body.manual, dry_run=body.dry_run,
            no_llm=body.no_llm, yes=True, verbose_list=False, model=body.model,
        )
        return {"source": source}

    job_id = job_runner.start_job(
        request.app.state.db_path, kind="plugin_add", params=body.model_dump(),
        target_fn=target_fn,
    )
    return {"job_id": job_id}


@router.post("/manual", status_code=status.HTTP_202_ACCEPTED)
def add_manual(body: PluginManualRequest, request: Request,
                _auth: None = Depends(require_api_key)) -> dict:
    """Add a service manual to an already-installed plugin's RAG knowledge.

    Job-backed rather than synchronous: the manual may be an http(s) URL, and
    ingestion chunks and embeds the whole document — the same duration profile
    as an install, not a request.
    """
    def target_fn(db_path: str, emit) -> dict:
        from cli.commands.plugin_cmds import plugin_manual

        ctx = click.Context(plugin_manual, obj={"db_path": db_path})
        ctx.invoke(plugin_manual, target=body.target, manual=body.manual)
        return {"target": body.target, "manual": body.manual}

    job_id = job_runner.start_job(
        request.app.state.db_path, kind="plugin_manual",
        params=body.model_dump(), target_fn=target_fn,
    )
    return {"job_id": job_id}
