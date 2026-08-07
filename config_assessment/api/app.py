"""
config_assessment/api/app.py
-------------------------------
App factory: create_app(db_path) -> FastAPI. Registers every router under
/api/v1. `caspar serve` mounts the CVM Console (frontend/dist) onto this same
app instance, so CVM Core, the REST API, and the console run out of one
process.
"""

from __future__ import annotations

from fastapi import FastAPI

from config_assessment.api.routers import (
    builds, health, hosts, jobs, knowledge, maintenance, manage, plugins,
    reports, scans, targets, trends, watch,
)


def create_app(db_path: str = "ccss.db") -> FastAPI:
    from cli._discovery import _discover_plugins
    _discover_plugins()

    app = FastAPI(
        title="CVM API",
        description=(
            "REST API of the **Configuration Vulnerability Meter (CVM)** — "
            "quantitative scoring of security misconfigurations using CCSS "
            "(NISTIR 7502).\n\n"
            "Every endpoint runs the same engines as the `caspar` "
            "command-line tool, so a result obtained here is identical to the "
            "one the CLI would produce for the same input.\n\n"
            "**Long-running operations** (knowledge-base builds, plugin "
            "installs, exploit enrichment) return `202 Accepted` with a "
            "`job_id` instead of blocking; poll `GET /api/v1/jobs/{job_id}` "
            "for status and `GET /api/v1/jobs/{job_id}/logs?after=` to tail "
            "output.\n\n"
            "**Authentication** is off by default. Setting the "
            "`CASPAR_API_KEY` environment variable makes every write endpoint "
            "require a matching `X-API-Key` header.\n\n"
            "This API is **additive-only**: fields and endpoints may be "
            "added within `/api/v1`, but existing response shapes will not "
            "change meaning."
        ),
        version="1.0",
    )
    app.state.db_path = db_path

    app.include_router(scans.router)
    app.include_router(trends.router)
    app.include_router(hosts.router)
    app.include_router(targets.router)
    app.include_router(knowledge.router)
    app.include_router(reports.router)
    app.include_router(health.router)
    app.include_router(jobs.router)
    app.include_router(builds.router)
    app.include_router(plugins.router)
    app.include_router(watch.router)
    app.include_router(manage.router)
    app.include_router(maintenance.router)

    from config_assessment.api.job_runner import reconcile_on_startup
    reconcile_on_startup(db_path)

    return app
