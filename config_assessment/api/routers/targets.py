"""
config_assessment/api/routers/targets.py
--------------------------------------------
GET /api/v1/targets — the registered plugin/target registry.
"""

from __future__ import annotations

from fastapi import APIRouter

from config_assessment.core.engines import assessment

router = APIRouter(prefix="/api/v1/targets", tags=["targets"])


@router.get("")
def list_targets() -> list[dict]:
    """The services this server can assess, from the plugins currently
    registered. A file whose type matches none of these cannot be scanned —
    install a plugin first (POST /api/v1/plugins/install)."""
    return [
        {
            "name": p.metadata().name,
            "display_name": p.metadata().display_name,
            "version": p.metadata().version,
            "benchmark_source": p.metadata().benchmark_source,
            "priority": p.metadata().priority,
        }
        for p in assessment.registered_plugins()
    ]
