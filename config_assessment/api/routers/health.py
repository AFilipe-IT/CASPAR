"""
config_assessment/api/routers/health.py
-------------------------------------------
GET /api/v1/health — liveness: DB reachable, plugins registered.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from config_assessment.api.deps import get_db
from config_assessment.api.schemas import HealthResponse
from config_assessment.core.db.database import Database
from config_assessment.core.engines import assessment

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(db: Database = Depends(get_db)) -> HealthResponse:
    """Liveness probe. Always 200 when the server is up — read `db_reachable`
    and `plugins_registered` for whether it can actually do any work."""
    db_reachable = True
    try:
        db.get_target_names()
    except Exception:
        db_reachable = False
    return HealthResponse(
        status="ok",
        db_reachable=db_reachable,
        plugins_registered=len(assessment.registered_plugins()),
    )
