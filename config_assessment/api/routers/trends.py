"""
config_assessment/api/routers/trends.py
------------------------------------------
GET /api/v1/trends — cross-scan drift via the Aggregation Engine.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from config_assessment.api.deps import get_db
from config_assessment.core.db.database import Database
from config_assessment.core.engines.aggregation import aggregate_trend

router = APIRouter(prefix="/api/v1/trends", tags=["trends"])


def _serialize(series) -> dict:
    return {
        "input_path": series.input_path,
        "scores": series.scores,
        "timestamps": series.timestamps,
        "first": series.first,
        "last": series.last,
        "delta": series.delta,
        "verdict": series.verdict,
        "sparkline": series.sparkline,
    }


@router.get("")
def get_trends(
    input_path: str | None = None,
    limit: int = 200,
    db: Database = Depends(get_db),
) -> list[dict]:
    """How each configuration's score has moved over its scan history.

    One series per `input_path`, with `delta` (last minus first) and a
    `verdict` naming the direction. This is the temporal view the CVM
    methodology is built around: a single score says how bad things are, a
    trend says whether the work is paying off. Pass `input_path` for one file.
    """
    history = db.get_scan_history(limit=limit)
    return [_serialize(s) for s in aggregate_trend(history, input_filter=input_path)]
