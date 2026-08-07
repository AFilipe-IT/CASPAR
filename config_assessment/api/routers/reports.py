"""
config_assessment/api/routers/reports.py
--------------------------------------------
POST /api/v1/scans/{id}/report — export a persisted scan via the existing
report generators (unchanged, pure functions of a ScanResult).
POST /api/v1/scans/{id}/diff/{other_id} — diff two persisted scans.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Response, status

from config_assessment.api.deps import get_db
from config_assessment.api.schemas import ReportRequest
from config_assessment.core.db.database import Database
from config_assessment.core.engines.reporting import (
    diff_scans,
    generate_dashboard,
    generate_dashboard_online,
    generate_html,
)

router = APIRouter(prefix="/api/v1/scans", tags=["reports"])


def _get_or_404(db: Database, scan_id: str):
    result = db.get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return result


@router.post("/{scan_id}/report")
def export_report(
    scan_id: str, body: ReportRequest, db: Database = Depends(get_db),
) -> Response:
    """Render a stored scan as a shareable document.

    `html` is a self-contained report, `dashboard` an interactive one (set
    `online` for CDN-hosted charts instead of inline SVG), `sarif` is for code
    scanning ingestion, `json` the raw result. Reports are generated on
    demand, not stored — the scan is the persistent artifact.
    """
    result = _get_or_404(db, scan_id)

    if body.format == "json":
        return Response(content=result.model_dump_json(indent=2), media_type="application/json")
    if body.format == "sarif":
        from cli._output import _to_sarif
        return Response(content=json.dumps(_to_sarif(result), indent=2), media_type="application/json")
    if body.format == "dashboard":
        html = generate_dashboard_online(result) if body.online else generate_dashboard(result)
        return Response(content=html, media_type="text/html")
    html = generate_html(result)
    return Response(content=html, media_type="text/html")


@router.post("/{scan_id}/diff/{other_id}")
def diff(scan_id: str, other_id: str, db: Database = Depends(get_db)) -> dict:
    """What changed between two scans: findings resolved, findings introduced,
    and the score delta. `scan_id` is the older side, `other_id` the newer —
    swapping them inverts the sign of every change."""
    old = _get_or_404(db, scan_id)
    new = _get_or_404(db, other_id)
    result = diff_scans(json.loads(old.model_dump_json()), json.loads(new.model_dump_json()))
    return {
        "old_score": result.old_score,
        "new_score": result.new_score,
        "score_delta": result.score_delta,
        "resolved": result.resolved,
        "new_issues": result.new_issues,
        "unchanged": result.unchanged,
    }
