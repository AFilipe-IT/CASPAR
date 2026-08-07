"""
config_assessment/api/routers/hosts.py
------------------------------------------
GET /api/v1/hosts — cross-target rollup via the Aggregation Engine.
Aggregates every persisted scan's most recent result per input_path into one
executive summary (worst offender, totals, average score).

/registry* — the Operating System entity registry: hosts a user tagged via
`caspar scan --host <label>` (or the API's `ScanRequest.host`). Kept under a
distinct sub-path so the pre-existing, unrelated `GET /api/v1/hosts` above
keeps its exact current behavior.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, status

from config_assessment.api.deps import get_db, require_api_key
from config_assessment.api.schemas import HostCreate
from config_assessment.core.db.database import Database
from config_assessment.core.engines.aggregation import (
    aggregate_categories,
    aggregate_chain_category,
    aggregate_hosts,
)
from config_assessment.core.engines.categorization import ATTACK_CHAINS

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


@router.get("")
def get_hosts(limit: int = 200, db: Database = Depends(get_db)) -> dict:
    """Fleet-wide rollup across every assessed configuration.

    Each distinct `input_path` counts once, at its most recent scan, so a file
    scanned nightly does not outweigh one scanned once. `worst_score` is the
    figure to alert on; `average_score` describes the estate.
    """
    rows = db.list_scans(limit=limit)
    # One scan per input_path — the most recent (rows are newest-first).
    latest_by_input: dict[str, dict] = {}
    for row in rows:
        latest_by_input.setdefault(row["input_path"], row)

    scan_dicts = []
    for row in latest_by_input.values():
        result = db.get_scan_result(row["id"])
        if result is not None:
            scan_dicts.append(json.loads(result.model_dump_json()))

    rollup = aggregate_hosts(scan_dicts)
    return {
        "scans": rollup.scans,
        "total_issues": rollup.total_issues,
        "total_chains": rollup.total_chains,
        "worst_score": rollup.worst_score,
        "worst_target": rollup.worst_target,
        "average_score": rollup.average_score,
    }


def _latest_scans_for_host(db: Database, host_id: int) -> list:
    rows = db.get_scans_for_host(host_id, limit=500)
    latest_by_target: dict[str, dict] = {}
    for row in rows:
        latest_by_target.setdefault(row["target_name"], row)
    results = [db.get_scan_result(r["id"]) for r in latest_by_target.values()]
    return [r for r in results if r is not None]


@router.get("/registry")
def list_hosts_registry(db: Database = Depends(get_db)) -> list[dict]:
    """Every registered host label and id. A host is just a label scans are
    grouped under — CVM never connects to it."""
    return db.list_hosts()


@router.post("/registry", status_code=status.HTTP_201_CREATED)
def create_host(
    body: HostCreate,
    db: Database = Depends(get_db),
    _auth: None = Depends(require_api_key),
) -> dict:
    """Register a host label, or return the existing id if the label is
    already known — safe to call repeatedly from a provisioning script."""
    host_id = db.upsert_host(body.label)
    return {"id": host_id, "label": body.label}


@router.get("/registry/{host_id}")
def get_host_detail(host_id: int, db: Database = Depends(get_db)) -> dict:
    """One host's posture: its rollup plus a per-category breakdown, computed
    over the latest scan of each service on it (so two services are compared
    fairly even when scanned at different times)."""
    label = db.get_host_label(host_id)
    if label is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

    results = _latest_scans_for_host(db, host_id)
    scan_dicts = [json.loads(r.model_dump_json()) for r in results]
    rollup = aggregate_hosts(scan_dicts)

    all_issues = [i for r in results for i in r.issues]
    all_chains = [c for r in results for c in r.chains]
    categories = aggregate_categories(all_issues)
    categories[ATTACK_CHAINS] = aggregate_chain_category(all_chains)

    os_own = next((r for r in results if r.target_name == "ubuntu"), None)

    return {
        "id": host_id,
        "label": label,
        "rollup": {
            "scans": rollup.scans,
            "total_issues": rollup.total_issues,
            "total_chains": rollup.total_chains,
            "worst_score": rollup.worst_score,
            "worst_target": rollup.worst_target,
            "average_score": rollup.average_score,
        },
        "categories": {
            cat: {
                "score": c.score, "severity": c.severity, "issue_count": c.issue_count,
            }
            for cat, c in categories.items()
        },
        "os_own_scan": json.loads(os_own.model_dump_json()) if os_own else None,
    }
