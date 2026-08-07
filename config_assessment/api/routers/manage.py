"""
config_assessment/api/routers/manage.py
------------------------------------------
GET    /api/v1/settings                — effective server config (read-only)
GET    /api/v1/doctor                  — DB integrity check
GET    /api/v1/suppressions            — list accepted risks
POST   /api/v1/suppressions            — accept a risk
DELETE /api/v1/suppressions/{directive}
POST   /api/v1/fix/preview             — remediation diff (never writes)
POST   /api/v1/promote                 — promote candidates (background job)
GET    /api/v1/promote/stats           — learning-loop scoreboard
GET    /api/v1/scans/{id}/badge        — shields.io badge for a scan

`explain` deliberately has no endpoint here: GET /knowledge/targets/{target}/
rules/{rule_id} already returns the same Misconfiguration the CLI renders, so
adding one would duplicate an existing contract.

Two commands are intentionally narrower than their CLI counterparts, for
reasons recorded in schemas_manage.py: `fix` cannot apply edits (preview
only), and suppression files must be named explicitly instead of defaulting
to a cwd-relative path.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status

from config_assessment.api import job_runner
from config_assessment.api.deps import get_db, require_api_key
from config_assessment.api.schemas_manage import (BadgeResponse, DoctorReport,
                                                   FixPreview, FixRequest,
                                                   PromoteRequest,
                                                   PromoteStatsRow, Settings,
                                                   SuppressionCreate,
                                                   SuppressionItem)
from config_assessment.core.db.database import Database
# The learning loop's attribution marker, imported from the module that
# stamps it — a local copy would drift and silently skew the scoreboard.
from config_assessment.core.unknown_directives import PROMOTED_MARK

router = APIRouter(prefix="/api/v1", tags=["manage"])


# ── settings ──────────────────────────────────────────────────────────

@router.get("/settings", response_model=Settings)
def get_settings(request: Request) -> dict:
    """The server's effective configuration, read-only.

    Editing server-side paths over HTTP is deliberately not offered. The API
    key is never echoed back — `api_key_required` reports only whether one is
    being enforced.
    """
    from config_assessment.core.engines import assessment
    from config_assessment.core.manifest import CASPAR_VERSION

    return {
        "caspar_version": CASPAR_VERSION,
        "db_path": request.app.state.db_path,
        "plugins_dir": os.environ.get("CASPAR_PLUGINS_DIR"),
        "data_dir": os.environ.get("CASPAR_DATA_DIR"),
        # Never echo the key itself — only whether one is enforced.
        "api_key_required": bool(os.environ.get("CASPAR_API_KEY")),
        "registered_plugins": sorted(p.metadata().name
                                      for p in assessment.registered_plugins()),
    }


# ── doctor ────────────────────────────────────────────────────────────

@router.get("/doctor", response_model=DoctorReport)
def run_doctor(request: Request, strict: bool = False) -> dict:
    """Read-only integrity check. The CLI exits 1 on errors; an HTTP status
    can't carry that without conflating 'the check ran' with 'the DB is
    clean', so the counts are returned as data instead."""
    from config_assessment.core.db.doctor import check

    findings = check(request.app.state.db_path, strict=strict)
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    return {
        "healthy": not findings,
        "errors": len(errors),
        "warnings": len(warnings),
        "findings": [{"severity": f.severity, "category": f.category,
                      "message": f.message} for f in findings],
    }


# ── suppressions ──────────────────────────────────────────────────────

def _store(suppress_file: str | None):
    """A SuppressionStore for an explicitly-named file.

    The CLI's cwd-relative default (.caspar-suppress.json) is not inherited:
    for a long-running server that resolves to wherever it was launched,
    which is not something a browser user can reason about.
    """
    from config_assessment.reports.scan_features import SuppressionStore

    if not suppress_file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="suppress_file is required — the API does not fall back to "
                   "a path relative to the server's working directory.")
    return SuppressionStore(suppress_file)


@router.get("/suppressions", response_model=list[SuppressionItem])
def list_suppressions(suppress_file: str | None = None) -> list[dict]:
    """The accepted risks in a suppression file: findings excluded from
    threshold decisions, each with the reason it was accepted."""
    store = _store(suppress_file)
    return [{"directive": s.directive, "reason": s.reason,
             "bad_value": s.bad_value, "date": s.date} for s in store.items]


@router.post("/suppressions", response_model=SuppressionItem,
             status_code=status.HTTP_201_CREATED)
def create_suppression(body: SuppressionCreate,
                        _auth: None = Depends(require_api_key)) -> dict:
    """Accept a risk: exclude a directive from threshold decisions, on the
    record. `reason` is required and stored — a suppression without a stated
    justification is indistinguishable from an oversight later."""
    from datetime import date as _date

    store = _store(body.suppress_file)
    today = str(_date.today())
    store.add(body.directive, body.reason, body.bad_value, date=today)
    store.save()
    return {"directive": body.directive, "reason": body.reason,
            "bad_value": body.bad_value, "date": today}


@router.delete("/suppressions/{directive}")
def delete_suppression(directive: str, suppress_file: str | None = None,
                        _auth: None = Depends(require_api_key)) -> dict:
    """Withdraw an accepted risk, so the directive counts against thresholds
    again. Returns how many entries were removed (0 if it was not
    suppressed)."""
    store = _store(suppress_file)
    before = len(store.items)
    store.items = [s for s in store.items
                   if s.directive.lower() != directive.lower()]
    store.save()
    return {"removed": before - len(store.items)}


# ── fix (preview only) ────────────────────────────────────────────────

@router.post("/fix/preview", response_model=FixPreview)
def fix_preview(body: FixRequest, request: Request,
                 _auth: None = Depends(require_api_key)) -> dict:
    """The remediation diff, without writing anything.

    Applying fixes stays CLI-only: `caspar fix --in-place` overwrites a real
    config file with no backup, and this API's auth is a no-op unless
    CASPAR_API_KEY is set. Exposing that over HTTP is a separate decision,
    not an implementation detail of parity.
    """
    from config_assessment.core import runtime
    from config_assessment.core.input_resolver import resolve
    from config_assessment.reports.remediation import build_fix_plan, render_diff

    try:
        resolved = resolve(body.input_path, live=body.live)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail=str(exc)) from exc

    with Database(request.app.state.db_path) as db:
        result = runtime.scan(resolved.path, db)
    plan = build_fix_plan(result)

    return {
        "target_name": result.target_name,
        "edits": [{"file": e.file, "line_number": e.line_number,
                   "directive": e.directive, "old_line": e.old_line,
                   "new_line": e.new_line} for e in plan.edits],
        "manual": [{"directive": m.get("directive", ""),
                    "good_value": m.get("good_value") or "",
                    "reason": m.get("reason") or "",
                    "recommendation": m.get("recommendation") or "",
                    "score": m.get("score", 0.0)} for m in plan.manual],
        "diff": render_diff(plan) if plan.edits else "",
        "applied": False,
    }


# ── promote ───────────────────────────────────────────────────────────

@router.post("/promote", status_code=status.HTTP_202_ACCEPTED)
def start_promote(body: PromoteRequest, request: Request,
                   _auth: None = Depends(require_api_key)) -> dict:
    """Promotion runs the LLM over every uncovered directive, so it goes
    through the job runner rather than blocking the request."""
    from config_assessment.core.input_resolver import resolve

    try:
        resolve(body.input_path, live=False)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail=str(exc)) from exc

    def target_fn(db_path: str, emit) -> dict:
        import click
        from cli.commands.manage_cmds import promote

        # ctx.invoke with yes=True mirrors what plugin_fetch --then-install
        # already does: a non-interactive caller must not block on confirm.
        ctx = click.Context(promote, obj={"db_path": db_path})
        ctx.invoke(promote, input_path=body.input_path,
                   only_directive=body.directive, docs_path=body.docs_path,
                   show_stats=False, yes=True)
        return {"input_path": body.input_path}

    job_id = job_runner.start_job(request.app.state.db_path, kind="promote",
                                   params=body.model_dump(),
                                   target_fn=target_fn)
    return {"job_id": job_id}


@router.get("/promote/stats", response_model=list[PromoteStatsRow])
def promote_stats(db: Database = Depends(get_db)) -> list[dict]:
    """Same scoreboard as `caspar promote --stats`, as data."""
    rows = []
    for target in db.get_target_names():
        rules = db.get_all_misconfigurations(target)
        if not rules:
            continue
        promoted = [m for m in rules
                    if PROMOTED_MARK in (m.justification or "")]
        rows.append({
            "target": target,
            "rules": len(rules),
            "promoted": len(promoted),
            "needs_review": sum(1 for m in promoted if not m.good_value),
        })
    return rows


# ── badge ─────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/badge", response_model=BadgeResponse)
def scan_badge(scan_id: str, label: str = "CVM",
                db: Database = Depends(get_db)) -> dict:
    """The CLI's `badge` reads a scan JSON off disk; over REST a scan is
    already addressable by id, so this takes the id instead of a file."""
    from config_assessment.reports.scan_features import badge_markdown, badge_url

    result = db.get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                             detail="Scan not found")
    score = result.global_temporal_score
    return {"url": badge_url(score, label),
            "markdown": badge_markdown(score, label)}
