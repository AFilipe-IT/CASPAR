"""
config_assessment/api/routers/scans.py
-----------------------------------------
POST/GET /api/v1/scans — runs and lists scans. Calls runtime.scan() and
db.save_scan_result(), the exact same functions `caspar scan` calls, so the
CLI and this endpoint always agree on scoring.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from config_assessment.api.deps import get_db, require_api_key
from config_assessment.api.schemas import ScanRequest, ScanResponse
from config_assessment.core.db.database import Database
from config_assessment.core.input_resolver import resolve
from config_assessment.core.models import AttackChain, ScanResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _run_scan(body: ScanRequest, db: Database) -> ScanResponse:
    """Shared by POST /scans and POST /scans/upload — resolve, scan, persist,
    then apply the same CI-flag semantics `caspar scan` applies (suppression,
    --assess-unknown, --threshold), surfaced as response data instead of an
    exit code."""
    from config_assessment.core import runtime

    try:
        resolved = resolve(body.input_path, live=body.live)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    try:
        detected_version = body.version or resolved.metadata.get("version") or None
        if detected_version == "unknown":
            detected_version = None
        image_hint = resolved.metadata.get("image")
        try:
            result = runtime.scan(
                resolved.path, db, version=detected_version,
                image=image_hint, env_profile=body.env_profile,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

        # Suppressions (--suppress-file): hide accepted-risk issues, same as
        # the CLI — only loads a file if given, or the default exists.
        suppressed_count = 0
        from config_assessment.reports.scan_features import SuppressionStore
        supp_path = body.suppress_file or SuppressionStore.DEFAULT_PATH
        if body.suppress_file or Path(supp_path).exists():
            store = SuppressionStore(supp_path)
            kept = []
            for issue in result.issues:
                i_dict = {"directive": issue.directive, "bad_value": issue.bad_value}
                if store.is_suppressed(i_dict):
                    suppressed_count += 1
                else:
                    kept.append(issue)
            if suppressed_count:
                result.issues = kept

        # --assess-unknown: LLM triage of UNCOVERED directives (opt-in,
        # non-deterministic; never touches the deterministic scores).
        if body.assess_unknown and result.unknown_directives:
            from cli._knowledge import _assess_unknown_directives
            _assess_unknown_directives(result, body.docs_path)

        try:
            host_id = db.upsert_host(body.host) if body.host else None
            db.save_scan_result(result, host_id=host_id)
        except Exception as exc:
            logger.warning("Could not save scan history: %s", exc)
    finally:
        if resolved.cleanup:
            resolved.cleanup()

    passed = not (body.threshold > 0.0 and result.global_temporal_score > body.threshold)
    return ScanResponse(
        **result.model_dump(),
        passed_threshold=passed,
        suppressed_count=suppressed_count,
    )


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    body: ScanRequest,
    db: Database = Depends(get_db),
    _auth: None = Depends(require_api_key),
) -> ScanResponse:
    """Assess a configuration file that already lives on the server, by path.

    This is the CI/automation entry point and the exact equivalent of
    `caspar scan <path>`. `threshold` does not affect the HTTP status — the
    verdict comes back as `passed_threshold` in the body, because a non-2xx
    would conflate "the scan failed to run" with "the score was too high".
    Use POST /scans/upload when the caller is a browser with no server path.
    """
    return _run_scan(body, db)


@router.post("/upload", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan_from_upload(
    file: UploadFile = File(...),
    env_profile: Literal["production", "internal", "dev"] | None = Form(default=None),
    host: str | None = Form(default=None),
    threshold: float = Form(default=0.0),
    db: Database = Depends(get_db),
    _auth: None = Depends(require_api_key),
) -> ScanResponse:
    """Browser upload path: no server-side path exists client-side, so stage
    the file to a temp dir then run it through the exact same _run_scan()
    used by POST /scans — no new assessment logic, pure I/O plumbing."""
    suffix = Path(file.filename or "config").name
    staging_dir = tempfile.mkdtemp(prefix="caspar-upload-")
    staged_path = Path(staging_dir) / suffix
    staged_path.write_bytes(file.file.read())

    try:
        body = ScanRequest(
            input_path=str(staged_path), env_profile=env_profile,
            host=host, threshold=threshold,
        )
        return _run_scan(body, db)
    finally:
        import shutil
        shutil.rmtree(staging_dir, ignore_errors=True)


@router.get("")
def list_scans(
    target: str | None = None,
    input_path: str | None = None,
    severity_min: float | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Database = Depends(get_db),
) -> list[dict]:
    """Scan history, newest first, as summary rows rather than full results.

    Filters compose: `target` and `input_path` narrow to one service or one
    file (the series a trend is computed over), `severity_min` keeps only
    scans at or above a temporal score. Use GET /scans/{scan_id} for the
    findings themselves.
    """
    return db.list_scans(
        target_name=target, input_path=input_path,
        severity_min=severity_min, limit=limit, offset=offset,
    )


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str, db: Database = Depends(get_db)) -> ScanResult:
    """One stored assessment in full: findings, attack chains, scores, and the
    system profile the scores were computed under."""
    result = db.get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return result


@router.get("/{scan_id}/chains", response_model=list[AttackChain])
def get_scan_chains(scan_id: str, db: Database = Depends(get_db)) -> list[AttackChain]:
    """Just the attack chains from a scan — the combinations of individually
    lower-severity findings that amplify each other. Already included in
    GET /scans/{scan_id}; served separately so a chains view need not fetch
    every finding."""
    result = db.get_scan_result(scan_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return result.chains


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    db: Database = Depends(get_db),
    _auth: None = Depends(require_api_key),
) -> None:
    """Permanently remove one stored scan. This breaks any trend series that
    included it; the knowledge base (rules, chains) is untouched."""
    if not db.delete_scan_result(scan_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
