"""
cli/_publish.py — the single publishing mechanism, used by both
`caspar publish <file>` and `caspar scan --publish-to <url>`.

Deliberately the only place in this codebase that knows about the platform's
HTTP API, wire format, or CASPAR_API_KEY. `caspar scan` itself stays fully
platform-agnostic — it only ever produces a ScanResult artifact; this module
is what turns that artifact into an HTTP POST, so old scans, offline scans,
and third-party results can all be published the same way a live scan can.

`requests` is imported lazily so the core scan/CLI dependency footprint is
untouched for users who never publish (see the `publish` extra in
pyproject.toml).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from config_assessment.core.models import ScanResult

logger = logging.getLogger("ccss")


def publish_scan_result(result_or_path: "ScanResult | str | Path", url: str,
                         *, timeout: float = 10.0) -> bool:
    """POST a ScanResult (already in memory, or loaded from a JSON file on
    disk) to the platform. Best-effort — never raises; callers decide
    whether a publish failure should affect their own exit code.

    Returns True on a successful (2xx) publish, False otherwise.
    """
    try:
        import requests
    except ImportError:
        logger.warning(
            "Could not publish: 'requests' is not installed. "
            "Install with: pip install caspar[publish]"
        )
        return False

    try:
        if isinstance(result_or_path, (str, Path)):
            payload = json.loads(Path(result_or_path).read_text(encoding="utf-8"))
        else:
            payload = json.loads(result_or_path.model_dump_json())
    except Exception as exc:
        logger.warning("Could not read scan result to publish: %s", exc)
        return False

    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get("CASPAR_API_KEY")
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("Could not publish scan result to %s: %s", url, exc)
        return False

    return True
