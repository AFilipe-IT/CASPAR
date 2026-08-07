"""
core/engines/reporting.py
----------------------------
Reporting Engine (CVM Core).

Thin re-export of the report generators in config_assessment/reports/ —
those functions are already pure (ScanResult in, self-contained string out)
and unchanged; this module is the engine's named seam for the REST API and
Dashboard to import from, per the CVM Core architecture.
"""

from __future__ import annotations

from config_assessment.reports.report_dashboard import generate_dashboard
from config_assessment.reports.report_dashboard_online import generate_dashboard_online
from config_assessment.reports.report_html import generate_html
from config_assessment.reports.scan_features import (
    badge_markdown,
    badge_url,
    diff_scans,
    load_scan,
)

__all__ = [
    "generate_html",
    "generate_dashboard",
    "generate_dashboard_online",
    "diff_scans",
    "load_scan",
    "badge_url",
    "badge_markdown",
]
