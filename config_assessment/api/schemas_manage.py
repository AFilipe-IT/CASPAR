"""
config_assessment/api/schemas_manage.py
---------------------------------------
Request/response schemas for the management surface: suppressions, DB
integrity (doctor), remediation previews (fix), rule promotion, badges, and
read-only effective settings. Long-running maintenance work lives in
schemas_maintenance.py instead.

Two deliberate asymmetries with the CLI, both security-driven and documented
in the parity checklist rather than left implicit:

  * `fix` is preview-only here. The CLI can rewrite a config in place; the
    REST API never writes to files it did not create, because the API's auth
    is a no-op unless CASPAR_API_KEY is set.
  * suppression files must be named explicitly. The CLI defaults to
    .caspar-suppress.json relative to the process cwd, which for a server
    means "wherever it happened to be started" — too surprising to inherit.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ── suppress ──────────────────────────────────────────────────────────

class SuppressionItem(BaseModel):
    directive: str
    reason: str = ""
    bad_value: str = ""
    date: str = ""


class SuppressionCreate(BaseModel):
    directive: str
    # Required here (the CLI also refuses an empty --reason): accepting a
    # risk without a justification is exactly what this feature exists to
    # prevent.
    reason: str = Field(min_length=1)
    bad_value: str = ""
    suppress_file: str | None = None


# ── doctor ────────────────────────────────────────────────────────────

class DoctorFinding(BaseModel):
    severity: str
    category: str
    message: str


class DoctorReport(BaseModel):
    healthy: bool
    errors: int
    warnings: int
    findings: list[DoctorFinding]


# ── fix (preview only) ────────────────────────────────────────────────

class FixRequest(BaseModel):
    input_path: str
    live: bool = False


class FixEditOut(BaseModel):
    file: str
    line_number: int
    directive: str
    old_line: str
    new_line: str


class FixManualStep(BaseModel):
    directive: str
    good_value: str = ""
    reason: str = ""
    recommendation: str = ""
    score: float = 0.0


class FixPreview(BaseModel):
    """What `caspar fix --dry-run` shows, as data. `applied` is always false —
    see the module docstring."""
    target_name: str | None = None
    edits: list[FixEditOut]
    manual: list[FixManualStep]
    diff: str
    applied: bool = False


# ── promote ───────────────────────────────────────────────────────────

class PromoteRequest(BaseModel):
    input_path: str
    directive: str | None = None
    docs_path: str | None = None


class PromoteStatsRow(BaseModel):
    target: str
    rules: int
    promoted: int
    needs_review: int


# ── explain / badge ───────────────────────────────────────────────────

class BadgeResponse(BaseModel):
    url: str
    markdown: str


# ── settings (read-only) ──────────────────────────────────────────────

class Settings(BaseModel):
    """The server's *effective* configuration. Read-only by design: making
    these editable over HTTP is a separate, security-relevant decision."""
    caspar_version: str
    db_path: str
    plugins_dir: str | None = None
    data_dir: str | None = None
    api_key_required: bool = False
    registered_plugins: list[str] = []
