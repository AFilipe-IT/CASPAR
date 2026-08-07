"""
config_assessment/api/schemas_maintenance.py
--------------------------------------------
Request schemas for the maintenance surface: refreshing CVE/exploit data on an
existing knowledge base (`refresh`) and enriching it with exploit availability
(`fetch-exploits`).

Both are network-bound and slow, so both routes are job-backed: they return
202 + a job_id rather than holding the request open. That is why these live
here and not in schemas_manage.py — `manage` is the synchronous, read-mostly
operator surface, while these two are long-running maintenance work.
"""

from __future__ import annotations

from pydantic import BaseModel


class RefreshRequest(BaseModel):
    target: str = "apache-httpd"
    # Accepted per-request so a key never has to live in the server's env,
    # and never echoed back in the job's params.
    nvd_key: str = ""
    dry_run: bool = False


class FetchExploitsRequest(BaseModel):
    product: str | None = None
    versions: list[str] = []
