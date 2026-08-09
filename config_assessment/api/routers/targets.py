"""
config_assessment/api/routers/targets.py
--------------------------------------------
GET /api/v1/targets — the registered plugin/target registry.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

from config_assessment.core.engines import assessment
from config_assessment.core.input_resolver import _LIVE_SERVICE_MAP

router = APIRouter(prefix="/api/v1/targets", tags=["targets"])


@router.get("")
def list_targets() -> list[dict]:
    """The services this server can assess, from the plugins currently
    registered. A file whose type matches none of these cannot be scanned —
    install a plugin first (POST /api/v1/plugins/install)."""
    return [
        {
            "name": p.metadata().name,
            "display_name": p.metadata().display_name,
            "version": p.metadata().version,
            "benchmark_source": p.metadata().benchmark_source,
            "priority": p.metadata().priority,
        }
        for p in assessment.registered_plugins()
    ]


@router.get("/live")
def list_live_services() -> list[dict]:
    """Services that can be scanned with `live=true`, and whether each one is
    actually present on the machine running this server.

    Exists so the console can offer a list instead of a free-text field: the
    service name has to come from `_LIVE_SERVICE_MAP` (anything else is a hard
    error from the resolver), and typing it blind is how users hit
    "Service 'x' not found".

    `detected` is a directory check, deliberately not a `systemctl` call — it
    answers "is this service's configuration here", which is exactly what the
    resolver goes on to read. A stopped service still scans (see the guide's
    §1.3), so reporting it as absent would be wrong.

    Two consequences worth knowing when reading the result. In Docker the
    server sees the container's filesystem, not the host's, so everything
    reports `detected: false` unless the host's /etc is bind-mounted. And a
    service with no registered plugin is returned with `plugin_installed:
    false` rather than hidden — the config may well be there, and the fix is
    to install the plugin, which the console can then say.
    """
    installed = {p.metadata().name for p in assessment.registered_plugins()}

    # The map is alias-keyed (apache2/apache/httpd all reach apache-httpd).
    # Collapse to one entry per plugin so the console shows a service list,
    # not a synonym list, keeping the first alias as the canonical name —
    # dict order is insertion order, and the map lists the usual name first.
    seen: dict[str, dict] = {}
    for alias, (plugin_id, config_dir) in _LIVE_SERVICE_MAP.items():
        entry = seen.get(plugin_id)
        if entry is None:
            seen[plugin_id] = {
                "service": alias,
                "plugin": plugin_id,
                "config_dir": config_dir,
                "aliases": [],
                "detected": Path(config_dir).is_dir(),
                "plugin_installed": plugin_id in installed,
            }
            continue
        entry["aliases"].append(alias)
        # An alias may map to a different directory (httpd → /etc/httpd/conf/).
        # If that one exists, it is the live one: adopt it, so RHEL-style
        # layouts are detected instead of being reported absent.
        if not entry["detected"] and Path(config_dir).is_dir():
            entry["detected"] = True
            entry["service"] = alias
            entry["config_dir"] = config_dir

    return sorted(seen.values(), key=lambda e: (not e["detected"], e["service"]))
