"""
plugins/apache_httpd/rules.py
------------------------------
Deterministic rule engine for Apache HTTP Server 2.4.

Implements the SystemProfile inference logic required by Target.get_profile().
All rules are deterministic (no LLM, no external calls).
Worst-case principle applies throughout.

AV (Access Vector) rules:
  - Default: Network (Apache is a network service by definition)
  - Exception: if Listen is explicitly bound to 127.0.0.1 only → Local

Au (Authentication) rules:
  - Default: None (most Apache configs have unauthenticated endpoints)
  - Single: if AuthType is configured AND at least one Require directive
    exists that is not "all granted"
  - Multiple: not typically applicable to Apache (kept for completeness)
"""

from __future__ import annotations

from core.models import AuValue, AVValue, Directive, SystemProfile


# ------------------------------------------------------------------ #
# AV inference                                                         #
# ------------------------------------------------------------------ #

_LOOPBACK_PREFIXES = ("127.", "::1", "localhost")


def _infer_av(directives: list[Directive]) -> tuple[AVValue, str]:
    """
    Infer Access Vector from Listen directives.

    Returns (av_value, rationale_string).
    """
    listen_directives = [d for d in directives if d.name == "Listen"]

    if not listen_directives:
        # No Listen directive → Apache defaults to 0.0.0.0:80 → Network
        return "N", "No Listen directive found; Apache defaults to 0.0.0.0:80 (Network)"

    # Check if ALL listen addresses are loopback
    all_loopback = True
    listen_values = []
    for d in listen_directives:
        val = d.value.strip()
        listen_values.append(val)
        # Extract host part if host:port format
        if ":" in val and not val.startswith("["):
            host = val.rsplit(":", 1)[0]
        elif val.startswith("["):
            # IPv6 [::1]:port format
            host = val.split("]")[0].lstrip("[")
        else:
            # Port only (e.g. "Listen 80") → binds to all interfaces
            host = "0.0.0.0"

        if not any(host.startswith(pfx) or host == pfx for pfx in _LOOPBACK_PREFIXES):
            all_loopback = False

    if all_loopback:
        return "L", f"All Listen directives bound to loopback only: {listen_values}"
    return "N", f"At least one Listen directive exposes a non-loopback address: {listen_values}"


# ------------------------------------------------------------------ #
# Au inference                                                         #
# ------------------------------------------------------------------ #

def _infer_au(directives: list[Directive]) -> tuple[AuValue, str]:
    """
    Infer Authentication level from AuthType + Require directives.

    Returns (au_value, rationale_string).
    """
    auth_type_dirs = [
        d for d in directives
        if d.name in ("AuthType",) and d.value.lower() not in ("none", "")
    ]
    require_dirs = [d for d in directives if d.name == "Require"]

    # Filter out permissive requires
    permissive_requires = {"all granted", "all", "granted"}
    restrictive_requires = [
        d for d in require_dirs
        if d.value.lower().strip() not in permissive_requires
    ]

    if auth_type_dirs and restrictive_requires:
        return (
            "S",
            f"AuthType configured ({auth_type_dirs[0].value}) with {len(restrictive_requires)} "
            f"restrictive Require directive(s) — single authentication required",
        )

    return (
        "N",
        "No effective authentication configured (no AuthType + Require combination found)",
    )


# ------------------------------------------------------------------ #
# Public entry point                                                   #
# ------------------------------------------------------------------ #

def infer_profile(directives: list[Directive]) -> SystemProfile:
    """
    Build a SystemProfile from Apache directive analysis.

    Called by ApachePlugin.get_profile().
    """
    av, rationale_av = _infer_av(directives)
    au, rationale_au = _infer_au(directives)

    return SystemProfile(
        av=av,
        au=au,
        rationale_av=rationale_av,
        rationale_au=rationale_au,
    )
