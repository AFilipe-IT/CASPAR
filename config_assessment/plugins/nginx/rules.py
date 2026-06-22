"""
plugins/nginx/rules.py
-----------------------
Deterministic rule engine for Nginx.

Implements SystemProfile inference required by Target.get_profile().
All rules are deterministic (no LLM). Worst-case principle applies.

AV (Access Vector) rules:
  - Default: Network (Nginx is a network service by definition)
  - Exception: if every `listen` is bound to 127.0.0.1 / ::1 / localhost → Local

Au (Authentication) rules:
  - Default: None (most Nginx configs serve unauthenticated content)
  - Single: if `auth_basic` is set to something other than "off", OR an
    `auth_request` directive is present — single authentication required
"""

from __future__ import annotations

from config_assessment.core.models import AuValue, AVValue, Directive, SystemProfile


_LOOPBACK_PREFIXES = ("127.", "::1", "localhost", "[::1]")


def _listen_host(value: str) -> str:
    """
    Extract the host part of an Nginx `listen` value.

    Nginx listen forms include:
      listen 80;                 -> all interfaces
      listen 127.0.0.1:8080;     -> loopback
      listen [::1]:80;           -> IPv6 loopback
      listen *:443 ssl;          -> all interfaces (extra flags after)
      listen unix:/var/run/x;    -> unix socket (treat as local)
    """
    val = value.strip()
    # Drop any flags after the address (ssl, default_server, http2, ...)
    first = val.split()[0] if val.split() else val

    if first.startswith("unix:"):
        return "127.0.0.1"  # unix socket -> not network-exposed -> treat as loopback

    if first.startswith("["):
        # IPv6 [::1]:port
        return first.split("]")[0].lstrip("[")

    if ":" in first:
        host = first.rsplit(":", 1)[0]
        # "*:443" -> host "*"
        return host

    # Port-only (e.g. "80") OR bare address. If it's purely a port number,
    # Nginx binds all interfaces.
    if first.isdigit():
        return "0.0.0.0"
    return first


def _infer_av(directives: list[Directive]) -> tuple[AVValue, str]:
    listen_dirs = [d for d in directives if d.name == "listen"]

    if not listen_dirs:
        return "N", "No listen directive found; Nginx server blocks default to network exposure"

    listen_values = []
    all_loopback = True
    for d in listen_dirs:
        listen_values.append(d.value.strip())
        host = _listen_host(d.value)
        if host in ("*", "0.0.0.0", "::"):
            all_loopback = False
        elif not any(host.startswith(pfx) or host == pfx for pfx in _LOOPBACK_PREFIXES):
            all_loopback = False

    if all_loopback:
        return "L", f"All listen directives bound to loopback only: {listen_values}"
    return "N", f"At least one listen directive exposes a non-loopback address: {listen_values}"


def _infer_au(directives: list[Directive]) -> tuple[AuValue, str]:
    auth_basic = [
        d for d in directives
        if d.name == "auth_basic" and d.value.strip().strip('"').strip("'").lower() not in ("off", "")
    ]
    auth_request = [
        d for d in directives
        if d.name == "auth_request" and d.value.strip().lower() not in ("off", "")
    ]

    if auth_basic:
        return (
            "S",
            f"auth_basic configured ({auth_basic[0].value}) — single authentication required",
        )
    if auth_request:
        return (
            "S",
            f"auth_request configured ({auth_request[0].value}) — single authentication required",
        )

    return (
        "N",
        "No effective authentication configured (no auth_basic or auth_request found)",
    )


def infer_profile(directives: list[Directive]) -> SystemProfile:
    """Build a SystemProfile from Nginx directive analysis."""
    av, rationale_av = _infer_av(directives)
    au, rationale_au = _infer_au(directives)
    return SystemProfile(
        av=av,
        au=au,
        rationale_av=rationale_av,
        rationale_au=rationale_au,
    )
