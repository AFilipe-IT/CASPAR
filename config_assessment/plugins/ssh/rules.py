"""
plugins/ssh/rules.py
---------------------
Deterministic rule engine for OpenSSH (sshd_config).

Implements SystemProfile inference required by Target.get_profile().
All rules are deterministic (no LLM). Worst-case principle applies.

AV (Access Vector) rules:
  - Default: Network — sshd with no ListenAddress binds all interfaces.
  - There may be multiple ListenAddress lines. Worst-case: if ANY is a
    non-loopback address → Network. Only Local when EVERY ListenAddress is
    loopback (127.0.0.1, ::1, localhost). A Port directive without a
    ListenAddress does not change AV — it is already Network by default.

Au (Authentication) rules:
  - Au = None for ALL SSH misconfigurations. See _infer_au for the rationale.
"""

from __future__ import annotations

from config_assessment.core.models import AuValue, AVValue, Directive, SystemProfile


_LOOPBACK = ("127.", "::1", "localhost", "[::1]", "0:0:0:0:0:0:0:1")


def _is_loopback(host: str) -> bool:
    h = host.strip().strip("[]").lower()
    return any(h == pfx or h.startswith(pfx) for pfx in _LOOPBACK)


def _listen_host(value: str) -> str:
    """
    Extract the host part of a sshd ListenAddress value.

    ListenAddress forms:
      ListenAddress 0.0.0.0            -> all IPv4 interfaces
      ListenAddress 127.0.0.1          -> loopback
      ListenAddress 127.0.0.1:2222     -> loopback with port
      ListenAddress ::1                -> IPv6 loopback
      ListenAddress [::1]:22           -> IPv6 loopback with port
      ListenAddress 192.168.1.10       -> specific (non-loopback) address
    """
    val = value.strip()
    first = val.split()[0] if val.split() else val

    if first.startswith("["):
        # [::1]:22  -> ::1
        return first.split("]")[0].lstrip("[")

    # IPv4 with optional :port. IPv6 literals contain multiple ':' and no
    # brackets here are unusual; only strip a trailing :port for IPv4.
    if first.count(":") == 1:
        return first.rsplit(":", 1)[0]

    return first


def _infer_av(directives: list[Directive]) -> tuple[AVValue, str]:
    listen_dirs = [d for d in directives if d.name == "ListenAddress"]

    if not listen_dirs:
        return "N", "No ListenAddress; sshd defaults to binding all interfaces (network)"

    values = [d.value.strip() for d in listen_dirs]
    all_loopback = all(_is_loopback(_listen_host(v)) for v in values)

    if all_loopback:
        return "L", f"All ListenAddress entries bound to loopback only: {values}"
    return "N", f"At least one ListenAddress exposes a non-loopback address: {values}"


def _infer_au(directives: list[Directive]) -> tuple[AuValue, str]:
    # SSH misconfigurations are either pre-authentication (Ciphers, MACs,
    # KexAlgorithms, MaxStartups, LoginGraceTime) or weaken authentication
    # itself (PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords).
    # In both cases, an attacker needs no valid credentials to exploit the
    # misconfiguration — Au=None is the correct model for all SSH misconfigs.
    return "N", (
        "Au=None for all SSH misconfigurations: they are exploited either "
        "pre-authentication or by weakening authentication itself — no valid "
        "credentials are required."
    )


def infer_profile(directives: list[Directive]) -> SystemProfile:
    """Build a SystemProfile from sshd_config directive analysis."""
    av, rationale_av = _infer_av(directives)
    au, rationale_au = _infer_au(directives)
    return SystemProfile(
        av=av,
        au=au,
        rationale_av=rationale_av,
        rationale_au=rationale_au,
    )
