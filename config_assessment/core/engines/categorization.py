"""
core/engines/categorization.py
--------------------------------
Category Engine (CVM Core) — deterministic, runtime classification of a
Misconfiguration into the thesis's 7-item category taxonomy. Pure heuristic
matching against fields already present on the Misconfiguration (directive
name, justification, recommendation, cis_section/cce_id) — no LLM, no
build-time authoring. A rule may match several categories; unmatched rules
fall back to SERVICE_CONFIG so every issue counts toward at least one
category in the Operating System level's rollup (see engines/aggregation.py
::aggregate_categories).

"Cadeias de ataque / risco composto" is the 7th category but is chain-level,
not rule-level — it has no entry here, see
engines/aggregation.py::aggregate_chain_category.
"""

from __future__ import annotations

from config_assessment.core.models import Misconfiguration

AUTH = "Autenticação"
AUTHZ = "Autorização"
EXPOSURE = "Exposição de serviços"
CRYPTO = "Configuração criptográfica"
SERVICE_CONFIG = "Configuração de serviços"
CIS_STIG = "Conformidade com CIS Benchmarks e DISA STIG"
ATTACK_CHAINS = "Cadeias de ataque / risco composto"

ALL_RULE_CATEGORIES = (AUTH, AUTHZ, EXPOSURE, CRYPTO, SERVICE_CONFIG, CIS_STIG)
ALL_CATEGORIES = ALL_RULE_CATEGORIES + (ATTACK_CHAINS,)

_AUTH_KEYWORDS = (
    "password", "auth", "login", "credential", "pam", "token", "mfa",
    "kerberos", "2fa", "passwd",
)
_AUTHZ_KEYWORDS = (
    "permission", "privilege", "sudo", "root", "chmod", "acl", "role",
    "grant", "owner", "umask",
)
_EXPOSURE_KEYWORDS = (
    "listen", "bind", "port", "expose", "public", "0.0.0.0", "firewall",
    "iptables", "interface", "network",
)
_CRYPTO_KEYWORDS = (
    "tls", "ssl", "cipher", "certificate", "encrypt", "hash", "protocol",
    "sha", "md5", "key exchange", "dh param",
)


def categorize(m: Misconfiguration) -> list[str]:
    """Classify one Misconfiguration into 1+ of the 6 rule-level categories.

    Deliberately avoids CCSS metric fields (av/au) as signals — they are the
    common-case defaults for most rules (e.g. av="N" is the default exposure
    for a "production" profile), so using them here would over-trigger a
    category on nearly every issue rather than being a meaningful signal.
    """
    haystack = " ".join([m.directive, m.justification, m.recommendation]).lower()

    cats: set[str] = set()
    if any(k in haystack for k in _AUTH_KEYWORDS):
        cats.add(AUTH)
    if any(k in haystack for k in _AUTHZ_KEYWORDS):
        cats.add(AUTHZ)
    if any(k in haystack for k in _EXPOSURE_KEYWORDS):
        cats.add(EXPOSURE)
    if any(k in haystack for k in _CRYPTO_KEYWORDS):
        cats.add(CRYPTO)
    if m.cis_section or m.cce_id:
        cats.add(CIS_STIG)
    if not cats:
        cats.add(SERVICE_CONFIG)
    return sorted(cats)
