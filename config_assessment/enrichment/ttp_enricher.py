"""
enrichment/ttp_enricher.py
--------------------------
CTI enrichment for misconfigurations that have NO associated CVE.

Rationale (Revisor 1, INForum): most misconfiguration-driven security
incidents have no CVE, because a misconfiguration is not a code defect — the
existing F1 mechanism (cve_enricher.py) is therefore structurally blind to
them and falls back to a flat GEL="L". This module adds a second, narrower
signal for that no-CVE case: whether the *technique* a misconfiguration
enables is a documented MITRE ATT&CK technique. It follows the same pattern
already used for NVD/KEV/Exploit-DB — a static, offline, auditable mapping,
not a live threat-intel feed subscription (MISP/OTX), which would introduce a
network dependency the runtime path is designed to avoid.

Coverage is intentionally small and hand-curated (not automatically derived):
each entry requires a human judgement call linking a directive+bad_value
pattern to a specific technique ID, mirroring how CPE_TEMPLATES in
cve_enricher.py is a curated, not exhaustive, table. Extending coverage is
future work, not a claim of completeness.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TTPRecord:
    technique_id: str      # e.g. "T1078"
    technique_name: str    # e.g. "Valid Accounts"
    tactic: str            # e.g. "Initial Access"
    rationale: str         # why this directive/value enables the technique


# Curated directive → ATT&CK technique mapping. Keys are (target_name,
# directive, bad_value_prefix); bad_value_prefix "" matches any value for
# that directive (used when the mere presence of the directive is the risk,
# regardless of its specific bad value).
_TTP_TABLE: dict[tuple[str, str, str], TTPRecord] = {
    ("ssh", "PermitRootLogin", "yes"): TTPRecord(
        technique_id="T1078.003", technique_name="Valid Accounts: Local Accounts",
        tactic="Initial Access / Privilege Escalation",
        rationale="Direct root authentication over SSH removes the "
                   "privilege-escalation step an attacker would otherwise need "
                   "after compromising a non-root account.",
    ),
    ("ssh", "PasswordAuthentication", "yes"): TTPRecord(
        technique_id="T1110", technique_name="Brute Force",
        tactic="Credential Access",
        rationale="Password authentication exposes the service to credential "
                   "brute-forcing; key-based auth removes this attack surface.",
    ),
    ("ssh", "PermitEmptyPasswords", "yes"): TTPRecord(
        technique_id="T1078", technique_name="Valid Accounts",
        tactic="Initial Access",
        rationale="Empty passwords allow authentication bypass without any "
                   "credential material.",
    ),
    ("apache-httpd", "ServerTokens", "Full"): TTPRecord(
        technique_id="T1592.002", technique_name="Gather Victim Host Information: Software",
        tactic="Reconnaissance",
        rationale="Verbose version banners let an attacker fingerprint the "
                   "exact software version to target known exploits.",
    ),
    ("apache-httpd", "Options", "Indexes"): TTPRecord(
        technique_id="T1083", technique_name="File and Directory Discovery",
        tactic="Discovery",
        rationale="Directory listing exposes the file/directory structure "
                   "without needing any other access.",
    ),
    ("mysql", "skip-grant-tables", ""): TTPRecord(
        technique_id="T1078", technique_name="Valid Accounts",
        tactic="Initial Access",
        rationale="Disabling the privilege system allows authentication "
                   "bypass entirely.",
    ),
    ("redis", "requirepass", ""): TTPRecord(
        technique_id="T1078", technique_name="Valid Accounts",
        tactic="Initial Access",
        rationale="An unset/blank requirepass allows unauthenticated access "
                   "to the datastore.",
    ),
}


def lookup_ttp(target_name: str, directive: str, bad_value: str) -> TTPRecord | None:
    """
    Look up a curated MITRE ATT&CK technique for a directive/value pair.

    Tries an exact (target, directive, bad_value) match first, then a
    (target, directive, "") wildcard match (directive-level, value-agnostic).
    Returns None when nothing is curated for this combination — callers must
    treat that as "no additional CTI signal", not as an error.
    """
    exact = _TTP_TABLE.get((target_name, directive, bad_value))
    if exact is not None:
        return exact
    return _TTP_TABLE.get((target_name, directive, ""))


def compute_gel_from_ttp(record: TTPRecord | None) -> tuple[str, str]:
    """
    Map a TTP lookup to a GEL value + human-readable note, for use as a
    fallback when a misconfiguration has no associated CVE.

    A documented ATT&CK technique is treated as GEL="M": weaker evidence than
    an actual CVE/KEV entry (GEL="H"), because a technique mapping shows the
    *category* of attack is well-documented, not that automated exploit code
    exists for this exact configuration — but stronger than the current
    blanket GEL="L" for "no CVE", because it is not merely a theoretical risk.
    Callers still fall back to GEL="L" when lookup_ttp returns None.
    """
    if record is None:
        return "L", "No CVE and no known ATT&CK technique — configuration risk without further CTI evidence."
    return "M", (
        f"No CVE, but maps to ATT&CK {record.technique_id} "
        f"({record.technique_name}, {record.tactic}): {record.rationale}"
    )
