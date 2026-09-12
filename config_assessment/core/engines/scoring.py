"""
core/engines/scoring.py
------------------------
Scoring Engine (CVM Core) — CCSS scoring.

All formulas and numeric weights are taken directly from NISTIR 7502
(Scarfone & Mell, Dec 2010), Section 3.2.

This module is the SINGLE source of truth for scoring mathematics.
No plugin, no report generator, no test should re-implement these.

Numeric weights
---------------
Derived from the CVSS v2 lineage, as specified in CCSS:

  AV  : Local=0.395, Adjacent=0.646, Network=1.000
  Au  : Multiple=0.450, Single=0.560, None=0.704
  AC  : High=0.350, Medium=0.610, Low=0.710
  C/I/A: None=0.000, Partial=0.275, Complete=0.660
  GEL : None=0.600, Low=0.800, Medium=1.000, High=1.200, ND=1.000
  GRL : None=1.000, Low=0.800, Medium=0.600, High=0.400, ND=1.000

GRL vocabulary note
-------------------
NISTIR 7502 defines GeneralRemediationLevel as the degree to which a
remediation has *already been applied* across the population of affected
systems -- an environment-level fact.  CASPAR records a different fact in
its ``grl`` column: whether a remediation is *available* at all
(H = official fix documented, W = workaround only, U = no viable remedy).
A file-level assessment cannot observe deployed mitigations, so the
conservative and honest reading is that no general remediation has been
applied: every stored label maps to the norm's ``None`` (coefficient
1.000).  The column is retained as report metadata -- it tells the reader
whether a fix exists -- but it no longer modulates the score.
"""

from __future__ import annotations

from config_assessment.core.models import (
    ACValue,
    AuValue,
    AVValue,
    CIAValue,
    GELValue,
    GRLValue,
    SeverityLabel,
)

# ------------------------------------------------------------------ #
# Numeric weights (NISTIR 7502 §3.2)                                   #
# ------------------------------------------------------------------ #

_AV: dict[AVValue, float] = {
    "L": 0.395,   # Local
    "A": 0.646,   # Adjacent Network
    "N": 1.000,   # Network
}

_AU: dict[AuValue, float] = {
    "M": 0.450,   # Multiple
    "S": 0.560,   # Single
    "N": 0.704,   # None
}

_AC: dict[ACValue, float] = {
    "H": 0.350,   # High complexity
    "M": 0.610,   # Medium complexity
    "L": 0.710,   # Low complexity
}

_CIA: dict[CIAValue, float] = {
    "N": 0.000,   # None
    "P": 0.275,   # Partial
    "C": 0.660,   # Complete
}

_GEL: dict[GELValue, float] = {
    "N":  0.600,  # None    — exploitation not observed
    "L":  0.800,  # Low     — rarely exploited
    "M":  1.000,  # Medium  — occasionally exploited
    "H":  1.200,  # High    — frequently exploited
    "ND": 1.000,  # Not Defined → neutral (NISTIR §3.2.2)
}

# The norm's own GeneralRemediationLevel table (NISTIR 7502 §3.2.2).
_GRL_NORM: dict[str, float] = {
    "N":  1.000,  # None    — no general remediation applied
    "L":  0.800,  # Low     — marginal remediation applied
    "M":  0.600,  # Medium  — partial remediation applied
    "H":  0.400,  # High    — effective remediation widely applied
    "ND": 1.000,  # Not Defined → neutral
}

# CASPAR's stored vocabulary answers "is a fix available?", not "has a fix
# been applied?".  See the GRL vocabulary note in the module docstring: a
# configuration file carries no evidence of deployed mitigations, so every
# label resolves to the norm's None.
_GRL_APPLIED: dict[GRLValue, str] = {
    "U":  "N",    # Unavailable — no viable remedy
    "W":  "N",    # Workaround  — partial contour documented
    "H":  "N",    # High        — official fix documented
    "ND": "N",    # Not Defined
}

_GRL: dict[GRLValue, float] = {
    label: _GRL_NORM[applied] for label, applied in _GRL_APPLIED.items()
}


# ------------------------------------------------------------------ #
# Base Score  (NISTIR 7502 §3.2.1)                                     #
# ------------------------------------------------------------------ #

def impact(c: CIAValue, i: CIAValue, a: CIAValue) -> float:
    """Impact sub-score (NISTIR 7502 §3.2.1), unrounded."""
    return 10.41 * (1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))


def exploitability(av: AVValue, au: AuValue, ac: ACValue) -> float:
    """Exploitability sub-score (NISTIR 7502 §3.2.1), unrounded."""
    return 20 * _AV[av] * _AU[au] * _AC[ac]


def base_score(
    av: AVValue,
    au: AuValue,
    ac: ACValue,
    c: CIAValue,
    i: CIAValue,
    a: CIAValue,
) -> float:
    """
    Compute the CCSS Base Score.

    Formula (NISTIR 7502, eq. 1 and 2):

        Impact         = 10.41 * (1 - (1-C[c]) * (1-C[i]) * (1-C[a]))
        Exploitability = 20 * AV[av] * AU[au] * AC[ac]

        f(Impact) = 0 if Impact == 0 else 1.176

        BaseScore = round(((0.6 * Impact) + (0.4 * Exploitability) - 1.5)
                          * f(Impact), 1)

    Returns a float in [0.0, 10.0], rounded to one decimal place.
    """
    f_impact = impact(c, i, a)
    f_exploit = exploitability(av, au, ac)

    if f_impact == 0.0:
        return 0.0

    raw = (0.6 * f_impact) + (0.4 * f_exploit) - 1.5
    return round(raw * 1.176, 1)


# ------------------------------------------------------------------ #
# Temporal Score  (NISTIR 7502 §3.2.2)                                 #
# ------------------------------------------------------------------ #

def temporal_score(
    av: AVValue,
    au: AuValue,
    ac: ACValue,
    c: CIAValue,
    i: CIAValue,
    a: CIAValue,
    gel: GELValue = "ND",
    grl: GRLValue = "ND",
) -> float:
    """
    Compute the CCSS Temporal Score exactly as NISTIR 7502 §3.2.2 specifies.

    The temporal metrics modify the *Exploitability* component only; the
    Impact component is carried over unchanged from the base equation:

        TemporalExploitability = min(10, Exploitability * GEL * GRL)

        TemporalScore = round(((0.6 * Impact)
                               + (0.4 * TemporalExploitability)
                               - 1.5) * f(Impact), 1)

    Because GEL[high] = 1.200, a temporal score may legitimately exceed the
    base score: frequently exploited misconfigurations are scored upward,
    which is the behaviour the norm intends.

    Returns a float in [0.0, 10.0], rounded to one decimal place.
    """
    f_impact = impact(c, i, a)
    if f_impact == 0.0:
        return 0.0

    f_exploit = exploitability(av, au, ac)
    temporal_exploit = min(10.0, f_exploit * _GEL[gel] * _GRL[grl])

    raw = (0.6 * f_impact) + (0.4 * temporal_exploit) - 1.5
    return round(raw * 1.176, 1)


# ------------------------------------------------------------------ #
# AV / Au adjustment  (runtime, worst-case principle)                  #
# ------------------------------------------------------------------ #

# Ordering for "worst case" selection: higher index = worse (higher score)
_AV_ORDER: list[AVValue] = ["L", "A", "N"]
_AU_ORDER: list[AuValue] = ["M", "S", "N"]


def worst_av(a: AVValue, b: AVValue) -> AVValue:
    """Return the AV value that yields the higher exploitability."""
    return a if _AV_ORDER.index(a) >= _AV_ORDER.index(b) else b


def worst_au(a: AuValue, b: AuValue) -> AuValue:
    """Return the Au value that yields the higher exploitability."""
    return a if _AU_ORDER.index(a) >= _AU_ORDER.index(b) else b


def adjust_av_au(
    misconfig_base_av: AVValue,
    misconfig_base_au: AuValue,
    system_av: AVValue,
    system_au: AuValue,
) -> tuple[AVValue, AuValue]:
    """
    Merge the misconfiguration's intrinsic AV/Au (from the DB) with the
    system-level worst-case profile (from the plugin rule engine).

    The worst case always wins: if the system is exposed at Network level,
    every individual misconfiguration is scored as Network, even if its
    CIS entry suggests Local.
    """
    return worst_av(misconfig_base_av, system_av), worst_au(misconfig_base_au, system_au)


# ------------------------------------------------------------------ #
# Score aggregation  (runtime, pior caso)                              #
# ------------------------------------------------------------------ #

def aggregate(temporal_scores: list[float]) -> float:
    """
    Aggregate a list of TemporalScores into a single global score.

    Strategy: worst case (maximum).  Rationale: the global risk of a
    system is determined by its most severe uncorrected misconfiguration.
    Returns 0.0 for an empty list.
    """
    return max(temporal_scores, default=0.0)


# ------------------------------------------------------------------ #
# Severity label  (NVD-compatible mapping)                             #
# ------------------------------------------------------------------ #

def severity_label(score: float) -> SeverityLabel:
    """
    Map a numeric score (0–10) to a qualitative severity label.

    Thresholds follow the CVSS v3 / NVD convention, which is widely
    understood and consistent with how CIS Benchmarks are reported:

        0.0          → None
        0.1 –  3.9   → Low
        4.0 –  6.9   → Medium
        7.0 –  8.9   → High
        9.0 – 10.0   → Critical
    """
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ------------------------------------------------------------------ #
# Chain-amplified score                                                #
# ------------------------------------------------------------------ #

def amplified_score(temporal: float, amplification: float) -> float:
    """
    Apply an attack-chain amplification factor to a TemporalScore.

    The result is capped at 10.0 (the maximum CCSS score).
    """
    return min(round(temporal * amplification, 1), 10.0)


# Score below which "Critical" is not reached — a pure information-disclosure
# chain (no Integrity or Availability impact) should not be labelled Critical.
_NON_CRITICAL_CAP = 8.9


def impact_capped_score(amplified: float, impacts: list[tuple[str, str, str]]) -> float:
    """Cap a chain's amplified score by the *kind* of impact it actually has.

    A chain amplifies risk, but its severity ceiling should reflect what the
    combined misconfigurations can do. Reserve the Critical band (>= 9.0) for
    chains that touch Integrity or Availability (tampering, RCE, DoS); a chain
    whose combined impact is only Confidentiality — i.e. information disclosure
    / fingerprinting — is capped at High (8.9), no matter the LLM amplification.

    `impacts` is the list of (c, i, a) tuples of the constituent misconfigs
    (values "N"/"P"/"C"). Deterministic and auditable — the ceiling follows a
    rule, not a per-chain human judgement.

    Returns the (possibly lowered) score.
    """
    has_integrity = any(i != "N" for _, i, _ in impacts)
    has_availability = any(a != "N" for _, _, a in impacts)
    if has_integrity or has_availability:
        return amplified                      # may legitimately be Critical
    # Confidentiality-only (or no impact recorded): cannot be Critical.
    return min(amplified, _NON_CRITICAL_CAP)


# ------------------------------------------------------------------ #
# Convenience: recompute all scores from raw metrics                   #
# ------------------------------------------------------------------ #

def full_score(
    av: AVValue,
    au: AuValue,
    ac: ACValue,
    c: CIAValue,
    i: CIAValue,
    a: CIAValue,
    gel: GELValue = "ND",
    grl: GRLValue = "ND",
) -> tuple[float, float]:
    """
    Compute (BaseScore, TemporalScore) from all CCSS metrics in one call.

    Useful for validation scripts and tests.
    """
    bs = base_score(av, au, ac, c, i, a)
    ts = temporal_score(av, au, ac, c, i, a, gel, grl)
    return bs, ts
