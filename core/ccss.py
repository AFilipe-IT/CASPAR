"""
core/ccss.py
------------
CCSS scoring engine.

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
  GEL : None=0.900, Low=0.930, Medium=1.000, High=1.000, ND=1.000
  GRL : Unavailable=0.900, Workaround=0.950, High=1.000, ND=1.000
"""

from __future__ import annotations

from core.models import (
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
    "N":  0.900,  # None
    "L":  0.930,  # Low
    "M":  1.000,  # Medium
    "H":  1.000,  # High  (same weight — High is already worst case)
    "ND": 1.000,  # Not Defined → defaults to Medium (NISTIR §2.2.1)
}

_GRL: dict[GRLValue, float] = {
    "U":  0.900,  # Unavailable
    "W":  0.950,  # Workaround
    "H":  1.000,  # High (official remediation documented)
    "ND": 1.000,  # Not Defined → defaults to High (NISTIR §2.2.2)
}


# ------------------------------------------------------------------ #
# Base Score  (NISTIR 7502 §3.2.1)                                     #
# ------------------------------------------------------------------ #

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

        f_impact  = 10.41 * (1 - (1-C[c]) * (1-C[i]) * (1-C[a]))
        f_exploit = 20 * AV[av] * AU[au] * AC[ac]

        if f_impact == 0:
            BaseScore = 0.0
        else:
            BaseScore = round(((0.6 * f_impact) + (0.4 * f_exploit) - 1.5) * 1.176, 1)

    Returns a float in [0.0, 10.0], rounded to one decimal place.
    """
    f_impact = 10.41 * (1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))
    f_exploit = 20 * _AV[av] * _AU[au] * _AC[ac]

    if f_impact == 0.0:
        return 0.0

    raw = (0.6 * f_impact) + (0.4 * f_exploit) - 1.5
    return round(raw * 1.176, 1)


# ------------------------------------------------------------------ #
# Temporal Score  (NISTIR 7502 §3.2.2)                                 #
# ------------------------------------------------------------------ #

def temporal_score(bs: float, gel: GELValue, grl: GRLValue) -> float:
    """
    Compute the CCSS Temporal Score.

    Formula:
        TemporalScore = round(BaseScore * GEL[gel] * GRL[grl], 1)

    Returns a float in [0.0, 10.0], rounded to one decimal place.
    """
    return round(bs * _GEL[gel] * _GRL[grl], 1)


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
    ts = temporal_score(bs, gel, grl)
    return bs, ts
