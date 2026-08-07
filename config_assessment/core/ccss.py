"""
core/ccss.py
------------
Compatibility shim. The CCSS scoring engine now lives at
config_assessment.core.engines.scoring (the CVM Core's Scoring Engine).

This module re-exports its public and private (weight-table) names unchanged
so existing imports of `config_assessment.core.ccss` keep working.
"""

from __future__ import annotations

from config_assessment.core.engines.scoring import (
    _AC,
    _AU,
    _AV,
    _CIA,
    _GEL,
    _GRL,
    adjust_av_au,
    aggregate,
    amplified_score,
    base_score,
    full_score,
    impact_capped_score,
    severity_label,
    temporal_score,
    worst_au,
    worst_av,
)

__all__ = [
    "adjust_av_au",
    "aggregate",
    "amplified_score",
    "base_score",
    "full_score",
    "impact_capped_score",
    "severity_label",
    "temporal_score",
    "worst_au",
    "worst_av",
]
