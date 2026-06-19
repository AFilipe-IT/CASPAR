"""
tests/test_ccss.py
------------------
Unit tests for core/ccss.py — all CCSS scoring formulas.

These tests are the mathematical ground truth for the project.
Any change to numeric weights must be justified by a citation to
NISTIR 7502 and reflected here first.
"""

import pytest
from core.ccss import (
    aggregate,
    amplified_score,
    base_score,
    full_score,
    severity_label,
    temporal_score,
    worst_av,
    worst_au,
    adjust_av_au,
)


class TestBaseScore:
    """Verify BaseScore formula against manually computed values."""

    def test_zero_impact_returns_zero(self):
        # f_impact = 0 → BaseScore must be 0 regardless of exploitability
        assert base_score("N", "N", "L", "N", "N", "N") == 0.0

    def test_known_value_complete_cia(self):
        # Worst case: AV=N, Au=N, AC=L, C=C, I=C, A=C
        # f_impact = 10.41 * (1 - (1-0.66)*(1-0.66)*(1-0.66))
        #          = 10.41 * (1 - 0.34^3) = 10.41 * (1 - 0.039304) ≈ 10.0
        # f_exploit = 20 * 1.0 * 0.704 * 0.71 ≈ 9.997
        # raw = 0.6*10.0 + 0.4*9.997 - 1.5 = 6.0 + 3.999 - 1.5 = 8.499
        # BaseScore = round(8.499 * 1.176, 1) = round(9.995, 1) = 10.0
        score = base_score("N", "N", "L", "C", "C", "C")
        assert score == 10.0

    def test_partial_impact(self):
        # AV=N, Au=N, AC=L, C=P, I=P, A=P
        # f_impact = 10.41 * (1 - (0.725)^3) = 10.41 * (1 - 0.3814) ≈ 6.44
        # f_exploit = 20 * 1.0 * 0.704 * 0.71 ≈ 9.997
        # raw = 0.6*6.44 + 0.4*9.997 - 1.5 = 3.864 + 3.999 - 1.5 = 6.363
        # BaseScore = round(6.363 * 1.176, 1) = round(7.483, 1) = 7.5
        score = base_score("N", "N", "L", "P", "P", "P")
        assert 7.0 <= score <= 8.0, f"Expected ~7.5, got {score}"

    def test_local_access_reduces_score(self):
        score_local = base_score("L", "N", "L", "P", "P", "P")
        score_network = base_score("N", "N", "L", "P", "P", "P")
        assert score_local < score_network

    def test_multiple_auth_reduces_score(self):
        score_none_auth = base_score("N", "N", "L", "P", "P", "P")
        score_multi_auth = base_score("N", "M", "L", "P", "P", "P")
        assert score_multi_auth < score_none_auth

    def test_high_complexity_reduces_score(self):
        score_low_ac = base_score("N", "N", "L", "P", "P", "P")
        score_high_ac = base_score("N", "N", "H", "P", "P", "P")
        assert score_high_ac < score_low_ac

    def test_score_bounded_0_to_10(self):
        for av in ("L", "A", "N"):
            for au in ("M", "S", "N"):
                for ac in ("H", "M", "L"):
                    for cia in ("N", "P", "C"):
                        s = base_score(av, au, ac, cia, cia, cia)
                        assert 0.0 <= s <= 10.0, f"Out of bounds: {s}"


class TestTemporalScore:
    """Verify TemporalScore formula."""

    def test_nd_gel_grl_returns_same_as_base(self):
        bs = base_score("N", "N", "L", "P", "P", "P")
        ts = temporal_score(bs, "ND", "ND")
        # ND weights are 1.0 for both, so ts == bs
        assert ts == bs

    def test_none_gel_reduces_score(self):
        bs = base_score("N", "N", "L", "P", "P", "P")
        ts_none = temporal_score(bs, "N", "H")
        ts_high = temporal_score(bs, "H", "H")
        assert ts_none < ts_high

    def test_temporal_never_exceeds_base(self):
        bs = base_score("N", "N", "L", "C", "C", "C")
        for gel in ("N", "L", "M", "H", "ND"):
            for grl in ("U", "W", "H", "ND"):
                ts = temporal_score(bs, gel, grl)
                assert ts <= bs + 0.05, f"Temporal {ts} exceeded base {bs}"

    def test_temporal_score_bounded(self):
        bs = 10.0
        ts = temporal_score(bs, "H", "H")
        assert 0.0 <= ts <= 10.0


class TestWorstCase:
    """Verify worst-case AV/Au selection logic."""

    def test_worst_av_network_wins(self):
        assert worst_av("L", "N") == "N"
        assert worst_av("N", "L") == "N"
        assert worst_av("A", "N") == "N"

    def test_worst_au_none_wins(self):
        assert worst_au("M", "N") == "N"
        assert worst_au("N", "S") == "N"
        assert worst_au("S", "M") == "S"

    def test_adjust_av_au_picks_worst(self):
        av, au = adjust_av_au("L", "M", "N", "N")
        assert av == "N"
        assert au == "N"

    def test_adjust_av_au_keeps_existing_if_worse(self):
        av, au = adjust_av_au("N", "N", "L", "M")
        assert av == "N"
        assert au == "N"


class TestAggregate:
    def test_empty_returns_zero(self):
        assert aggregate([]) == 0.0

    def test_returns_max(self):
        assert aggregate([2.5, 7.1, 4.0]) == 7.1

    def test_single_element(self):
        assert aggregate([5.5]) == 5.5


class TestSeverityLabel:
    def test_zero_is_none(self):
        assert severity_label(0.0) == "None"

    def test_low_boundary(self):
        assert severity_label(0.1) == "Low"
        assert severity_label(3.9) == "Low"

    def test_medium_boundary(self):
        assert severity_label(4.0) == "Medium"
        assert severity_label(6.9) == "Medium"

    def test_high_boundary(self):
        assert severity_label(7.0) == "High"
        assert severity_label(8.9) == "High"

    def test_critical_boundary(self):
        assert severity_label(9.0) == "Critical"
        assert severity_label(10.0) == "Critical"


class TestAmplifiedScore:
    def test_amplification_applied(self):
        assert amplified_score(5.0, 1.5) == 7.5

    def test_capped_at_10(self):
        assert amplified_score(9.0, 2.0) == 10.0

    def test_no_amplification(self):
        assert amplified_score(6.0, 1.0) == 6.0


class TestFullScore:
    def test_returns_tuple(self):
        bs, ts = full_score("N", "N", "L", "P", "P", "P")
        assert isinstance(bs, float)
        assert isinstance(ts, float)
        assert ts <= bs + 0.1
