"""
tests/test_nistir7502_examples.py
---------------------------------
Replication of the official scoring examples in NISTIR 7502 Section 4
(CCE-4675-5 … CCE-2776-3), i.e. the 16 fully-worked base vectors published
in the CCSS specification itself. The report states (footnote 13) that the
published scores were produced with the NVD CVSS v2 calculator, so these
values are authoritative ground truth for core/ccss.py::base_score.

Each case asserts three published numbers:
  - impact subscore      = 10.41 * (1 - (1-C)(1-I)(1-A))
  - exploitability subscore = 20 * AV * AC * Au
  - base score           (via base_score(), the code under test)

The temporal example in §4.12 (GEL:L/GRL:M → 1.9 / 3.7) is replicated with
the OFFICIAL temporal equation (§3.2.2) implemented locally, because
AEGIS's temporal_score() deliberately uses a simplified model
(BaseScore × GEL × GRL with a reduced value set) — see the note in
TestTemporalExample412.
"""

import pytest

from config_assessment.core.ccss import _AC, _AU, _AV, _CIA, base_score

# ── §4 published examples ───────────────────────────────────────────────
# (id, AV, AC, Au, C, I, A, impact, exploitability, base score)
# PL and EM appear in the report's vectors but do not affect the base score.
NISTIR_EXAMPLES = [
    ("CCE-4675-5 (Solaris kernel auditing)",        "N", "L", "N", "N", "P", "N", 2.9, 10.0, 5.0),
    ("CCE-4693-8 case 1 (cron.allow, denied use)",  "L", "L", "N", "N", "N", "P", 2.9,  3.9, 2.1),
    ("CCE-4693-8 case 2 (cron.allow, tampering)",   "L", "L", "N", "P", "P", "P", 6.4,  3.9, 4.6),
    ("CCE-2786-2 (create pagefile right)",          "L", "L", "N", "N", "N", "P", 2.9,  3.9, 2.1),
    ("CCE-2363-0 case 1 (lockout too short)",       "L", "H", "N", "P", "N", "N", 2.9,  1.9, 1.2),
    ("CCE-2363-0 case 2 (lockout too long)",        "L", "L", "N", "N", "N", "P", 2.9,  3.9, 2.1),
    ("CCE-2366-3 case 1 (shutdown right granted)",  "L", "L", "N", "N", "N", "C", 6.9,  3.9, 4.9),
    ("CCE-2366-3 case 2 (shutdown right denied)",   "L", "L", "N", "N", "N", "P", 2.9,  3.9, 2.1),
    ("CCE-4208-5 (IE7 offline page hit logging)",   "N", "H", "N", "P", "N", "N", 2.9,  4.9, 2.6),
    ("CCE-2519-7 case 1 (idle timeout too low)",    "N", "L", "N", "N", "N", "P", 2.9, 10.0, 5.0),
    ("CCE-2519-7 case 2 (idle timeout too high)",   "N", "H", "N", "P", "P", "P", 6.4,  4.9, 5.1),
    ("CCE-3171-6 (ALG service / firewall off)",     "N", "L", "N", "P", "N", "P", 4.9, 10.0, 6.4),
    ("CCE-3047-8 case 1 (app mgmt disabled)",       "L", "L", "N", "N", "N", "P", 2.9,  3.9, 2.1),
    ("CCE-3047-8 case 2 (app mgmt enabled)",        "L", "L", "N", "N", "P", "N", 2.9,  3.9, 2.1),
    ("CCE-4191-3 case 1 (dhcp client disabled)",    "L", "L", "N", "N", "N", "P", 2.9,  3.9, 2.1),
    ("CCE-4191-3 case 2 (dhcp client enabled)",     "L", "L", "N", "P", "N", "N", 2.9,  3.9, 2.1),
    ("CCE-3245-8 (IPSEC services disabled)",        "N", "L", "N", "P", "P", "P", 6.4, 10.0, 7.5),
    ("CCE-2776-3 (automatic logon)",                "L", "L", "N", "P", "P", "P", 6.4,  3.9, 4.6),
]


class TestNistirBaseExamples:
    """All 16 worked base vectors of NISTIR 7502 §4 must replicate exactly."""

    @pytest.mark.parametrize(
        "label, av, ac, au, c, i, a, exp_impact, exp_exploit, exp_base",
        NISTIR_EXAMPLES,
        ids=[e[0] for e in NISTIR_EXAMPLES],
    )
    def test_example(self, label, av, ac, au, c, i, a,
                     exp_impact, exp_exploit, exp_base):
        impact = 10.41 * (1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))
        exploit = 20 * _AV[av] * _AC[ac] * _AU[au]
        assert round(impact, 1) == exp_impact
        assert round(exploit, 1) == exp_exploit
        assert base_score(av, au, ac, c, i, a) == exp_base

    def test_full_coverage_of_section_4(self):
        # 12 CCEs, 6 of them with two cases → 18 vectors published.
        assert len(NISTIR_EXAMPLES) == 18


# ── §4.12 temporal example (official equation §3.2.2) ───────────────────
_GEL_OFFICIAL = {"N": 0.6, "L": 0.8, "M": 1.0, "H": 1.2, "ND": 1.0}
_GRL_OFFICIAL = {"N": 1.0, "L": 0.8, "M": 0.6, "H": 0.4, "ND": 1.0}


def _official_temporal(av, ac, au, c, i, a, gel, grl):
    """NISTIR 7502 §3.2.2 temporal equation, implemented verbatim."""
    impact = 10.41 * (1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))
    exploit = 20 * _AV[av] * _AC[ac] * _AU[au]
    t_exploit = min(10, exploit * _GEL_OFFICIAL[gel] * _GRL_OFFICIAL[grl])
    f = 0.0 if impact == 0 else 1.176
    t_score = round(((0.6 * impact) + (0.4 * t_exploit) - 1.5) * f, 1)
    return round(t_exploit, 1), t_score


class TestTemporalExample412:
    """
    §4.12 (CCE-2776-3): base AV:L/AC:L/Au:N/C:P/I:P/A:P with GEL:L/GRL:M
    → temporal exploitability 1.9, temporal score 3.7.

    NOTE: this validates the OFFICIAL equation, not AEGIS's
    temporal_score(). AEGIS intentionally uses a simplified temporal
    model (BaseScore × GEL × GRL, GRL values U/W/H/ND) whose multipliers
    stay in [0.81, 1.0] — a conservative deviation from the spec, which
    scales only the exploitability term with multipliers down to 0.4.
    The deviation is documented in VALIDACAO.md §7 (tradeoffs).
    """

    def test_official_equation_reproduces_published_values(self):
        t_exploit, t_score = _official_temporal(
            "L", "L", "N", "P", "P", "P", gel="L", grl="M")
        assert t_exploit == 1.9
        assert t_score == 3.7

    def test_nd_defaults_are_neutral_in_both_models(self):
        # Spec: GEL:ND→1.0, GRL:ND→1.0 (no effect). AEGIS: ND→1.0 as well.
        from config_assessment.core.ccss import temporal_score
        _, t_score = _official_temporal(
            "L", "L", "N", "P", "P", "P", gel="ND", grl="ND")
        assert t_score == base_score("L", "N", "L", "P", "P", "P") == 4.6
        assert temporal_score(4.6, "ND", "ND") == 4.6
