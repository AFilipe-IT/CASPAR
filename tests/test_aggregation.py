"""
tests/test_aggregation.py
---------------------------
Unit tests for the two new CVM hierarchy levels added to
core/engines/aggregation.py:

  - aggregate_by_file        (Configuration File level)
  - aggregate_categories / aggregate_chain_category (category taxonomy,
    an aggregation dimension inside the Operating System level)

Plus core/engines/categorization.py::categorize() — the deterministic
classifier the aggregation functions depend on.
"""

from __future__ import annotations

from config_assessment.core.engines.aggregation import (
    aggregate_by_file,
    aggregate_categories,
    aggregate_chain_category,
)
from config_assessment.core.engines.categorization import (
    ATTACK_CHAINS,
    AUTH,
    AUTHZ,
    CIS_STIG,
    CRYPTO,
    EXPOSURE,
    SERVICE_CONFIG,
    categorize,
)
from config_assessment.core.models import AttackChain, Directive, Misconfiguration


def _issue(**kwargs) -> Misconfiguration:
    defaults = dict(
        target_name="dummy", directive="SomeDirective", bad_value="on",
        ac="L", c="P", i="P", a="P", base_score=5.0, temporal_score=5.0,
    )
    defaults.update(kwargs)
    return Misconfiguration(**defaults)


def _chain(**kwargs) -> AttackChain:
    defaults = dict(
        chain_id="c1", target_name="dummy", misconfig_directives=["A", "B"],
        amplification=1.5, amplified_score=7.5, active=True,
    )
    defaults.update(kwargs)
    return AttackChain(**defaults)


# ------------------------------------------------------------------ #
# aggregate_by_file — Configuration File level                        #
# ------------------------------------------------------------------ #

class TestAggregateByFile:
    def test_groups_by_source_file(self):
        d1 = Directive(name="A", value="on", source_file="/etc/app/a.conf")
        d2 = Directive(name="B", value="on", source_file="/etc/app/b.conf")
        issues = [
            _issue(directive="A", temporal_score=4.0, source_directive=d1),
            _issue(directive="B", temporal_score=9.0, source_directive=d2),
        ]
        rollups = aggregate_by_file(issues)
        assert set(rollups) == {"/etc/app/a.conf", "/etc/app/b.conf"}
        assert rollups["/etc/app/a.conf"].temporal_score == 4.0
        assert rollups["/etc/app/b.conf"].temporal_score == 9.0

    def test_worst_case_within_a_file(self):
        d = Directive(name="A", value="on", source_file="/etc/app/a.conf")
        issues = [
            _issue(temporal_score=3.0, source_directive=d),
            _issue(temporal_score=8.5, source_directive=d),
        ]
        rollup = aggregate_by_file(issues)["/etc/app/a.conf"]
        assert rollup.temporal_score == 8.5
        assert rollup.severity == "High"
        assert len(rollup.issues) == 2

    def test_missing_source_directive_groups_as_unknown(self):
        issues = [_issue(temporal_score=5.0, source_directive=None)]
        rollups = aggregate_by_file(issues)
        assert "(unknown)" in rollups
        assert rollups["(unknown)"].temporal_score == 5.0

    def test_empty_source_file_string_groups_together(self):
        d = Directive(name="A", value="on")  # source_file defaults to ""
        issues = [_issue(source_directive=d), _issue(source_directive=d)]
        rollups = aggregate_by_file(issues)
        assert list(rollups.keys()) == [""]
        assert len(rollups[""].issues) == 2

    def test_empty_input_returns_empty_dict(self):
        assert aggregate_by_file([]) == {}


# ------------------------------------------------------------------ #
# categorize() — deterministic classifier                             #
# ------------------------------------------------------------------ #

class TestCategorize:
    def test_password_directive_matches_auth(self):
        m = _issue(directive="PasswordAuthentication", justification="", recommendation="")
        assert AUTH in categorize(m)

    def test_sudo_matches_authz(self):
        m = _issue(directive="X", justification="allows passwordless sudo", recommendation="")
        assert AUTHZ in categorize(m)

    def test_listen_matches_exposure(self):
        m = _issue(directive="Listen", justification="binds to 0.0.0.0", recommendation="")
        assert EXPOSURE in categorize(m)

    def test_tls_matches_crypto(self):
        m = _issue(directive="SSLProtocol", justification="weak cipher suite", recommendation="")
        assert CRYPTO in categorize(m)

    def test_cis_section_matches_cis_stig(self):
        m = _issue(directive="X", cis_section="1.1.1", justification="", recommendation="")
        assert CIS_STIG in categorize(m)

    def test_cce_id_matches_cis_stig(self):
        m = _issue(directive="X", cce_id="CCE-1234", justification="", recommendation="")
        assert CIS_STIG in categorize(m)

    def test_unmatched_falls_back_to_service_config(self):
        m = _issue(directive="LogLevel", bad_value="warn", justification="", recommendation="")
        assert categorize(m) == [SERVICE_CONFIG]

    def test_multiple_categories_can_match(self):
        m = _issue(
            directive="PasswordAuthentication", cis_section="5.2.10",
            justification="weak password policy", recommendation="",
        )
        cats = categorize(m)
        assert AUTH in cats
        assert CIS_STIG in cats

    def test_av_au_metrics_are_not_used_as_signals(self):
        # av="N" is the common production default and must not by itself
        # trigger EXPOSURE — only keyword/field signals should.
        m = _issue(directive="LogLevel", av="N", au="N", justification="", recommendation="")
        assert categorize(m) == [SERVICE_CONFIG]


# ------------------------------------------------------------------ #
# aggregate_categories / aggregate_chain_category — OS level          #
# ------------------------------------------------------------------ #

class TestAggregateCategories:
    def test_worst_case_per_category(self):
        issues = [
            _issue(directive="PasswordAuthentication", temporal_score=3.0),
            _issue(directive="PasswordAuthentication", temporal_score=9.0),
        ]
        out = aggregate_categories(issues)
        assert out[AUTH].score == 9.0
        assert out[AUTH].severity == "Critical"
        assert out[AUTH].issue_count == 2

    def test_fallback_category_present_for_unmatched_rule(self):
        issues = [_issue(directive="LogLevel", bad_value="warn", temporal_score=2.0)]
        out = aggregate_categories(issues)
        assert SERVICE_CONFIG in out
        assert out[SERVICE_CONFIG].score == 2.0

    def test_rule_in_multiple_categories_counted_in_both(self):
        issues = [_issue(
            directive="PasswordAuthentication", cis_section="5.2.10", temporal_score=7.0,
        )]
        out = aggregate_categories(issues)
        assert out[AUTH].issue_count == 1
        assert out[CIS_STIG].issue_count == 1

    def test_empty_issues_returns_empty_dict(self):
        assert aggregate_categories([]) == {}

    def test_top_issues_capped_and_worst_first(self):
        issues = [
            _issue(directive="Listen", temporal_score=float(i))
            for i in range(1, 8)
        ]
        out = aggregate_categories(issues)
        top = out[EXPOSURE].top_issues
        assert len(top) == 5
        assert top[0].temporal_score == 7.0


class TestAggregateChainCategory:
    def test_worst_case_across_active_chains(self):
        chains = [_chain(amplified_score=4.0), _chain(amplified_score=9.5)]
        cat = aggregate_chain_category(chains)
        assert cat.category == ATTACK_CHAINS
        assert cat.score == 9.5
        assert cat.issue_count == 2

    def test_inactive_chains_excluded(self):
        chains = [
            _chain(amplified_score=9.9, active=False),
            _chain(amplified_score=3.0, active=True),
        ]
        cat = aggregate_chain_category(chains)
        assert cat.score == 3.0
        assert cat.issue_count == 1

    def test_no_chains_scores_zero(self):
        cat = aggregate_chain_category([])
        assert cat.score == 0.0
        assert cat.severity == "None"
        assert cat.issue_count == 0
