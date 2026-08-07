"""
tests/test_promote_stats.py
---------------------------
`caspar promote --stats` — the learning-loop scoreboard. Promoted rules are
attributable (marker in their justification), so the DB can answer: how much
of the knowledge base came from the candidate→promote loop, and how much of
that still awaits operator review (empty good_value)?
"""

from __future__ import annotations

from click.testing import CliRunner

import cli.main as m
from config_assessment.core.models import Misconfiguration, TargetMetadata


def _seed(db_path):
    from config_assessment.core.db.database import Database
    with Database(str(db_path)) as db:
        db.upsert_target(TargetMetadata(
            name="nginx", display_name="NGINX", version="1.0",
            benchmark_source="CIS NGINX"))
        # A normal benchmark-extracted rule.
        db.upsert_misconfiguration(Misconfiguration(
            target_name="nginx", directive="server_tokens", bad_value="on",
            good_value="off", ac="L", c="P", i="N", a="N",
            justification="Exposes version info."))
        # A rule that came out of the learning loop — attributable marker,
        # good_value still empty (needs review).
        db.upsert_misconfiguration(Misconfiguration(
            target_name="nginx", directive="mystery_flag", bad_value="1",
            good_value="", ac="L", c="P", i="N", a="N",
            justification="LLM-assessed [promoted from unknown-directive "
                          "assessment; review before trusting]"))
        db._conn.commit()


def test_stats_counts_promoted_and_pending(tmp_path):
    dbf = tmp_path / "kb.db"
    _seed(dbf)
    res = CliRunner().invoke(m.cli, ["--db", str(dbf), "promote", "--stats"])
    assert res.exit_code == 0, res.output
    assert "LEARNING LOOP" in res.output
    # nginx: 2 rules, 1 promoted (50%), 1 pending review.
    assert "nginx" in res.output
    assert "50%" in res.output


def test_promote_without_config_or_stats_errors(tmp_path):
    dbf = tmp_path / "kb.db"
    _seed(dbf)
    res = CliRunner().invoke(m.cli, ["--db", str(dbf), "promote"])
    assert res.exit_code == 2
    assert "--stats" in res.output


def test_promoted_rule_carries_the_marker():
    """The contract the scoreboard relies on: promote_to_misconfiguration
    stamps the attribution marker into the justification."""
    from config_assessment.core.unknown_directives import (
        PROMOTED_MARK, UnknownDirective, promote_to_misconfiguration)
    u = UnknownDirective(name="x_flag", value="1")
    u.llm_is_misconfig = True
    u.llm_impact = "C:P"
    u.llm_justification = "test"
    rule = promote_to_misconfiguration(u, target_name="nginx")
    assert PROMOTED_MARK in rule.justification
    assert rule.good_value == ""   # review is still required, by design
