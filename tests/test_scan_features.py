"""
tests/test_scan_features.py
---------------------------
Tests for the product-level features built on the scan JSON: diff, badge,
differentiated exit codes, suppressions, and catalog fuzzy-search — plus the
CLI commands that expose them. All offline; no scanning or LLM.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from cli.main import cli
from config_assessment.reports.scan_features import (
    issue_key, diff_scans, badge_url, badge_markdown, classify_exit,
    EXIT_OK, EXIT_THRESHOLD, EXIT_CRITICAL,
    SuppressionStore, search_catalog, load_scan)


def _scan(score, issues):
    return {"global_temporal_score": score, "severity": "Medium", "issues": issues}


def _issue(directive, bad, score=5.0):
    return {"directive": directive, "bad_value": bad, "temporal_score": score}


# ── diff ────────────────────────────────────────────────────────────────

def test_diff_detects_resolved_new_and_delta():
    old = _scan(6.0, [_issue("a", "x"), _issue("b", "y")])
    new = _scan(4.0, [_issue("b", "y"), _issue("c", "z")])
    d = diff_scans(old, new)
    assert d.score_delta == -2.0
    assert [i["directive"] for i in d.resolved] == ["a"]
    assert [i["directive"] for i in d.new_issues] == ["c"]
    assert len(d.unchanged) == 1


def test_diff_identical_scans_no_change():
    s = _scan(5.0, [_issue("a", "x")])
    d = diff_scans(s, s)
    assert d.score_delta == 0.0 and not d.resolved and not d.new_issues


def test_issue_key_is_case_insensitive_and_pairs_directive_value():
    assert issue_key({"directive": "SSL", "bad_value": "Off"}) == "ssl=off"


# ── badge ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,color", [
    (9.5, "critical"), (7.5, "red"), (5.0, "yellow"), (2.0, "green"), (0.0, "brightgreen"),
])
def test_badge_color_by_score(score, color):
    assert color in badge_url(score)


def test_badge_markdown_shape():
    md = badge_markdown(5.7)
    assert md.startswith("![CASPAR Score](https://img.shields.io/badge/")
    assert "5.7" in md


# ── exit codes ─────────────────────────────────────────────────────────

def test_exit_critical_dominates_even_under_threshold():
    assert classify_exit(["Critical", "Low"], 3.0, 9.9) == EXIT_CRITICAL


def test_exit_threshold_when_over_and_no_critical():
    assert classify_exit(["Medium"], 6.0, 5.0) == EXIT_THRESHOLD


def test_exit_ok_when_clean():
    assert classify_exit(["Medium"], 3.0, 5.0) == EXIT_OK
    assert classify_exit([], 0.0, 0.0) == EXIT_OK


# ── suppressions ───────────────────────────────────────────────────────

def test_suppression_roundtrip_and_partition(tmp_path):
    p = tmp_path / "supp.json"
    store = SuppressionStore(p)
    store.add("keepalive_timeout", "accepted", date="2026-07-02")
    store.save()

    reloaded = SuppressionStore(p)
    issues = [{"directive": "keepalive_timeout", "bad_value": "65"},
              {"directive": "ssl", "bad_value": "off"}]
    active, suppressed = reloaded.partition(issues)
    assert len(active) == 1 and len(suppressed) == 1
    assert suppressed[0]["directive"] == "keepalive_timeout"


def test_suppression_value_specific(tmp_path):
    store = SuppressionStore(tmp_path / "s.json")
    store.add("ssl", "ok", bad_value="off")
    assert store.is_suppressed({"directive": "ssl", "bad_value": "off"})
    # A different bad_value is NOT suppressed.
    assert store.is_suppressed({"directive": "ssl", "bad_value": "weak"}) is None


def test_suppression_add_replaces_duplicate(tmp_path):
    store = SuppressionStore(tmp_path / "s.json")
    store.add("x", "first")
    store.add("x", "second")
    assert len(store.items) == 1 and store.items[0].reason == "second"


# ── catalog search ─────────────────────────────────────────────────────

def _catalog_rows():
    return [
        {"service": "postgresql", "service_name": "PostgreSQL", "sources": [{"type": "stigviewer"}]},
        {"service": "epas", "service_name": "EnterpriseDB Postgres Advanced Server", "sources": [{"type": "stigviewer"}]},
        {"service": "nginx", "service_name": "NGINX", "sources": [{"type": "stigviewer"}]},
        {"service": "sles12", "service_name": "SUSE Linux Enterprise Server 12", "sources": [{"type": "stigviewer"}]},
    ]


def test_search_substring_and_fuzzy():
    hits = {r["service"] for r in search_catalog(_catalog_rows(), "postgres")}
    assert "postgresql" in hits and "epas" in hits
    assert "sles12" not in hits            # must not fuzzy-match unrelated


def test_search_no_match_returns_empty():
    assert search_catalog(_catalog_rows(), "zzzznotathing") == []


# ── load_scan validation ───────────────────────────────────────────────

def test_load_scan_rejects_non_scan_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(ValueError, match="not a CASPAR scan"):
        load_scan(p)


# ── CLI wiring ─────────────────────────────────────────────────────────

def _write_scan(path, score, issues):
    path.write_text(json.dumps(_scan(score, issues)))


def test_cli_diff(tmp_path):
    old = tmp_path / "old.json"; new = tmp_path / "new.json"
    _write_scan(old, 6.0, [_issue("a", "x")])
    _write_scan(new, 4.0, [])                       # resolved 'a', score down
    res = CliRunner().invoke(cli, ["diff", str(old), str(new)])
    assert res.exit_code == 0                       # improvement → 0
    assert "Resolved" in res.output and "▼" in res.output


def test_cli_diff_exit_1_when_worse(tmp_path):
    old = tmp_path / "old.json"; new = tmp_path / "new.json"
    _write_scan(old, 4.0, [])
    _write_scan(new, 6.0, [_issue("a", "x")])       # score up
    res = CliRunner().invoke(cli, ["diff", str(old), str(new)])
    assert res.exit_code == 1


def test_cli_badge(tmp_path):
    p = tmp_path / "s.json"; _write_scan(p, 5.7, [])
    res = CliRunner().invoke(cli, ["badge", str(p)])
    assert res.exit_code == 0
    assert "img.shields.io" in res.output and "5.7" in res.output


def test_cli_suppress_requires_reason(tmp_path):
    res = CliRunner().invoke(
        cli, ["suppress", "ssl", "--file", str(tmp_path / "s.json")])
    assert res.exit_code == 2
    assert "reason" in res.output.lower()


def test_cli_suppress_add_and_list(tmp_path):
    f = str(tmp_path / "s.json")
    add = CliRunner().invoke(cli, ["suppress", "ssl", "-r", "ok", "--file", f])
    assert add.exit_code == 0
    lst = CliRunner().invoke(cli, ["suppress", "--list", "--file", f])
    assert "ssl" in lst.output and "ok" in lst.output


def test_cli_fetch_search():
    res = CliRunner().invoke(cli, ["plugin", "fetch", "--search", "postgres"])
    assert res.exit_code == 0
    assert "postgresql" in res.output


def test_cli_fetch_search_no_match():
    res = CliRunner().invoke(cli, ["plugin", "fetch", "--search", "zzzznope"])
    assert res.exit_code == 1
