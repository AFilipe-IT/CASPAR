"""
tests/test_remediation.py
-------------------------
Assisted remediation (caspar fix): value rules with a literal good_value become
in-place line rewrites; prose/absence findings are manual. Nothing is written
unless asked, and prose good_values never corrupt a config.
"""

from __future__ import annotations

from types import SimpleNamespace

from config_assessment.reports.remediation import (
    build_fix_plan, render_diff, apply_plan, _is_literal_value)


def _issue(directive, bad, good, file=None, line=None, rule_type="value",
           recommendation="", score=5.0):
    src = None
    if file:
        src = SimpleNamespace(source_file=file, line_number=line,
                              value=bad, name=directive)
    return SimpleNamespace(
        directive=directive, bad_value=bad, good_value=good,
        rule_type=rule_type, source_directive=src,
        recommendation=recommendation, temporal_score=score)


def _result(issues):
    return SimpleNamespace(issues=issues)


# ── literal-value guard ────────────────────────────────────────────────

def test_literal_values_accepted():
    assert _is_literal_value("10")
    assert _is_literal_value("off")
    assert _is_literal_value("TLSv1.2 TLSv1.3")


def test_prose_values_rejected():
    assert not _is_literal_value("https://backend with restrictions")
    assert not _is_literal_value("<organizationally defined value>")
    assert not _is_literal_value("an appropriate role for the user")
    assert not _is_literal_value("")


# ── plan building ──────────────────────────────────────────────────────

def test_value_rule_becomes_editable(tmp_path):
    conf = tmp_path / "x.conf"
    conf.write_text("worker_processes 1;\nkeepalive_timeout 65;\n")
    r = _result([_issue("keepalive_timeout", "65", "10", str(conf), 2)])
    plan = build_fix_plan(r)
    assert len(plan.edits) == 1 and not plan.manual
    e = plan.edits[0]
    assert e.old_line == "keepalive_timeout 65;"
    assert e.new_line == "keepalive_timeout 10;"


def test_absence_rule_is_manual(tmp_path):
    r = _result([_issue("ssl", "", "on", rule_type="absence")])
    plan = build_fix_plan(r)
    assert not plan.edits and len(plan.manual) == 1
    assert "absence" in plan.manual[0]["reason"]


def test_prose_goodvalue_is_manual(tmp_path):
    conf = tmp_path / "x.conf"
    conf.write_text("proxy_pass http://x;\n")
    r = _result([_issue("proxy_pass", "http://x", "https with restrictions",
                        str(conf), 1)])
    plan = build_fix_plan(r)
    assert not plan.edits and len(plan.manual) == 1
    assert "guidance" in plan.manual[0]["reason"]


def test_unknown_location_is_manual():
    r = _result([_issue("x", "bad", "good")])   # no source_directive
    plan = build_fix_plan(r)
    assert not plan.edits and plan.manual[0]["reason"] == "location unknown"


def test_value_not_on_line_falls_back_to_directive_rewrite(tmp_path):
    conf = tmp_path / "x.conf"
    conf.write_text("    ServerTokens Full\n")
    # bad_value 'OS' isn't literally on the line, but the directive is → rewrite.
    r = _result([_issue("ServerTokens", "OS", "Prod", str(conf), 1)])
    plan = build_fix_plan(r)
    assert len(plan.edits) == 1
    assert plan.edits[0].new_line == "    ServerTokens Prod"   # indent preserved


# ── applying ───────────────────────────────────────────────────────────

def test_apply_writes_fixed_copy_not_original(tmp_path):
    conf = tmp_path / "x.conf"
    conf.write_text("keepalive_timeout 65;\n")
    r = _result([_issue("keepalive_timeout", "65", "10", str(conf), 1)])
    plan = build_fix_plan(r)
    written = apply_plan(plan, in_place=False)
    assert written == [str(conf) + ".fixed"]
    # Original untouched, .fixed has the correction.
    assert conf.read_text() == "keepalive_timeout 65;\n"
    assert "keepalive_timeout 10;" in (tmp_path / "x.conf.fixed").read_text()


def test_apply_in_place(tmp_path):
    conf = tmp_path / "x.conf"
    conf.write_text("keepalive_timeout 65;\n")
    r = _result([_issue("keepalive_timeout", "65", "10", str(conf), 1)])
    apply_plan(build_fix_plan(r), in_place=True)
    assert "keepalive_timeout 10;" in conf.read_text()


def test_render_diff_shows_before_after(tmp_path):
    conf = tmp_path / "x.conf"
    conf.write_text("keepalive_timeout 65;\n")
    r = _result([_issue("keepalive_timeout", "65", "10", str(conf), 1)])
    diff = render_diff(build_fix_plan(r))
    assert "- keepalive_timeout 65;" in diff
    assert "+ keepalive_timeout 10;" in diff
