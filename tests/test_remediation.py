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


# ── commenting a directive out ─────────────────────────────────────────
# Module rules carry good_value "#LoadModule <mod>": the commented form of
# their own directive, meaning "disable this line". Substituting that into the
# line would name the directive twice ("LoadModule #LoadModule status_module
# modules/mod_status.so") and Apache refuses to start on it.

def test_comment_out_values_are_recognised():
    from config_assessment.reports.remediation import _is_comment_out
    assert _is_comment_out("#LoadModule status_module", "LoadModule")
    assert _is_comment_out("# loadmodule info_module", "LoadModule")
    assert not _is_comment_out("Prod", "ServerTokens")
    assert not _is_comment_out("#some prose", "LoadModule")


def test_module_rule_comments_the_whole_line(tmp_path):
    conf = tmp_path / "httpd.conf"
    conf.write_text("LoadModule status_module modules/mod_status.so\n")
    plan = build_fix_plan(_result([
        _issue("LoadModule", "status_module", "#LoadModule status_module",
               file=str(conf), line=1)]))
    assert len(plan.edits) == 1
    edit = plan.edits[0]
    assert edit.new_line == "#LoadModule status_module modules/mod_status.so"
    assert "#LoadModule #" not in edit.new_line


def test_indented_module_rule_keeps_its_indentation(tmp_path):
    conf = tmp_path / "httpd.conf"
    conf.write_text("    LoadModule info_module modules/mod_info.so\n")
    plan = build_fix_plan(_result([
        _issue("LoadModule", "info_module", "#LoadModule info_module",
               file=str(conf), line=1)]))
    assert plan.edits[0].new_line == \
        "    #LoadModule info_module modules/mod_info.so"


def test_already_commented_module_is_not_edited_again(tmp_path):
    conf = tmp_path / "httpd.conf"
    conf.write_text("#LoadModule status_module modules/mod_status.so\n")
    plan = build_fix_plan(_result([
        _issue("LoadModule", "status_module", "#LoadModule status_module",
               file=str(conf), line=1)]))
    assert plan.edits == []


# ── the bad token must not be matched inside the directive's name ──────

def test_value_is_replaced_in_the_arguments_not_the_directive_name(tmp_path):
    """"AllowOverride All" → "None" must not rewrite the "All" of the
    directive's own name ("NoneowOverride All")."""
    conf = tmp_path / "httpd.conf"
    conf.write_text("    AllowOverride All\n")
    plan = build_fix_plan(_result([
        _issue("AllowOverride", "All", "None", file=str(conf), line=1)]))
    assert plan.edits[0].new_line == "    AllowOverride None"


def test_substring_of_the_directive_name_alone_falls_back(tmp_path):
    """The bad token occurs only inside the directive name: there is no value
    to substitute, so the directive is rewritten with the good value."""
    conf = tmp_path / "httpd.conf"
    conf.write_text("ServerTokens\n")
    plan = build_fix_plan(_result([
        _issue("ServerTokens", "Tokens", "Prod", file=str(conf), line=1)]))
    assert plan.edits[0].new_line == "ServerTokens Prod"
