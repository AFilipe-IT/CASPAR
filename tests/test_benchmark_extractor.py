"""
tests/test_benchmark_extractor.py
----------------------------------
Regression tests for the heuristic CIS extractor (Peça 1).

The "verified ground truth" cases below were checked against the actual text of
the Apache CIS Benchmark PDF (not assumed defaults). They pin the 8/8 result so a
later change to the extractor can't silently regress it.

Also includes unit tests on synthetic Section objects (no PDF needed) for the
individual heuristics, and a coverage smoke test over the full benchmark.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from config_assessment.build.benchmark_extractor import (
    try_extract_entry,
    classify_section,
    extract_bad_value_from_default,
    llm_extract_entry,
    extract_all,
)
from config_assessment.build.llm_client import StubLLMClient


# ------------------------------------------------------------------ #
# Synthetic Section (no PDF) for unit-level heuristic tests           #
# ------------------------------------------------------------------ #

@dataclass
class _Sec:
    section_id: str = "x"
    title: str = ""
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    default_value: str = ""
    directives: list = field(default_factory=list)


class TestHeuristics:
    def test_p1_plus_p2_directive_value_line(self):
        s = _Sec(remediation="Add or modify the\nServerTokens Prod",
                 default_value="The default value is Full which provides detail.",
                 directives=["ServerTokens"])
        r = try_extract_entry(s)
        assert r.directive == "ServerTokens"
        assert r.bad_value == "Full"
        assert r.good_value == "Prod"
        assert r.rule_type == "value" and r.confidence == "high"
        assert r.method == "P1+P2"

    def test_numeric_default(self):
        s = _Sec(remediation="have a value of 10 or shorter.\nTimeout 10",
                 default_value="Timeout 60", directives=["Timeout"])
        r = try_extract_entry(s)
        assert (r.directive, r.bad_value, r.good_value) == ("Timeout", "60", "10")

    def test_default_equals_good_no_bad(self):
        # default already holds the recommended value → not a value misconfig.
        s = _Sec(remediation="have a value of On\nKeepAlive On",
                 default_value="KeepAlive On", directives=["KeepAlive"])
        r = try_extract_entry(s)
        assert r.directive == "KeepAlive"
        assert r.bad_value == ""
        assert r.confidence == "medium" and r.method == "P1-no-bad"

    def test_p2_default_only_when_no_clean_remediation_line(self):
        # Remediation is prose; the bad value lives in the Default Value.
        s = _Sec(remediation="1. Check OpenSSL version\n2. change to TLSv1.2",
                 default_value="SSLProtocol all", directives=["SSLProtocol"])
        r = try_extract_entry(s)
        assert r.directive == "SSLProtocol"
        assert r.bad_value == "all"
        assert r.method == "P2-default-only"

    def test_p3_absence_is_enabled(self):
        s = _Sec(remediation="Add a TraceEnable directive with a value of off.",
                 default_value="The TRACE method is enabled.",
                 directives=["TraceEnable"])
        r = try_extract_entry(s)
        assert r.rule_type == "absence" and r.method == "P3-enabled"

    def test_no_directive_is_skipped(self):
        # pdftotext noise: a 2-word line but no known directive → rejected.
        s = _Sec(remediation="Page 17", default_value="", directives=[])
        r = try_extract_entry(s)
        assert r.method == "no-directive"

    def test_noise_line_not_matched_when_directive_known(self):
        # "CIS Controls:" must not be taken as a directive value.
        s = _Sec(remediation="CIS Controls:\nServerTokens Prod",
                 default_value="The default value is Full.",
                 directives=["ServerTokens"])
        r = try_extract_entry(s)
        assert r.directive == "ServerTokens"  # the real line, not the noise


class TestClassify:
    def test_procedure_detected(self):
        s = _Sec(remediation="Run: # chmod o-rwx /var/log/httpd",
                 directives=["Group"])
        assert classify_section(s) == "procedure"

    def test_procedure_chsh_useradd(self):
        s = _Sec(remediation="# chsh -s /sbin/nologin apache", directives=["User"])
        assert classify_section(s) == "procedure"

    def test_value_default(self):
        s = _Sec(remediation="ServerTokens Prod",
                 default_value="Full", directives=["ServerTokens"])
        assert classify_section(s) == "value"


class TestExtractBadValue:
    def test_directive_value_form(self):
        assert extract_bad_value_from_default("Timeout 60", "Timeout") == "60"

    def test_default_is_prose(self):
        assert extract_bad_value_from_default(
            "The default value is Full which provides detail.", "ServerTokens"
        ) == "Full"

    def test_empty_default(self):
        assert extract_bad_value_from_default("", "Timeout") == ""


# ------------------------------------------------------------------ #
# Verified ground truth against the real Apache PDF (8/8)             #
# ------------------------------------------------------------------ #

_PDF = "config_assessment/plugins/apache_httpd/Benchmark.pdf"

# (section_id → expected bad_value), verified against the PDF text.
_GT_VERIFIED = {
    "8.1": "Full",   # ServerTokens default=Full
    "8.2": "",       # ServerSignature default=Off (already good)
    "9.1": "60",     # Timeout default=60
    "9.2": "",       # KeepAlive default=On (already good)
    "9.3": "",       # MaxKeepAliveRequests default=100 (recommended)
    "9.4": "5",      # KeepAliveTimeout default=5
    "5.8": "",       # TraceEnable → absence
    "7.4": "all",    # SSLProtocol default=all
}


@pytest.fixture(scope="module")
def sections():
    import os
    if not os.path.exists(_PDF):
        pytest.skip(f"{_PDF} not present")
    from config_assessment.build.rag import BenchmarkIndex
    idx = BenchmarkIndex(_PDF)
    return {s.section_id: s for s in idx.sections}


@pytest.mark.parametrize("sid,expected_bad", sorted(_GT_VERIFIED.items()))
def test_verified_ground_truth(sections, sid, expected_bad):
    s = sections.get(sid)
    if s is None:
        pytest.skip(f"section {sid} not in benchmark")
    r = try_extract_entry(s)
    assert (r.bad_value or "") == expected_bad, (
        f"[{sid}] expected bad_value={expected_bad!r}, got {r.bad_value!r} "
        f"(method={r.method})"
    )


class TestLLMExtraction:
    def test_llm_extracts_directive(self):
        s = _Sec(section_id="3.1.2", title="log_destination",
                 remediation="set log_destination to csvlog", directives=[])
        llm = StubLLMClient(fixed_response=(
            '{"extract": true, "directive": "log_destination", '
            '"bad_value": "stderr", "good_value": "csvlog", "rule_type": "value"}'))
        r = llm_extract_entry(s, llm)
        assert r is not None
        assert r.directive == "log_destination"
        assert r.bad_value == "stderr" and r.good_value == "csvlog"
        assert r.method == "LLM" and r.confidence == "medium"

    def test_llm_declines_procedure(self):
        s = _Sec(section_id="2.1", title="file permissions")
        llm = StubLLMClient(fixed_response='{"extract": false, "reason": "procedure"}')
        assert llm_extract_entry(s, llm) is None

    def test_llm_garbage_returns_none(self):
        s = _Sec(section_id="x", title="y")
        llm = StubLLMClient(fixed_response="no json here")
        assert llm_extract_entry(s, llm) is None

    def test_llm_json_with_preamble(self):
        s = _Sec(section_id="z", title="ssl")
        llm = StubLLMClient(fixed_response=(
            'Sure! Here is the JSON:\n'
            '{"extract": true, "directive": "ssl", "bad_value": "off", '
            '"good_value": "on", "rule_type": "value"}'))
        r = llm_extract_entry(s, llm)
        assert r is not None and r.directive == "ssl"


class TestExtractAll:
    class _Idx:
        def __init__(self, sections):
            self.sections = sections

    def test_high_confidence_kept_without_llm(self):
        s = _Sec(section_id="8.1", remediation="ServerTokens Prod",
                 default_value="The default value is Full.",
                 directives=["ServerTokens"])
        res = extract_all(self._Idx([s]), llm=None)
        assert len(res) == 1 and res[0].confidence == "high"

    def test_procedure_skipped(self):
        s = _Sec(section_id="3.2", remediation="# chmod 600 file", directives=["User"])
        res = extract_all(self._Idx([s]), llm=None)
        assert res == []

    def test_llm_used_for_non_high(self):
        # A section with no known directive (heuristic fails) → LLM resolves it.
        s = _Sec(section_id="3.1.2", title="log_destination",
                 remediation="set log_destination to csvlog", directives=[])
        llm = StubLLMClient(fixed_response=(
            '{"extract": true, "directive": "log_destination", '
            '"bad_value": "stderr", "good_value": "csvlog", "rule_type": "value"}'))
        res = extract_all(self._Idx([s]), llm=llm)
        assert len(res) == 1 and res[0].method == "LLM"

    def test_needs_review_without_llm(self):
        # Heuristic can't resolve, no LLM → needs_review (if a directive hint).
        s = _Sec(section_id="6.6", title="x", directives=["User"],
                 remediation="prose only", default_value="")
        res = extract_all(self._Idx([s]), llm=None)
        assert len(res) == 1 and res[0].needs_review is True

    def test_high_sorted_before_medium(self):
        high = _Sec(section_id="8.1", remediation="ServerTokens Prod",
                    default_value="The default value is Full.",
                    directives=["ServerTokens"])
        med = _Sec(section_id="3.1", title="ssl", remediation="set ssl", directives=[])
        llm = StubLLMClient(fixed_response=(
            '{"extract": true, "directive": "ssl", "bad_value": "off", '
            '"good_value": "on", "rule_type": "value"}'))
        res = extract_all(self._Idx([med, high]), llm=llm)
        assert res[0].confidence == "high"   # high first regardless of input order


def test_coverage_is_stable(sections):
    """Guard the reported coverage numbers (honest, per-category)."""
    counts = {"extractable": 0, "procedure": 0, "skip": 0}
    for s in sections.values():
        cat = classify_section(s)
        r = try_extract_entry(s)
        if cat == "procedure":
            counts["procedure"] += 1
        elif (r.confidence in ("high", "medium") and r.directive
              and r.rule_type in ("value", "absence")):
            counts["extractable"] += 1
        else:
            counts["skip"] += 1
    total = sum(counts.values())
    # Sanity bounds (not exact, to tolerate benign parser drift).
    assert total >= 80
    assert counts["extractable"] >= 12   # 15 today
    assert counts["procedure"] >= 10     # 13 today
