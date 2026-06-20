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

from core.benchmark_extractor import (
    try_extract_entry,
    classify_section,
    extract_bad_value_from_default,
)


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

_PDF = "plugins/apache_httpd/Benchmark.pdf"

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
    from core.rag import BenchmarkIndex
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
