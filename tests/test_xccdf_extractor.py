"""
tests/test_xccdf_extractor.py
------------------------------
XCCDF (DISA STIG) support: format auto-detection + XCCDFExtractor parsing the
Redis STIG. The LLM path is environment-dependent, so extraction-shape tests use
a StubLLMClient with a fixed JSON response.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from config_assessment.build.benchmark_extractor import (
    detect_source_format,
    extract_service_name,
    XCCDFExtractor,
    ExtractionResult,
)
from config_assessment.build.llm_client import StubLLMClient


_REDIS_STIG = Path("sources/stigs/U_Redis_Enterprise_6-x_STIG_V2R2_Manual-xccdf.xml")

pytestmark = pytest.mark.skipif(
    not _REDIS_STIG.exists(), reason="Redis STIG XML not present")


def test_detect_xccdf_format_from_extension():
    assert detect_source_format(str(_REDIS_STIG)) == "xccdf"


def test_detect_pdf_format():
    assert detect_source_format("sources/benchmarks/CIS_PostgreSQL_13.pdf") == "pdf"
    assert detect_source_format("whatever.PDF") == "pdf"
    assert detect_source_format("notes.txt") == "unknown"


def test_xccdf_parses_redis_stig_rules():
    title, rules = XCCDFExtractor().load(str(_REDIS_STIG))
    assert "Redis" in title
    assert rules
    r0 = rules[0]
    assert set(r0) >= {"id", "severity", "title", "fixtext", "check_content"}
    assert r0["id"].startswith("SV-")
    assert r0["fixtext"]  # fixtext text was collected


def test_xccdf_rule_count_matches_xml():
    # The Redis V2R2 STIG has exactly 71 Rule elements.
    _, rules = XCCDFExtractor().load(str(_REDIS_STIG))
    assert len(rules) == 71


def test_xccdf_severity_mapping():
    _, rules = XCCDFExtractor().load(str(_REDIS_STIG))
    sev = {"high": 0, "medium": 0, "low": 0}
    for r in rules:
        assert r["severity"] in sev          # only known severities
        sev[r["severity"]] += 1
    # Known distribution for this STIG: 11 high · 58 medium · 2 low.
    assert sev == {"high": 11, "medium": 58, "low": 2}


def test_xccdf_produces_extracted_spec_format():
    # With a stub LLM returning a valid extraction, every rule yields an
    # ExtractionResult with the same fields extract_all() produces.
    stub = StubLLMClient(fixed_response=(
        '{"extract": true, "directive": "maxclients", "bad_value": "10000", '
        '"good_value": "100", "rule_type": "value"}'))
    results = XCCDFExtractor().extract(str(_REDIS_STIG), llm_client=stub)
    assert results
    assert all(isinstance(r, ExtractionResult) for r in results)
    r = results[0]
    assert r.directive == "maxclients"
    assert r.method == "LLM"
    assert r.section_id.startswith("SV-")     # section_id carries the STIG rule id
    assert r.confidence in ("high", "medium", "low")


def test_xccdf_no_llm_marks_needs_review():
    # Without an LLM, fixtext cannot be resolved deterministically → needs_review.
    results = XCCDFExtractor().extract(str(_REDIS_STIG), llm_client=None)
    assert results and all(r.needs_review for r in results)


@pytest.mark.parametrize("title,expected", [
    ("Apache Tomcat Application Server 9", "tomcat"),
    ("Oracle MySQL Enterprise Edition 8.0", "mysql"),
    ("Microsoft IIS 10.0 Server", "iis"),
    ("VMware vSphere ESXi 7.0", "vsphere"),
    ("Red Hat Enterprise Linux 9", "hat"),       # "red" skipped → "hat"
    ("Redis Enterprise 6.x", "redis"),            # not a vendor → first word
    ("PostgreSQL 13", "postgresql"),
    ("", "unknown"),
])
def test_extract_service_name_skips_vendor(title, expected):
    assert extract_service_name(title) == expected


def test_xccdf_absence_rule_from_stub():
    stub = StubLLMClient(fixed_response=(
        '{"extract": true, "directive": "tls", "bad_value": "", '
        '"good_value": "on", "rule_type": "absence"}'))
    results = XCCDFExtractor().extract(str(_REDIS_STIG), llm_client=stub)
    assert results and all(r.rule_type == "absence" for r in results)
