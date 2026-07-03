"""
tests/test_rag_document.py
--------------------------
Generic document ingestion for RAG (`--docs`): a service manual or CCSS/NISTIR
that is NOT a CIS benchmark is still chunked and retrievable, so it can ground
the Layer-3 LLM assessment. CIS benchmarks keep their structured parser.
"""

from __future__ import annotations

from config_assessment.build.rag import (
    BenchmarkIndex, parse_benchmark, parse_document)

MANUAL = """\
Apache HTTP Server Documentation

ServerTokens Directive
The ServerTokens directive controls the Server response header. Setting it to
Full exposes the full version and OS, which aids attackers in fingerprinting.
The recommended value is Prod.

TraceEnable Directive
The default TraceEnable on permits TRACE requests, which can be abused in
Cross-Site Tracing (XST) attacks. Set it to Off in production.
"""


def _write(tmp_path, text, name="manual.txt"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_generic_manual_is_chunked_by_heading(tmp_path):
    secs = parse_document(_write(tmp_path, MANUAL))
    titles = [s.title for s in secs]
    assert any("ServerTokens" in t for t in titles)
    assert any("TraceEnable" in t for t in titles)
    # Directives mentioned in a chunk are surfaced for retrieval.
    st = next(s for s in secs if "ServerTokens" in s.title)
    assert "ServerTokens" in st.directives


def test_non_cis_doc_falls_back_to_generic(tmp_path):
    # parse_benchmark on a doc with no 'Ensure …' sections must not return [];
    # it should route to the generic parser.
    secs = parse_benchmark(_write(tmp_path, MANUAL))
    assert secs, "generic doc produced no sections"
    assert all(s.section_id.startswith("doc-") for s in secs)


def test_manual_is_retrievable(tmp_path):
    idx = BenchmarkIndex(_write(tmp_path, MANUAL))
    hits = idx.query("TRACE cross-site tracing attack", top_k=1)
    assert hits and "TraceEnable" in hits[0].full_text


def test_long_chunk_is_split(tmp_path):
    # A heading followed by a very long body is split into windows, so a hit
    # stays focused rather than returning one giant section.
    big = "Reference Manual\n" + ("word " * 2000)
    secs = parse_document(_write(tmp_path, big), max_chars=1200)
    assert len(secs) >= 2
    assert all(len(s.description) <= 1200 for s in secs)


def test_cis_benchmark_still_uses_structured_parser(tmp_path):
    cis = (
        "1.1 Ensure ServerTokens is Set to 'Prod' (Automated)\n"
        "Profile Applicability:\n Level 1\n"
        "Description:\n Controls the Server header.\n"
        "Rationale:\n Discloses version.\n"
        "Audit:\n grep ServerTokens\n"
        "Remediation:\n Set ServerTokens Prod\n"
        "Default Value:\n Full\n"
        "References:\n CIS\n"
    )
    secs = parse_benchmark(_write(tmp_path, cis, "bench.txt"))
    assert secs
    # Structured parser assigns a numeric CIS id, not a generic doc- id.
    assert secs[0].section_id == "1.1"
