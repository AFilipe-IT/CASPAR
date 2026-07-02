"""
tests/test_unknown_directives.py
--------------------------------
Unknown-directive detection: Layer 1 (surfacing), Layer 2 (heuristic triage),
and Layer 3 (LLM assessment, mocked). Layers 1-2 are deterministic and must
never touch scoring; Layer 3 is opt-in and produces candidates only.
"""

from __future__ import annotations

from config_assessment.core.models import Directive
from config_assessment.core.unknown_directives import (
    UnknownDirective, find_unknown_directives, triage_unknown,
    surface_and_triage, assess_unknown_with_llm)


def _d(name, value, **kw):
    return Directive(name=name, value=value, **kw)


# ── Layer 1: surfacing ─────────────────────────────────────────────────

def test_surfacing_finds_only_uncovered():
    dirs = [_d("ssl_protocols", "TLSv1.2"), _d("newthing", "x")]
    known = {"ssl_protocols", "server_tokens"}
    out = find_unknown_directives(dirs, known)
    assert [u.name for u in out] == ["newthing"]


def test_surfacing_is_case_insensitive():
    dirs = [_d("SSL_Protocols", "TLSv1.2")]
    out = find_unknown_directives(dirs, {"ssl_protocols"})
    assert out == []


def test_surfacing_dedups_same_name_value():
    dirs = [_d("x", "1"), _d("x", "1"), _d("x", "2")]
    out = find_unknown_directives(dirs, set())
    # (x,1) once, (x,2) once
    assert len(out) == 2


def test_surfacing_preserves_location():
    dirs = [_d("x", "1", source_file="/f.conf", line_number=9, context="http")]
    u = find_unknown_directives(dirs, set())[0]
    assert u.source_file == "/f.conf" and u.line_number == 9 and u.context == "http"


# ── Layer 2: heuristic triage ──────────────────────────────────────────

def test_triage_flags_wildcard_and_all_interfaces():
    assert triage_unknown(UnknownDirective("bind", "0.0.0.0:80")).suspicious
    assert triage_unknown(UnknownDirective("cors", "*")).suspicious


def test_triage_flags_777():
    assert triage_unknown(UnknownDirective("perm", "0777")).suspicious


def test_triage_flags_security_directive_turned_off():
    u = triage_unknown(UnknownDirective("proxy_ssl_verify", "off"))
    assert u.suspicious
    assert any("security-relevant" in s for s in u.risk_signals)


def test_triage_flags_risky_directive_name():
    u = triage_unknown(UnknownDirective("experimental_debug_mode", "on"))
    assert u.suspicious
    assert any("non-production" in s for s in u.risk_signals)


def test_triage_does_not_flag_benign_off():
    # 'off' on a non-security directive is not, by itself, suspicious.
    assert not triage_unknown(UnknownDirective("sendfile", "off")).suspicious


def test_triage_does_not_flag_benign_value():
    assert not triage_unknown(UnknownDirective("worker_processes", "4")).suspicious


def test_surface_and_triage_orders_suspicious_first():
    dirs = [_d("benign", "4"), _d("perm", "0777"), _d("also_benign", "x")]
    out = surface_and_triage(dirs, set())
    assert out[0].name == "perm"          # suspicious first
    assert all(not u.suspicious for u in out[1:])


# ── Layer 3: LLM assessment (mocked) ───────────────────────────────────

class _FakeLLM:
    def __init__(self, response):
        self._r = response
        self.prompts = []

    def complete(self, prompt, system=""):
        self.prompts.append(prompt)
        return self._r


class _FakeRAG:
    def __init__(self):
        self.queried = []

    def query(self, text, top_k=3):
        self.queried.append(text)
        return [type("S", (), {"title": "Ctx", "body": "some doc text"})()]


def test_assess_marks_misconfig_and_uses_rag():
    unknowns = [UnknownDirective("weird_flag", "on")]
    llm = _FakeLLM('{"is_misconfig": true, "estimated_score": 7.5, '
                   '"impact": "C:P I:N A:N", "justification": "opens X"}')
    rag = _FakeRAG()
    assess_unknown_with_llm(unknowns, service="nginx", llm=llm, rag_index=rag)
    u = unknowns[0]
    assert u.llm_is_misconfig is True
    assert u.llm_estimated_score == 7.5
    assert u.llm_impact == "C:P I:N A:N"
    assert rag.queried and "weird_flag" in rag.queried[0]     # RAG grounded
    assert "some doc text" in llm.prompts[0]                  # context injected


def test_assess_marks_benign():
    unknowns = [UnknownDirective("tuning_param", "5")]
    llm = _FakeLLM('{"is_misconfig": false, "justification": "just perf tuning"}')
    assess_unknown_with_llm(unknowns, service="nginx", llm=llm, rag_index=None)
    u = unknowns[0]
    assert u.llm_is_misconfig is False
    assert "perf" in u.llm_justification
    assert u.llm_estimated_score is None


def test_assess_survives_bad_llm_output():
    unknowns = [UnknownDirective("x", "1")]
    llm = _FakeLLM("not json at all")
    assess_unknown_with_llm(unknowns, service="nginx", llm=llm)
    assert unknowns[0].llm_is_misconfig is None      # untouched, no crash


def test_assess_works_without_rag():
    unknowns = [UnknownDirective("x", "1")]
    llm = _FakeLLM('{"is_misconfig": false, "justification": "ok"}')
    assess_unknown_with_llm(unknowns, service="nginx", llm=llm, rag_index=None)
    assert unknowns[0].llm_is_misconfig is False
    assert "(no documentation found)" in llm.prompts[0]
