"""
tests/test_llm_pipeline.py
---------------------------
Testes para o LLM pipeline e RAG.

Todos os testes correm sem Ollama — usam StubLLMClient ou respostas
pré-definidas. O objectivo é verificar:
  - RAG: parsing correcto do CIS Benchmark, retrieval relevante
  - Prompt: construção correcta, campos presentes
  - JSON validation: aceita válidos, rejeita inválidos, extrai de markdown
  - Pipeline: stub → Misconfiguration com campos correctos
  - Fallback: comportamento conservador quando LLM falha
  - LLM client: OllamaClient.is_available() False sem servidor
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from config_assessment.core.ccss import base_score
from config_assessment.core.db.database import Database
from config_assessment.build.llm_client import OllamaClient, StubLLMClient, make_client
from config_assessment.core.models import TargetMetadata
from config_assessment.build.rag import BenchmarkIndex, parse_benchmark
from config_assessment.plugins.apache_httpd import ApachePlugin
from config_assessment.plugins.apache_httpd.llm_pipeline import (
    LLMBuildPipeline,
    MisconfigEntry,
    _conservative_fallback,
    _extract_json,
    build_prompt,
    validate_metrics,
)
from config_assessment.plugins.apache_httpd.build_llm import ENTRIES
from pathlib import Path as _Path


def _find_benchmark() -> str:
    """Locate CIS Benchmark PDF — works locally and in sandbox."""
    _plugins = _Path(__file__).parent.parent / "config_assessment" / "plugins"
    candidates = [
        _plugins / "apache_httpd" / "Benchmark.pdf",
        _Path("/mnt/project/CIS_Apache_HTTP_Server_2_4_Benchmark_V2_3_0.pdf"),
        *sorted((_plugins / "apache_httpd").glob("*.pdf")),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return str(candidates[0])


BENCHMARK_PATH = _find_benchmark()


# ------------------------------------------------------------------ #
# RAG tests                                                            #
# ------------------------------------------------------------------ #

class TestRAG:

    @pytest.fixture(scope="class")
    def index(self):
        return BenchmarkIndex(BENCHMARK_PATH)

    def test_parses_correct_number_of_sections(self, index):
        # CIS Apache 2.4 v2.3.0 has 87 recommendation sections
        assert len(index.sections) >= 50  # conservative lower bound
        assert len(index.sections) <= 100

    def test_all_sections_have_id_and_title(self, index):
        for s in index.sections:
            assert s.section_id, f"Missing section_id: {s}"
            assert s.title, f"Missing title in section {s.section_id}"
            assert "." in s.section_id, f"Bad section_id format: {s.section_id}"

    def test_section_81_servertokens(self, index):
        s = index.get_by_section_id("8.1")
        assert s is not None
        assert "ServerTokens" in s.title or "ServerTokens" in s.directives
        assert len(s.rationale) > 50
        assert len(s.remediation) > 20

    def test_section_58_traceenable(self, index):
        s = index.get_by_section_id("5.8")
        assert s is not None
        assert "TRACE" in s.title.upper()

    def test_query_servertokens_returns_relevant(self, index):
        results = index.query("ServerTokens information disclosure version header", top_k=3)
        section_ids = [r.section_id for r in results]
        assert "8.1" in section_ids, f"Expected 8.1 in top-3, got {section_ids}"

    def test_query_traceenable_returns_58(self, index):
        results = index.query("TraceEnable HTTP TRACE cross-site cookie XST", top_k=3)
        section_ids = [r.section_id for r in results]
        assert "5.8" in section_ids, f"Expected 5.8 in top-3, got {section_ids}"

    def test_query_ssl_returns_tls_section(self, index):
        results = index.query("SSLProtocol weak TLS version POODLE", top_k=3)
        section_ids = [r.section_id for r in results]
        assert any(s.startswith("7.") for s in section_ids), f"Expected section 7.x, got {section_ids}"

    def test_get_by_directive_loadmodule(self, index):
        sections = index.get_by_directive("LoadModule")
        assert len(sections) >= 3
        section_ids = [s.section_id for s in sections]
        assert "2.3" in section_ids or "2.4" in section_ids

    def test_get_by_directive_nonexistent(self, index):
        sections = index.get_by_directive("NonExistentDirective")
        assert sections == []


# ------------------------------------------------------------------ #
# JSON extraction tests                                                #
# ------------------------------------------------------------------ #

class TestJSONExtraction:

    VALID_JSON = {
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "M", "grl": "H",
        "justification": "Test justification.",
        "recommendation": "Set directive X.",
        "cve_ids": []
    }

    def test_plain_json(self):
        result = _extract_json(json.dumps(self.VALID_JSON))
        assert result["ac"] == "L"

    def test_markdown_fenced_json(self):
        md = f"```json\n{json.dumps(self.VALID_JSON)}\n```"
        result = _extract_json(md)
        assert result is not None
        assert result["c"] == "P"

    def test_markdown_fence_no_lang(self):
        md = f"```\n{json.dumps(self.VALID_JSON)}\n```"
        result = _extract_json(md)
        assert result is not None

    def test_json_with_preamble(self):
        text = f"Here is my analysis:\n\n{json.dumps(self.VALID_JSON)}\n\nHope that helps."
        result = _extract_json(text)
        assert result is not None
        assert result["gel"] == "M"

    def test_invalid_returns_none(self):
        assert _extract_json("not json at all") is None
        assert _extract_json("") is None
        assert _extract_json("{ broken json ") is None


# ------------------------------------------------------------------ #
# Metric validation tests                                              #
# ------------------------------------------------------------------ #

class TestValidateMetrics:

    def test_valid_metrics_accepted(self):
        raw = {"ac":"L","c":"P","i":"N","a":"N","gel":"M","grl":"H",
               "justification":"OK","recommendation":"Fix it.","cve_ids":[]}
        m = validate_metrics(raw)
        assert m is not None
        assert m.ac == "L"
        assert m.c == "P"

    def test_invalid_ac_rejected(self):
        raw = {"ac":"X","c":"P","i":"N","a":"N","gel":"M","grl":"H",
               "justification":"OK","recommendation":"Fix.","cve_ids":[]}
        assert validate_metrics(raw) is None

    def test_invalid_cia_rejected(self):
        raw = {"ac":"L","c":"Z","i":"N","a":"N","gel":"M","grl":"H",
               "justification":"OK","recommendation":"Fix.","cve_ids":[]}
        assert validate_metrics(raw) is None

    def test_cve_ids_validated(self):
        raw = {"ac":"L","c":"P","i":"N","a":"N","gel":"M","grl":"H",
               "justification":"OK","recommendation":"Fix.",
               "cve_ids":["CVE-2004-2320","not-a-cve","CVE-2014-3566"]}
        m = validate_metrics(raw)
        assert m is not None
        assert "CVE-2004-2320" in m.cve_ids
        assert "not-a-cve" not in m.cve_ids

    def test_nd_values_accepted(self):
        raw = {"ac":"M","c":"P","i":"P","a":"N","gel":"ND","grl":"ND",
               "justification":"OK","recommendation":"Fix.","cve_ids":[]}
        m = validate_metrics(raw)
        assert m is not None
        assert m.gel == "ND"

    def test_uppercase_coercion(self):
        raw = {"ac":"l","c":"p","i":"n","a":"n","gel":"m","grl":"h",
               "justification":"OK","recommendation":"Fix.","cve_ids":[]}
        m = validate_metrics(raw)
        assert m is not None
        assert m.ac == "L"


# ------------------------------------------------------------------ #
# Prompt tests                                                         #
# ------------------------------------------------------------------ #

class TestPromptConstruction:

    @pytest.fixture(scope="class")
    def index(self):
        return BenchmarkIndex(BENCHMARK_PATH)

    def test_prompt_contains_directive(self, index):
        sec = index.get_by_section_id("8.1")
        prompt = build_prompt(sec, "ServerTokens", "Full")
        assert "ServerTokens" in prompt
        assert "Full" in prompt

    def test_prompt_contains_section_body(self, index):
        sec = index.get_by_section_id("5.8")
        prompt = build_prompt(sec, "TraceEnable", "On")
        assert len(prompt) > 500
        assert "TRACE" in prompt.upper() or "TraceEnable" in prompt

    def test_prompt_contains_few_shot_examples(self, index):
        sec = index.get_by_section_id("8.1")
        prompt = build_prompt(sec, "ServerTokens", "Full")
        assert "Example" in prompt
        assert '"ac"' in prompt

    def test_prompt_contains_metric_definitions(self, index):
        # Metric definitions are in _SYSTEM_PROMPT, not in build_prompt().
        # build_prompt() contains the section body + few-shot examples.
        # We verify the system prompt has the definitions separately.
        from config_assessment.plugins.apache_httpd.llm_pipeline import _SYSTEM_PROMPT
        assert "Access Complexity" in _SYSTEM_PROMPT
        assert "Confidentiality" in _SYSTEM_PROMPT
        # And build_prompt contains the section content
        sec = index.get_by_section_id("8.1")
        prompt = build_prompt(sec, "ServerTokens", "Full")
        assert "ServerTokens" in prompt
        assert len(prompt) > 500


# ------------------------------------------------------------------ #
# Conservative fallback tests                                          #
# ------------------------------------------------------------------ #

class TestConservativeFallback:

    def test_section_8_gives_medium_confidentiality(self):
        m = _conservative_fallback("8.1")
        assert m.c == "P"  # information leakage = partial

    def test_section_3_gives_complete_impact(self):
        m = _conservative_fallback("3.1")
        # Privilege issues should have high impact
        assert m.c in ("P", "C")
        assert m.i in ("P", "C")

    def test_section_9_gives_availability_impact(self):
        m = _conservative_fallback("9.1")
        assert m.a == "P"  # DoS = partial availability

    def test_unknown_section_returns_defaults(self):
        m = _conservative_fallback("99.1")
        assert m.ac in ("H", "M", "L")
        assert m.c in ("N", "P", "C")


# ------------------------------------------------------------------ #
# LLM client tests                                                     #
# ------------------------------------------------------------------ #

class TestLLMClient:

    def test_stub_always_available(self):
        client = StubLLMClient()
        assert client.is_available() is True

    def test_stub_returns_valid_json(self):
        client = StubLLMClient()
        response = client.complete("test prompt")
        parsed = json.loads(response)
        assert "ac" in parsed
        assert "justification" in parsed

    def test_stub_with_fixed_response(self):
        fixed = json.dumps({"ac":"H","c":"C","i":"C","a":"C","gel":"H","grl":"H",
                            "justification":"Test.","recommendation":"Fix.","cve_ids":[]})
        client = StubLLMClient(fixed_response=fixed)
        assert client.complete("anything") == fixed

    def test_ollama_not_available_when_no_server(self):
        client = OllamaClient(base_url="http://localhost:19999")  # wrong port
        assert client.is_available() is False

    def test_404_fails_fast_with_model_hint(self, monkeypatch):
        # A 404 means the server is up but the model isn't pulled. It must NOT
        # be retried (permanent client error) and the message must name the
        # model + how to fix it.
        import urllib.error
        import config_assessment.build.llm_client as lc

        calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", hdrs=None, fp=None)

        monkeypatch.setattr(lc.urllib.request, "urlopen", fake_urlopen)
        client = OllamaClient(model="qwen2.5:14b")

        with pytest.raises(RuntimeError) as exc:
            client.complete("hi")

        assert calls["n"] == 1                       # no retry on 404
        assert "qwen2.5:14b" in str(exc.value)        # names the model
        assert "ollama pull" in str(exc.value)        # tells you how to fix it

    def test_5xx_is_retried(self, monkeypatch):
        # A 5xx is transient → exhaust retries then raise the "unreachable" error.
        import urllib.error
        import config_assessment.build.llm_client as lc

        calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            raise urllib.error.HTTPError(
                req.full_url, 503, "Service Unavailable", hdrs=None, fp=None)

        monkeypatch.setattr(lc.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(lc.time, "sleep", lambda *_: None)  # no real backoff
        client = OllamaClient(model="qwen2.5:14b", max_retries=3)

        with pytest.raises(RuntimeError) as exc:
            client.complete("hi")

        assert calls["n"] == 3                        # retried up to max_retries
        assert "unreachable" in str(exc.value).lower()

    def test_make_client_returns_stub_on_unavailable(self):
        client = make_client(
            backend="ollama",
            base_url="http://localhost:19999",
            fallback_to_stub=True,
        )
        assert isinstance(client, StubLLMClient)

    def test_make_client_stub_backend(self):
        client = make_client(backend="stub")
        assert isinstance(client, StubLLMClient)


# ------------------------------------------------------------------ #
# End-to-end pipeline test (stub, no Ollama)                           #
# ------------------------------------------------------------------ #

class TestLLMPipelineEndToEnd:

    @pytest.fixture
    def populated_db(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        with Database(db_path) as db:
            meta = ApachePlugin().metadata()
            db.upsert_target(TargetMetadata(
                name=meta.name,
                display_name=meta.display_name,
                version=meta.version,
                benchmark_source=meta.benchmark_source,
            ))
        return db_path

    def test_pipeline_processes_all_entries(self, populated_db):
        pipeline = LLMBuildPipeline(
            benchmark_path=BENCHMARK_PATH,
            llm=StubLLMClient(),
        )
        with Database(populated_db) as db:
            results = pipeline.run(ENTRIES[:5], db)
        assert len(results) == 5

    def test_pipeline_writes_to_db(self, populated_db):
        pipeline = LLMBuildPipeline(
            benchmark_path=BENCHMARK_PATH,
            llm=StubLLMClient(),
        )
        with Database(populated_db) as db:
            pipeline.run(ENTRIES[:3], db)
            all_m = db.get_all_misconfigurations("apache-httpd")
        assert len(all_m) == 3

    def test_pipeline_dry_run_does_not_write(self, populated_db):
        pipeline = LLMBuildPipeline(
            benchmark_path=BENCHMARK_PATH,
            llm=StubLLMClient(),
        )
        with Database(populated_db) as db:
            pipeline.run(ENTRIES[:5], db, dry_run=True)
            all_m = db.get_all_misconfigurations("apache-httpd")
        assert len(all_m) == 0  # nothing written

    def test_misconfig_has_valid_scores(self, populated_db):
        pipeline = LLMBuildPipeline(
            benchmark_path=BENCHMARK_PATH,
            llm=StubLLMClient(),
        )
        with Database(populated_db) as db:
            results = pipeline.run(ENTRIES[:10], db)

        for r in results:
            assert 0.0 <= r.base_score <= 10.0
            assert 0.0 <= r.temporal_score <= r.base_score + 0.1
            assert r.ac in ("H", "M", "L")
            assert r.c in ("N", "P", "C")

    def test_pipeline_fallback_on_bad_llm(self, populated_db):
        """LLM que devolve JSON inválido → fallback conservador."""
        bad_llm = StubLLMClient(fixed_response="This is not JSON at all, sorry!")
        pipeline = LLMBuildPipeline(
            benchmark_path=BENCHMARK_PATH,
            llm=bad_llm,
        )
        entry = ENTRIES[0]  # ServerTokens=Full, section 8.1
        with Database(populated_db) as db:
            results = pipeline.run([entry], db)

        assert len(results) == 1
        r = results[0]
        # Should use conservative fallback for section 8 (information leakage)
        assert r.c == "P"
        assert r.base_score > 0.0

    def test_llm_response_with_markdown_fences(self, populated_db):
        """LLM que envolve JSON em markdown fences."""
        good_json = {"ac":"M","c":"P","i":"P","a":"N","gel":"M","grl":"H",
                     "justification":"TraceEnable allows XST.","recommendation":"Set Off.",
                     "cve_ids":["CVE-2004-2320"]}
        md_response = f"```json\n{json.dumps(good_json)}\n```"
        pipeline = LLMBuildPipeline(
            benchmark_path=BENCHMARK_PATH,
            llm=StubLLMClient(fixed_response=md_response),
        )
        trace_entry = next(e for e in ENTRIES if e.directive == "TraceEnable")
        with Database(populated_db) as db:
            results = pipeline.run([trace_entry], db)

        assert results[0].ac == "M"
        assert "CVE-2004-2320" in results[0].cves

    def test_all_entries_have_cis_sections(self):
        """Verificar que todos os ENTRIES têm cis_section preenchida."""
        for entry in ENTRIES:
            assert entry.cis_section, f"Missing cis_section for {entry.directive}={entry.bad_value}"
            assert "." in entry.cis_section, f"Bad cis_section format: {entry.cis_section}"
