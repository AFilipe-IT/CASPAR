"""
tests/test_plugin_detector.py
------------------------------
Tests for the service detector (Peça 4).
"""

from __future__ import annotations

from unittest.mock import patch

from core.plugin_detector import detect_service_from_pdf, _from_filename
from core.llm_client import StubLLMClient


class TestFilename:
    def test_postgresql_from_filename(self):
        r = detect_service_from_pdf("CIS_PostgreSQL_13_Benchmark_v1.3.0.pdf")
        assert r is not None
        assert r["target_id"] == "postgresql"
        assert r["service_name"] == "PostgreSQL"
        assert r["config_format"] == "key_value"
        assert r["bind_directive"] == "listen_addresses"

    def test_mysql_from_filename(self):
        r = detect_service_from_pdf("/x/CIS_MySQL_8.0_Benchmark.pdf")
        assert r is not None and r["target_id"] == "mysql"

    def test_alias_postgres(self):
        assert _from_filename("cis_postgres_benchmark.pdf") == "postgresql"

    def test_alias_mariadb_to_mysql(self):
        assert _from_filename("CIS_MariaDB_Benchmark.pdf") == "mysql"

    def test_unknown_filename_returns_none(self):
        # No content, no LLM → None for an unknown service.
        with patch("core.plugin_detector._from_content", return_value=None):
            assert detect_service_from_pdf("CIS_Foobar_Benchmark.pdf") is None


class TestContent:
    def test_content_fallback_when_filename_fails(self):
        # Filename has no service token; content names PostgreSQL.
        with patch("core.plugin_detector._read_pdf_safe", create=True), \
             patch("core.rag._read_pdf",
                   return_value="CIS PostgreSQL 13 Benchmark\nThis document..."):
            r = detect_service_from_pdf("CIS_Database_Benchmark.pdf")
        assert r is not None and r["target_id"] == "postgresql"


class TestLLMFallback:
    def test_llm_used_when_filename_and_content_fail(self):
        llm = StubLLMClient(fixed_response="redis")
        with patch("core.plugin_detector._from_filename", return_value=None), \
             patch("core.plugin_detector._from_content", return_value=None), \
             patch("core.rag._read_pdf", return_value="some benchmark text"):
            r = detect_service_from_pdf("ambiguous.pdf", llm=llm)
        assert r is not None and r["target_id"] == "redis"

    def test_llm_unknown_returns_none(self):
        llm = StubLLMClient(fixed_response="unknown")
        with patch("core.plugin_detector._from_filename", return_value=None), \
             patch("core.plugin_detector._from_content", return_value=None):
            assert detect_service_from_pdf("ambiguous.pdf", llm=llm) is None

    def test_no_llm_no_match_returns_none(self):
        with patch("core.plugin_detector._from_filename", return_value=None), \
             patch("core.plugin_detector._from_content", return_value=None):
            assert detect_service_from_pdf("ambiguous.pdf") is None
