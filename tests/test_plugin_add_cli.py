"""
tests/test_plugin_add_cli.py
-----------------------------
Tests for the `ccss plugin add` command (Peça 5). The PDF index, extractor and
build are mocked — these tests exercise the command's control flow, not the LLM.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cli.main import cli
from core.benchmark_extractor import ExtractionResult


def _fake_index():
    secs = [SimpleNamespace(section_id="1.1", title="CIS PostgreSQL Benchmark")]
    return SimpleNamespace(sections=secs)


def _fake_candidates():
    return [
        ExtractionResult(directive="ssl", bad_value="off", good_value="on",
                         rule_type="value", confidence="high", section_id="6.2"),
        ExtractionResult(directive="log_connections", bad_value="off",
                         good_value="on", rule_type="value", confidence="medium",
                         method="LLM", section_id="3.2"),
    ]


@pytest.fixture
def pdf(tmp_path):
    p = tmp_path / "CIS_PostgreSQL_13_Benchmark_v1.3.0.pdf"
    p.write_bytes(b"%PDF-1.4 fake")
    return str(p)


def _patches():
    """Common patches: detector, index, extractor — no real PDF/LLM/build."""
    return [
        patch("core.plugin_detector.detect_service_from_pdf", return_value={
            "target_id": "postgresql", "service_name": "PostgreSQL",
            "config_format": "key_value",
            "config_paths": ["/etc/postgresql/16/main/postgresql.conf"],
            "config_filenames": ["postgresql.conf"], "bind_directive": "listen_addresses",
            "version_exposing": [],
        }),
        patch("core.rag.BenchmarkIndex", return_value=_fake_index()),
        patch("core.benchmark_extractor.extract_all", return_value=_fake_candidates()),
    ]


def test_dry_run_creates_no_files(pdf, tmp_path):
    ps = _patches()
    with ps[0], ps[1], ps[2], \
         patch("core.plugin_scaffolder.scaffold_plugin") as mock_scaffold:
        r = CliRunner().invoke(cli, ["plugin", "add", "-s", pdf, "--dry-run", "--no-llm"])
    assert r.exit_code == 0
    assert "[dry-run]" in r.output
    mock_scaffold.assert_not_called()           # no files


def test_unknown_service_warns(pdf):
    with patch("core.plugin_detector.detect_service_from_pdf", return_value=None), \
         patch("core.rag.BenchmarkIndex", return_value=_fake_index()), \
         patch("core.benchmark_extractor.extract_all", return_value=_fake_candidates()):
        # Decline the "proceed anyway" prompt → aborts.
        r = CliRunner().invoke(cli, ["plugin", "add", "-s", pdf, "--no-llm"],
                               input="n\n")
    assert "not recognised" in r.output.lower()
    assert "aborted" in r.output.lower()


def test_existing_plugin_warns_before_overwrite(pdf):
    ps = _patches()
    with ps[0], ps[1], ps[2], \
         patch("pathlib.Path.exists", return_value=True), \
         patch("core.plugin_scaffolder.scaffold_plugin") as mock_scaffold:
        # Decline the overwrite prompt.
        r = CliRunner().invoke(cli, ["plugin", "add", "-s", pdf, "--no-llm"],
                               input="n\n")
    assert "already exists" in r.output.lower()
    mock_scaffold.assert_not_called()


def test_yes_skips_confirmation(pdf, tmp_path):
    ps = _patches()
    fake_dir = tmp_path / "postgresql"
    fake_dir.mkdir()
    (fake_dir / "__init__.py").write_text("")
    with ps[0], ps[1], ps[2], \
         patch("core.plugin_scaffolder.scaffold_plugin", return_value=fake_dir) as mock_scaffold, \
         patch("core.generic_build.run_generic_build",
               return_value={"misconfigs": 2, "chains": 0, "narratives": 2}) as mock_build, \
         patch("pathlib.Path.exists", return_value=False):
        r = CliRunner().invoke(cli, ["plugin", "add", "-s", pdf, "--yes", "--no-llm"])
    # With --yes, no prompt; scaffolder and build are called.
    assert mock_scaffold.called
    assert mock_build.called
    assert "installed successfully" in r.output.lower()
