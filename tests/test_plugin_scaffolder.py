"""
tests/test_plugin_scaffolder.py
--------------------------------
Tests for the deterministic plugin scaffolder (Peça 2b).
"""

from __future__ import annotations

import ast
import sys

import pytest

from config_assessment.build.plugin_scaffolder import PluginSpec, scaffold_plugin


def _spec(target_id="testservice", service="TestService"):
    return PluginSpec(
        service_name=service,
        target_id=target_id,
        config_format="key_value",
        config_paths=[f"/etc/{target_id}/{target_id}.conf"],
        config_filenames=[f"{target_id}.conf"],
        bind_directive="listen_address",
        version_exposing=[],
        entries=[],
        absence_rules=[],
        benchmark_source="CIS TestService Benchmark v1.0",
    )


def test_scaffold_creates_files(tmp_path):
    spec = _spec()
    plugin_dir = scaffold_plugin(spec, tmp_path / "plugins", benchmark_pdf=None)
    assert (plugin_dir / "__init__.py").exists()
    assert (plugin_dir / "parser.py").exists()
    assert (plugin_dir / "rules.py").exists()
    assert (plugin_dir / "build_testservice.py").exists()


def test_scaffold_generates_valid_python(tmp_path):
    spec = _spec()
    plugin_dir = scaffold_plugin(spec, tmp_path / "plugins", benchmark_pdf=None)
    for f in plugin_dir.glob("*.py"):
        ast.parse(f.read_text(encoding="utf-8"))  # no SyntaxError


def test_absence_rules_written_to_rules_py(tmp_path):
    spec = _spec()
    spec.absence_rules = [("ssl", "on", "6.1"), ("logging", "enabled", "7.2")]
    plugin_dir = scaffold_plugin(spec, tmp_path / "plugins", benchmark_pdf=None)

    rules_src = (plugin_dir / "rules.py").read_text(encoding="utf-8")
    ast.parse(rules_src)  # still valid Python

    # Exec it and assert ABSENCE_RULES carries both entries with the right shape.
    ns: dict = {}
    exec(compile(rules_src, "rules.py", "exec"), ns)
    rules = ns["ABSENCE_RULES"]
    assert {r["directive"] for r in rules} == {"ssl", "logging"}
    ssl = next(r for r in rules if r["directive"] == "ssl")
    assert ssl["good_value"] == "on"
    assert ssl["cis_section"] == "6.1"
    assert ssl["required_when"] == "always"


def test_no_absence_rules_leaves_empty_list(tmp_path):
    spec = _spec()  # absence_rules=[]
    plugin_dir = scaffold_plugin(spec, tmp_path / "plugins", benchmark_pdf=None)
    rules_src = (plugin_dir / "rules.py").read_text(encoding="utf-8")
    ns: dict = {}
    exec(compile(rules_src, "rules.py", "exec"), ns)
    assert ns["ABSENCE_RULES"] == []   # commented placeholder only → empty list


def test_scaffold_plugin_importable():
    """Scaffold into the real plugins/ package (the actual target), import it,
    confirm auto-registration, then clean up so no test pollution remains."""
    import importlib
    import shutil
    from pathlib import Path

    real_plugins = Path(__file__).resolve().parents[1] / "config_assessment" / "plugins"
    spec = _spec(target_id="scaffoldimp", service="ScaffoldImp")
    plugin_dir = scaffold_plugin(spec, real_plugins, benchmark_pdf=None)
    try:
        mod = importlib.import_module("config_assessment.plugins.scaffoldimp")
        from config_assessment.core.runtime import registered_plugins
        names = [p.metadata().name for p in registered_plugins()]
        assert "scaffoldimp" in names
    finally:
        # Remove the generated package and its module cache + registration.
        shutil.rmtree(plugin_dir, ignore_errors=True)
        for m in list(sys.modules):
            if m == "config_assessment.plugins.scaffoldimp" or m.startswith("config_assessment.plugins.scaffoldimp."):
                del sys.modules[m]
        try:
            from config_assessment.core import runtime
            runtime._REGISTRY[:] = [
                p for p in runtime._REGISTRY
                if p.metadata().name != "scaffoldimp"
            ]
        except Exception:
            pass


def test_metadata_fields_correct(tmp_path):
    spec = _spec(target_id="metacheck", service="Meta Check")
    plugin_dir = scaffold_plugin(spec, tmp_path / "plugins", benchmark_pdf=None)
    src = (plugin_dir / "__init__.py").read_text(encoding="utf-8")
    assert 'name="metacheck"' in src
    assert 'display_name="Meta Check"' in src
    assert "class MetaCheckPlugin" in src   # service name → CamelCase class


def test_entries_emitted_in_build(tmp_path):
    spec = _spec(target_id="withentries", service="WithEntries")
    spec.entries = [("ssl", "off", "on", "1.1")]
    plugin_dir = scaffold_plugin(spec, tmp_path / "plugins", benchmark_pdf=None)
    src = (plugin_dir / "build_withentries.py").read_text(encoding="utf-8")
    ast.parse(src)
    assert "MisconfigEntry('ssl', 'off', 'on', '1.1'" in src


def test_benchmark_pdf_copied(tmp_path):
    pdf = tmp_path / "bench.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake")
    spec = _spec(target_id="withpdf", service="WithPdf")
    plugin_dir = scaffold_plugin(spec, tmp_path / "plugins", benchmark_pdf=pdf)
    assert (plugin_dir / "bench.pdf").exists()
