"""
tests/test_fetch.py
-------------------
Tests for `caspar plugin fetch` (config_assessment.fetch.benchmark_fetcher and
the CLI command). The network is always mocked — no test hits stigviewer.com —
so these exercise the catalog lookup, JSON→XCCDF conversion, file naming, error
handling and the CLI wiring.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cli.main import cli
from config_assessment.build.benchmark_extractor import (
    XCCDFExtractor, detect_source_format, extract_service_name)
from config_assessment.fetch.benchmark_fetcher import (
    BenchmarkFetcher, FetchError, _stig_json_to_xccdf, _clean_version_label)


# ── fixtures ───────────────────────────────────────────────────────────

def _fake_stig_json(title="F5 NGINX Security Technical Implementation Guide",
                    version="V1R2"):
    """A minimal stigviewer /export/json payload with two rules."""
    return {
        "stig": {
            "title": title,
            "version": version,
            "groups": [
                {
                    "groupId": "V-100001",
                    "ruleId": "SV-100001r1_rule",
                    "ruleSeverity": "high",
                    "ruleVersion": "NGNX-APP-000010",
                    "ruleTitle": "NGINX must limit concurrent sessions.",
                    "ruleFixText": "Set worker_connections to 512 in nginx.conf.",
                    "ruleCheckContent": "Run: nginx -T | grep worker_connections",
                },
                {
                    "groupId": "V-100002",
                    "ruleId": "SV-100002r1_rule",
                    "ruleSeverity": "medium",
                    "ruleTitle": "NGINX must disable <server_tokens> & escape \"quotes\".",
                    "ruleFixText": "Set server_tokens off; in the http block.",
                    "ruleCheckContent": "Verify server_tokens is off.",
                },
            ],
        }
    }


@pytest.fixture
def fetcher():
    return BenchmarkFetcher()


# ── catalog / listing ──────────────────────────────────────────────────

def test_catalog_loads_and_lists_services(fetcher):
    rows = fetcher.list_available()
    services = {r["service"] for r in rows}
    assert {"nginx", "mysql", "postgresql"} <= services
    # Documentation keys (leading underscore) must be filtered out.
    assert not any(r["service"].startswith("_") for r in rows)
    # Each service exposes at least one source with a type.
    for r in rows:
        assert r["sources"] and r["sources"][0]["type"]


def test_unknown_service_raises(fetcher, tmp_path):
    with pytest.raises(FetchError, match="Unknown service"):
        fetcher.fetch("does-not-exist", tmp_path)


# ── JSON → XCCDF conversion ────────────────────────────────────────────

def test_json_to_xccdf_is_wellformed_and_extractable():
    payload = _fake_stig_json()
    xml = _stig_json_to_xccdf(
        payload["stig"]["title"], "V1R2", payload["stig"]["groups"])
    # Parses and carries both rules with their severities.
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml)
    ns = {"x": "http://checklists.nist.gov/xccdf/1.1"}
    rules = root.findall(".//x:Rule", ns)
    assert len(rules) == 2
    assert {r.get("severity") for r in rules} == {"high", "medium"}


def test_special_characters_are_escaped():
    # The second rule's title contains <, > and quotes — must not break XML.
    payload = _fake_stig_json()
    xml = _stig_json_to_xccdf("T", "V1R1", payload["stig"]["groups"])
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml)  # raises if escaping is wrong
    titles = [t.text for t in root.iter() if t.tag.endswith("title")]
    assert any("server_tokens" in (t or "") for t in titles)


@pytest.mark.parametrize("raw,expected", [
    ("V1R2", "V1R2"), ("V 2 R 6", "V2R6"), ("v3r1", "V3R1"), ("", ""),
])
def test_clean_version_label(raw, expected):
    assert _clean_version_label(raw) == expected


# ── fetch() end-to-end (network mocked) ────────────────────────────────

def test_fetch_writes_extractable_xccdf(fetcher, tmp_path):
    payload = json.dumps(_fake_stig_json())
    with patch("config_assessment.fetch.benchmark_fetcher._http_get",
               return_value=payload):
        path = fetcher.fetch("nginx", tmp_path)

    # File is on disk, detected as XCCDF, and named with the STIG version.
    assert path.endswith(".xml")
    assert "V1R2" in path
    assert detect_source_format(path) == "xccdf"

    # And it round-trips through the real extractor that plugin_add uses.
    title, rules = XCCDFExtractor().load(path)
    assert len(rules) == 2
    # The canonical service name (not the "F5" vendor) drives the plugin id.
    assert extract_service_name(title) == "nginx"


def test_fetch_falls_back_across_sources(tmp_path):
    """A failing first source should not abort if a later source succeeds."""
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({
        "nginx": {"service_name": "NGINX", "sources": [
            {"type": "stigviewer", "slug": "broken"},
            {"type": "stigviewer", "slug": "works"},
        ]}
    }))
    f = BenchmarkFetcher(catalog_path=catalog)

    calls = {"n": 0}

    def fake_get(url, binary=False):
        calls["n"] += 1
        if "broken" in url:
            raise FetchError("HTTP 500")
        return json.dumps(_fake_stig_json())

    with patch("config_assessment.fetch.benchmark_fetcher._http_get",
               side_effect=fake_get):
        path = f.fetch("nginx", tmp_path)
    assert calls["n"] == 2  # tried broken, then works
    assert detect_source_format(path) == "xccdf"


def test_fetch_all_sources_fail(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({
        "nginx": {"sources": [{"type": "stigviewer", "slug": "x"}]}}))
    f = BenchmarkFetcher(catalog_path=catalog)
    with patch("config_assessment.fetch.benchmark_fetcher._http_get",
               side_effect=FetchError("HTTP 404")):
        with pytest.raises(FetchError, match="All sources failed"):
            f.fetch("nginx", tmp_path)


def test_empty_stig_raises(fetcher, tmp_path):
    empty = json.dumps({"stig": {"title": "X", "groups": []}})
    with patch("config_assessment.fetch.benchmark_fetcher._http_get",
               return_value=empty):
        with pytest.raises(FetchError, match="All sources failed"):
            fetcher.fetch("nginx", tmp_path)


# ── CLI wiring ─────────────────────────────────────────────────────────

def test_cli_list():
    res = CliRunner().invoke(cli, ["plugin", "fetch", "--list"])
    assert res.exit_code == 0
    assert "nginx" in res.output
    assert "SERVICE" in res.output


def test_cli_requires_service_or_list():
    res = CliRunner().invoke(cli, ["plugin", "fetch"])
    assert res.exit_code == 2
    assert "--list" in res.output


def test_cli_download_only(tmp_path):
    payload = json.dumps(_fake_stig_json())
    with patch("config_assessment.fetch.benchmark_fetcher._http_get",
               return_value=payload):
        res = CliRunner().invoke(
            cli, ["plugin", "fetch", "nginx", "-o", str(tmp_path)])
    assert res.exit_code == 0
    assert "Downloaded" in res.output
    assert "plugin add --source" in res.output  # hint for the manual next step
    assert list(tmp_path.glob("*.xml"))


def test_cli_unknown_service_exits_1(tmp_path):
    res = CliRunner().invoke(
        cli, ["plugin", "fetch", "nope", "-o", str(tmp_path)])
    assert res.exit_code == 1
    assert "Unknown service" in res.output


def test_cli_then_install_invokes_plugin_add(tmp_path):
    """--then-install should hand the downloaded file to plugin add."""
    payload = json.dumps(_fake_stig_json())
    seen = {}

    def fake_add(source, dry_run, no_llm, yes, verbose_list, model):
        seen["source"] = source

    with patch("config_assessment.fetch.benchmark_fetcher._http_get",
               return_value=payload), \
         patch("cli.main.plugin_add.callback", side_effect=fake_add):
        res = CliRunner().invoke(
            cli, ["plugin", "fetch", "nginx", "-o", str(tmp_path),
                  "--then-install", "--yes"])
    assert res.exit_code == 0, res.output
    assert seen.get("source", "").endswith(".xml")
