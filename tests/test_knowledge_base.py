"""
tests/test_knowledge_base.py
----------------------------
Build-time RAG knowledge: a target's knowledge documents (benchmark, service
manual, shared CCSS/NISTIR) are DISCOVERED from disk and retrieved on every
scan — not passed as a runtime flag. `plugin add --manual` ingests a manual
(local file or URL) into the plugin dir so it joins that knowledge base.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import cli.main as m


def _plugin_tree(tmp_path):
    base = tmp_path / "plugins"
    pdir = base / "apache_httpd"       # on-disk uses underscore
    pdir.mkdir(parents=True)
    (pdir / "CIS_Apache.pdf").write_text("benchmark")
    (pdir / "manual_httpd.pdf").write_text("service manual")
    return base, pdir


def test_discovers_benchmark_and_manual_by_target_name(tmp_path):
    base, _ = _plugin_tree(tmp_path)
    with patch.object(m, "_plugin_dirs", lambda: [base]):
        # target NAME uses a hyphen; dir uses underscore — both must resolve.
        names = [p.name for p in m._find_knowledge_docs("apache-httpd")]
    assert "CIS_Apache.pdf" in names
    assert "manual_httpd.pdf" in names


def test_no_runtime_flag_needed(tmp_path):
    # The point of the model: knowledge is found from disk, so a scan needs no
    # --docs to have RAG context.
    base, _ = _plugin_tree(tmp_path)
    with patch.object(m, "_plugin_dirs", lambda: [base]):
        docs = m._find_knowledge_docs("apache-httpd")
    assert docs, "knowledge base should be non-empty without any flag"


def test_ingest_manual_from_local_file(tmp_path):
    src = tmp_path / "apache-docs.pdf"
    src.write_text("manual body")
    pdir = tmp_path / "plugins" / "apache_httpd"
    pdir.mkdir(parents=True)

    dest = m._ingest_manual(str(src), pdir)
    assert dest is not None and dest.exists()
    assert dest.parent == pdir
    assert "manual" in dest.name


def test_ingest_manual_from_url(tmp_path, monkeypatch):
    pdir = tmp_path / "plugins" / "nginx"
    pdir.mkdir(parents=True)

    class _Resp:
        def __init__(self): self._body = b"downloaded manual"
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, size=-1):
            # copyfileobj calls read(bufsize) in a loop and stops on b"".
            # Return the body once, then EOF — otherwise it loops forever.
            body, self._body = self._body, b""
            return body
    # _ingest_manual does `from urllib.request import urlopen` at call time,
    # which resolves the name from urllib.request — so patch it there.
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _Resp())

    dest = m._ingest_manual(
        "https://archive.apache.org/dist/httpd/docs/manual.pdf", pdir)
    assert dest is not None and dest.exists()
    assert dest.read_bytes() == b"downloaded manual"
    assert dest.name.startswith("manual_")


def test_ingest_manual_missing_file_is_graceful(tmp_path):
    pdir = tmp_path / "p"
    pdir.mkdir()
    assert m._ingest_manual(str(tmp_path / "nope.pdf"), pdir) is None


# --- fetch --then-install --manual: the manual must reach plugin_add ---------

from click.testing import CliRunner


def test_fetch_then_install_forwards_manual(tmp_path, monkeypatch):
    """`fetch --then-install --manual X` must hand X to plugin_add — otherwise
    services added via fetch could never get a manual (the gap this closes)."""
    bench = tmp_path / "nginx.xml"
    bench.write_text("<xccdf/>")

    class _Fetcher:
        def fetch(self, service, output): return str(bench)
        def list_available(self): return []
    monkeypatch.setattr(
        "config_assessment.fetch.benchmark_fetcher.BenchmarkFetcher",
        lambda *a, **k: _Fetcher())

    seen = {}
    # Replace plugin_add with a stub command so we assert what it received
    # without running the real (LLM/Ollama) install.
    import click
    @click.command()
    @click.option("--source")
    @click.option("--manual", default=None)
    @click.option("--dry-run", is_flag=True)
    @click.option("--no-llm", is_flag=True)
    @click.option("--yes", is_flag=True)
    @click.option("--verbose-list", is_flag=True)
    @click.option("--model", default=None)
    def _fake_add(source, manual, dry_run, no_llm, yes, verbose_list, model):
        seen["manual"] = manual
        seen["source"] = source
    monkeypatch.setattr(m, "plugin_add", _fake_add)

    res = CliRunner().invoke(
        m.plugin_fetch,
        ["nginx", "--then-install", "--manual", "https://x/docs.pdf"])
    assert res.exit_code == 0, res.output
    assert seen.get("manual") == "https://x/docs.pdf"
    assert seen.get("source") == str(bench)


def test_fetch_manual_without_then_install_warns(tmp_path, monkeypatch):
    """--manual without --then-install can't be ingested (no plugin yet), so we
    warn and fold it into the printed hint rather than silently dropping it."""
    bench = tmp_path / "nginx.xml"
    bench.write_text("<xccdf/>")

    class _Fetcher:
        def fetch(self, service, output): return str(bench)
    monkeypatch.setattr(
        "config_assessment.fetch.benchmark_fetcher.BenchmarkFetcher",
        lambda *a, **k: _Fetcher())

    res = CliRunner().invoke(
        m.plugin_fetch, ["nginx", "--manual", "https://x/docs.pdf"])
    assert res.exit_code == 0, res.output
    assert "--manual" in res.output and "https://x/docs.pdf" in res.output
