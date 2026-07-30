"""
cli/_knowledge.py — the target's build-time RAG knowledge base.

Knowledge (benchmark + service manual + shared NISTIR/CCSS reference) is
ingested ONCE at build time (`plugin add --manual`) and DISCOVERED from disk
on every scan — never passed as a runtime flag. Layer 3 (--assess-unknown)
retrieves from it. Split out of cli/main.py (which re-exports these names).
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

from cli._discovery import _plugin_dirs

logger = logging.getLogger("ccss")


def _find_benchmark_file(target_name: str) -> Path | None:
    """Locate the benchmark PDF/XML shipped inside a plugin directory, so it can
    ground the --assess-unknown RAG. Best-effort: returns the first match."""
    for base in _plugin_dirs():
        pdir = base / target_name
        if not pdir.is_dir():
            continue
        for pat in ("*.pdf", "*.xml"):
            hits = sorted(pdir.glob(pat))
            if hits:
                return hits[0]
    return None


def _find_knowledge_docs(target_name: str) -> list[Path]:
    """Every knowledge document available to the RAG for this target, discovered
    from disk — no runtime flag needed. This is the build-time-knowledge model:
    you drop the docs next to the plugin (or ship the shared CCSS reference) and
    they are always retrievable at assessment time.

    Collected, de-duplicated, in priority order:
      1. the plugin's own docs — benchmark, service manual, any PDF/XML/txt in
         `plugins/<target>/` (and a `docs/` subdir if present);
      2. the shared CCSS reference (NISTIR 7502) at the project root, relevant
         to every target.
    """
    docs: list[Path] = []
    seen: set[str] = set()

    def _add(p: Path) -> None:
        rp = str(p.resolve())
        if p.is_file() and rp not in seen:
            seen.add(rp)
            docs.append(p)

    # The plugin dir on disk may use '_' where the target name uses '-'
    # (apache-httpd → apache_httpd), so try both spellings.
    variants = {target_name, target_name.replace("-", "_"),
                target_name.replace("_", "-")}
    for base in _plugin_dirs():
        for name in variants:
            pdir = base / name
            if not pdir.is_dir():
                continue
            # A PDF ingested with a .md sidecar (extracted at build time) is
            # indexed via the sidecar — same content, better chunks, and no
            # double-indexing of the pair.
            md_stems = {p.stem for pat in ("*.md", "docs/*.md")
                        for p in pdir.glob(pat)}
            for pat in ("*.md", "*.pdf", "*.xml", "*.txt",
                        "docs/*.md", "docs/*.pdf", "docs/*.txt"):
                for hit in sorted(pdir.glob(pat)):
                    if hit.suffix.lower() == ".pdf" and hit.stem in md_stems:
                        continue
                    _add(hit)

    # Shared CCSS reference (NISTIR 7502) — applies to every service.
    for root in {Path.cwd(), Path(__file__).resolve().parent.parent}:
        for name in ("nistir7502.pdf", "documentosccss/nistir7502.pdf"):
            _add(root / name)

    return docs


class _CombinedRAG:
    """Query several RAG indexes and merge their top sections. Lets
    --assess-unknown draw context from the benchmark AND user-supplied --docs."""

    def __init__(self, indexes: list) -> None:
        self._indexes = indexes

    def query(self, text: str, top_k: int = 3) -> list:
        out: list = []
        for idx in self._indexes:
            try:
                out.extend(idx.query(text, top_k=top_k))
            except Exception:
                continue
        return out[: top_k * max(1, len(self._indexes))]


def _assess_unknown_directives(result, docs_path: str | None) -> None:
    """Layer 3: build a RAG index over this target's KNOWLEDGE BASE and run the
    LLM over the surfaced unknown directives. Mutates result.unknown_directives.
    Degrades gracefully — any failure just leaves the LLM fields empty.

    The RAG context is the knowledge already gathered for the target: its
    benchmark, service manual, and the shared CCSS reference — discovered from
    disk, not passed each run. --docs only ADDS an extra document on top."""
    from config_assessment.build.llm_client import make_client
    from config_assessment.build.rag import BenchmarkIndex
    from config_assessment.core.unknown_directives import assess_unknown_with_llm

    sources = _find_knowledge_docs(result.target_name)
    if docs_path:
        sources.append(Path(docs_path))   # optional extra, added on top

    indexes = []
    for src in sources:
        if src and src.exists():
            try:
                indexes.append(BenchmarkIndex(str(src)))
            except Exception as exc:
                logger.warning("Could not index %s for RAG: %s", src, exc)
    rag = _CombinedRAG(indexes) if indexes else None

    click.echo(click.style(
        f"  Assessing {len(result.unknown_directives)} uncovered directive(s) "
        f"with LLM{f' + RAG ({len(indexes)} docs)' if rag else ''} "
        f"(non-deterministic)…", dim=True))
    llm = make_client(backend="ollama", fallback_to_stub=True)
    assess_unknown_with_llm(
        result.unknown_directives, service=result.target_name,
        llm=llm, rag_index=rag)


def _pdf_to_markdown(pdf: Path, out_md: Path) -> bool:
    """Extract a PDF's text to a markdown sidecar via `pdftotext -layout`
    (deterministic — no LLM rewrites the knowledge base). The .md is what the
    RAG indexes (better chunks) and what a human audits: you can READ exactly
    what grounds the LLM. Best-effort; returns False when pdftotext is absent."""
    import shutil as _sh
    import subprocess
    if not _sh.which("pdftotext"):
        return False
    try:
        subprocess.run(["pdftotext", "-layout", str(pdf), str(out_md)],
                       timeout=120, check=True, capture_output=True)
        return out_md.is_file() and out_md.stat().st_size > 0
    except (OSError, subprocess.SubprocessError):
        return False


def _ingest_manual(manual: str, plugin_dir: Path) -> Path | None:
    """Copy/download a service manual into the plugin dir, so it becomes part of
    the target's RAG knowledge base at BUILD time (retrieved on every scan, not
    passed each run). `manual` is a local path OR an http(s) URL to a PDF/text
    (e.g. https://archive.apache.org/dist/httpd/docs/…). A PDF also gets a
    readable .md sidecar (extracted once, here — build-time), which the RAG
    prefers over re-reading the PDF every scan. Best-effort."""
    import shutil
    from urllib.parse import urlparse
    from urllib.request import urlopen, Request

    plugin_dir.mkdir(parents=True, exist_ok=True)
    if manual.startswith(("http://", "https://")):
        fname = Path(urlparse(manual).path).name or "manual.pdf"
        dest = plugin_dir / f"manual_{fname}"
        try:
            req = Request(manual, headers={"User-Agent": "aegis-plugin-add"})
            with urlopen(req, timeout=30) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
        except Exception as exc:
            click.echo(click.style(
                f"  Could not download manual from {manual}: {exc}", fg="yellow"),
                err=True)
            return None
    else:
        src = Path(manual)
        if not src.exists():
            click.echo(click.style(f"  Manual not found: {manual}", fg="yellow"),
                       err=True)
            return None
        dest = plugin_dir / f"manual_{src.name}"
        shutil.copy(src, dest)

    click.echo(f"  Manual saved: {click.style(str(dest), fg='cyan')}")
    if dest.suffix.lower() == ".pdf":
        sidecar = dest.with_suffix(".md")
        if _pdf_to_markdown(dest, sidecar):
            click.echo(f"  Extracted:    {click.style(str(sidecar), fg='cyan')}"
                       + click.style("  (what the RAG reads — auditable)", dim=True))
    return dest
