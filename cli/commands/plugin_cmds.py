"""
cli/commands/plugin_cmds.py — the `sca plugin` group: add / fetch.

Build-time entry points: installing a plugin from a benchmark (PDF CIS or
XCCDF STIG) and fetching benchmarks from public sources. The service manual
(--manual) is ingested here, at build time, into the plugin's RAG knowledge
base. Registered on the group in cli/main.py.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import click

from cli._discovery import _plugin_dirs
from cli._knowledge import _ingest_manual

logger = logging.getLogger("ccss")


@click.group("plugin")
def plugin_group():
    """Manage AEGIS plugins."""


@plugin_group.command("add")
@click.option("--source", "-s", required=True, type=click.Path(exists=True),
              help="CIS Benchmark PDF")
@click.option("--manual", "manual", default=None,
              help="Service manual to add to the target's RAG knowledge (a local "
                   "PDF/text path OR an http(s) URL, e.g. the Apache docs). "
                   "Ingested at build time; retrieved on every scan.")
@click.option("--dry-run", is_flag=True, help="Show spec without installing")
@click.option("--no-llm", is_flag=True,
              help="Heuristic extraction only (skip LLM for ambiguous)")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.option("--verbose", "verbose_list", is_flag=True,
              help="List all extracted controls, not just a preview")
@click.option("--model", "-m", default="qwen2.5:14b", show_default=True)
@click.pass_context
def plugin_add(ctx, source, manual, dry_run, no_llm, yes, verbose_list, model) -> None:
    """Install a new plugin from a CIS Benchmark PDF."""
    from pathlib import Path as _Path
    from config_assessment.build.plugin_detector import detect_service_from_pdf
    from config_assessment.build.benchmark_extractor import (
        extract_all, detect_source_format, XCCDFExtractor)
    from config_assessment.build.rag import BenchmarkIndex
    from config_assessment.build.plugin_scaffolder import PluginSpec, scaffold_plugin
    from config_assessment.build.llm_client import make_client

    src_name = _Path(source).name
    click.echo(f"\nAnalysing {src_name}...")

    llm = None if no_llm else make_client(
        backend="ollama", model=model, fallback_to_stub=True)

    src_format = detect_source_format(source)

    # ── XCCDF (DISA STIG) branch ───────────────────────────────────────
    if src_format == "xccdf":
        candidates, info, src_label, n_sections, sev_counts = _plugin_add_xccdf(
            source, src_name, llm, XCCDFExtractor)
    else:
        candidates, info, src_label, n_sections, sev_counts = _plugin_add_pdf(
            source, src_name, llm, detect_service_from_pdf, BenchmarkIndex,
            extract_all, yes)
        if candidates is None:   # user aborted at the "proceed anyway?" prompt
            return

    n_high = sum(1 for c in candidates if c.confidence == "high" and not c.needs_review)
    n_llm = sum(1 for c in candidates if c.method == "LLM")
    usable = [c for c in candidates if c.directive and not c.needs_review]
    value_rules = [c for c in usable if c.rule_type != "absence"]
    absence_rules = [c for c in usable if c.rule_type == "absence"]
    n_skipped = n_sections - len(usable)

    if src_format == "xccdf":
        click.echo(f"  High severity:     {n_high:3}")
    else:
        click.echo(f"  Heuristic (high):  {n_high:3}")
    if not no_llm:
        click.echo(f"  LLM (medium/low):  {n_llm:3}")
    click.echo(f"  Absence-rules:     {len(absence_rules):3}")
    click.echo(f"  Skipped:           {n_skipped:3}    ({'procedural/manual' if src_format == 'xccdf' else 'procedures/out-of-scope'})")
    click.echo(f"  Total:             {len(usable):3} controls\n")

    _plugin_add_finish(
        ctx, info, src_name, usable, value_rules, absence_rules,
        PluginSpec, scaffold_plugin, dry_run, yes, verbose_list, no_llm,
        source, model)

    # Add the service manual to the target's RAG knowledge base (build-time
    # ingestion). Placed in the plugin dir, it's retrieved on every future scan
    # via _find_knowledge_docs — no runtime flag needed.
    if manual and not dry_run:
        tid = info["target_id"]
        found = False
        # External dir first (the persistent volume in Docker) — a manual
        # written into an in-image plugin dir would be lost with --rm.
        for base in reversed(_plugin_dirs()):
            for name in {tid, tid.replace("-", "_"), tid.replace("_", "-")}:
                pdir = base / name
                if pdir.is_dir():
                    _ingest_manual(manual, pdir)
                    found = True
                    break
            if found:
                break
    return


def _plugin_add_xccdf(source, src_name, llm, XCCDFExtractor):
    """Identify the service and extract controls from a DISA STIG XCCDF file."""
    from pathlib import Path as _Path
    extractor = XCCDFExtractor()
    title, rules = extractor.load(source)

    sev = {"high": 0, "medium": 0, "low": 0}
    for r in rules:
        sev[r["severity"]] = sev.get(r["severity"], 0) + 1

    # Derive a STIG version label (e.g. "V2R2") from the filename, if present.
    import re as _re
    m = _re.search(r"V(\d+)R(\d+)", src_name)
    ver_label = f"V{m.group(1)}R{m.group(2)}" if m else ""
    click.echo(f"Source format: XCCDF (DISA STIG{(' ' + ver_label) if ver_label else ''})")

    # Service identity from the STIG title, skipping a leading vendor word
    # ("Apache Tomcat" → tomcat, "Oracle MySQL" → mysql).
    from config_assessment.build.benchmark_extractor import extract_service_name
    svc = extract_service_name(title) if title else _Path(source).stem.split("_")[1].lower()
    target_id = _re.sub(r"[^a-z0-9]+", "", svc) or "service"
    info = {
        "target_id": target_id, "service_name": target_id.capitalize(),
        "config_format": "key_value", "config_paths": [],
        "config_filenames": [f"{target_id}.conf"], "bind_directive": None,
        "version_exposing": [],
    }
    click.echo(f"Identified: {info['service_name']} "
               f"({info['config_format']} — {info['config_filenames'][0]})")
    click.echo(f"STIG rules: {len(rules)} ({sev['high']} high · "
               f"{sev['medium']} medium · {sev['low']} low)\n")

    click.echo("Extracting controls...")
    candidates = extractor.extract(source, llm_client=llm)
    return candidates, info, title, len(rules), sev


def _plugin_add_pdf(source, src_name, llm, detect_service_from_pdf,
                    BenchmarkIndex, extract_all, yes):
    """Identify the service and extract controls from a CIS Benchmark PDF."""
    from pathlib import Path as _Path
    click.echo("Source format: PDF (CIS Benchmark)")
    info = detect_service_from_pdf(source, llm=llm)
    if info is None:
        click.echo(click.style(
            "  Service not recognised in known-services list.", fg="yellow"))
        if not yes and not click.confirm(
                "  Proceed anyway with a generic key_value plugin?", default=False):
            click.echo("  Aborted.")
            return None, None, None, 0, {}
        # Fallback generic descriptor derived from the filename.
        stem = _Path(source).stem.lower().replace("cis_", "").split("_")[0] or "service"
        info = {
            "target_id": stem, "service_name": stem.capitalize(),
            "config_format": "key_value", "config_paths": [],
            "config_filenames": [f"{stem}.conf"], "bind_directive": None,
            "version_exposing": [],
        }
    click.echo(f"Identified: {info['service_name']} "
               f"({info['config_format']} — {info['config_filenames'][0]})")

    # ── Peça 1+3: index + extract ──────────────────────────────────────
    idx = BenchmarkIndex(source)
    click.echo(f"Indexing benchmark sections: {len(idx.sections)} sections found\n")
    click.echo("Extracting controls...")
    candidates = extract_all(idx, llm=llm)
    return candidates, info, src_name, len(idx.sections), {}


def _plugin_add_finish(ctx, info, src_name, usable, value_rules, absence_rules,
                       PluginSpec, scaffold_plugin, dry_run, yes, verbose_list,
                       no_llm, source, model):
    """Shared tail for both formats: preview → spec → confirm → scaffold → build."""
    from pathlib import Path as _Path

    if not usable:
        click.echo(click.style("  No controls extracted — nothing to install.",
                               fg="yellow"))
        return

    # ── preview ────────────────────────────────────────────────────────
    click.echo("Preview:")
    shown = usable if verbose_list else usable[:5]
    for c in shown:
        tag = "llm" if c.method == "LLM" else c.confidence
        click.echo(f"  {c.directive:22} {(c.bad_value or '?'):12} → "
                   f"{(c.good_value or '?'):16} §{c.section_id:8} [{tag}]")
    if not verbose_list and len(usable) > 5:
        click.echo(f"  ... ({len(usable) - 5} more — use --verbose to see all)")

    click.echo(f"\nPlugin: {info['target_id']} | Format: {info['config_format']} "
               f"| Config: {info['config_filenames'][0]}")

    # ── build the spec ─────────────────────────────────────────────────
    # Value rules drive ENTRIES (concrete bad→good). Absence rules (a directive
    # that must be present) go to absence_rules → ABSENCE_RULES in rules.py.
    entries = [(c.directive, c.bad_value, c.good_value, c.section_id) for c in value_rules]
    absence = [(c.directive, c.good_value, c.section_id) for c in absence_rules]
    spec = PluginSpec(
        service_name=info["service_name"], target_id=info["target_id"],
        config_format=info["config_format"], config_paths=info["config_paths"],
        config_filenames=info["config_filenames"],
        bind_directive=info["bind_directive"],
        version_exposing=info["version_exposing"], entries=entries,
        absence_rules=absence,
        benchmark_source=src_name.rsplit(".", 1)[0].replace("_", " "),
    )

    if dry_run:
        click.echo(f"  Value rules:       {len(entries):3}")
        click.echo(f"  Absence-rules:     {len(absence):3}")
        click.echo("  Chains (auto):     generated at build (chains.json bootstrap)")
        click.echo(click.style("\n[dry-run] No files created.", fg="cyan"))
        return

    # ── confirm ────────────────────────────────────────────────────────
    # Write to the external plugins dir ($AEGIS_PLUGINS_DIR, a mounted volume)
    # when set, so a fetched plugin survives a --rm container; otherwise use the
    # in-package dir. Either way it imports as config_assessment.plugins.<id>,
    # because the package __path__ spans both (see plugins/__init__.py).
    _external_plugins = os.environ.get("AEGIS_PLUGINS_DIR")
    plugins_dir = (_Path(_external_plugins) if _external_plugins
                   else _plugin_dirs()[0])
    target_dir = plugins_dir / info["target_id"]
    if target_dir.exists() and not yes:
        if not click.confirm(
                f"\nPlugin '{info['target_id']}' already exists — overwrite?",
                default=False):
            click.echo("  Aborted.")
            return
    if not yes and not click.confirm(
            f"\nGenerate plugin '{info['target_id']}'?", default=False):
        click.echo("  Aborted.")
        return

    # ── Peça 2: scaffold ───────────────────────────────────────────────
    click.echo("\nGenerating plugin files...")
    plugin_dir = scaffold_plugin(spec, plugins_dir, benchmark_pdf=source)
    for f in sorted(plugin_dir.iterdir()):
        click.echo(click.style(f"  ✓ plugins/{info['target_id']}/{f.name}", fg="green"))

    # ── build pipeline (Stages 1+2+3) ──────────────────────────────────
    click.echo("\nRunning build pipeline...")
    from config_assessment.build.generic_build import run_generic_build
    from config_assessment.plugins.apache_httpd.llm_pipeline import MisconfigEntry
    mentries = [MisconfigEntry(d, b, g, s, "", info["target_id"])
                for (d, b, g, s) in entries]
    stats = run_generic_build(
        target_id=info["target_id"], service_name=info["service_name"],
        benchmark_source=spec.benchmark_source,
        benchmark_path=str(plugin_dir / _Path(source).name),
        entries=mentries, db_path=ctx.obj["db_path"], model=model,
    )
    click.echo(click.style(
        f"\nPlugin '{info['target_id']}' installed successfully.", fg="green"))
    click.echo(f"  Misconfigs: {stats['misconfigs']} | Chains: {stats['chains']} "
               f"| Narratives: {stats['narratives']}/{stats['misconfigs']}")
    cf = info["config_paths"][0] if info["config_paths"] else info["config_filenames"][0]
    click.echo(f"\nRun: sca scan {cf}")


@plugin_group.command("manual")
@click.argument("target")
@click.argument("manual")
def plugin_manual(target, manual) -> None:
    """Add a service manual to an INSTALLED plugin's RAG knowledge base.

    \b
    The retroactive path: `plugin add --manual` ingests at install time, this
    ingests any time after. MANUAL is a local PDF/text path or an http(s) URL.
    The document lands in the plugin dir and is retrieved on every future
    scan --assess-unknown — no runtime flag needed.

      sca plugin manual nginx https://nginx.org/en/docs/dirindex.pdf
      sca plugin manual apache-httpd ./manual_apache.pdf
    """
    variants = {target, target.replace("-", "_"), target.replace("_", "-")}
    match = None
    for base in _plugin_dirs():
        for name in variants:
            if (base / name).is_dir():
                match = name
                break
        if match:
            break
    if match is None:
        installed = sorted({d.name for b in _plugin_dirs() if b.is_dir()
                            for d in b.iterdir() if d.is_dir()
                            and (d / "__init__.py").exists()})
        click.echo(click.style(
            f"No installed plugin '{target}'. Installed: {', '.join(installed) or '(none)'}",
            fg="red"), err=True)
        sys.exit(2)

    # Destination: the EXTERNAL plugins dir when set (a mounted volume in
    # Docker) — a built-in plugin's dir lives inside the image, so a manual
    # written there would vanish with the --rm container. _find_knowledge_docs
    # scans both dirs and merges, so retrieval works either way.
    external = os.environ.get("AEGIS_PLUGINS_DIR")
    pdir = (Path(external) / match) if external else None
    if pdir is None:
        for base in _plugin_dirs():
            if (base / match).is_dir():
                pdir = base / match
                break
    if _ingest_manual(manual, pdir) is None:
        sys.exit(1)
    click.echo(click.style(
        f"  It will ground 'scan --assess-unknown' for "
        f"'{target}' from now on.", dim=True))


@plugin_group.command("fetch")
@click.argument("service", required=False)
@click.option("--list", "list_only", is_flag=True,
              help="List services available for automatic fetch.")
@click.option("--search", "search_term", default=None,
              help="Fuzzy-search the catalog (e.g. --search postgres).")
@click.option("--output", "-o", default="/tmp", show_default=True,
              help="Destination directory for the downloaded benchmark "
                   "(default /tmp: the container mounts /workspace read-only).")
@click.option("--then-install", is_flag=True,
              help="Run 'plugin add' on the downloaded benchmark afterwards.")
@click.option("--manual", "manual", default=None,
              help="Service manual to add to the target's RAG knowledge (a local "
                   "PDF/text path OR an http(s) URL). Ingested at build time via "
                   "--then-install; retrieved on every scan.")
@click.option("--yes", "-y", is_flag=True,
              help="Skip confirmation prompts during --then-install.")
@click.option("--model", "-m", default="qwen2.5:14b", show_default=True,
              help="LLM model used by --then-install.")
@click.pass_context
def plugin_fetch(ctx, service, list_only, search_term, output, then_install,
                 manual, yes, model) -> None:
    """Download a benchmark from a public source and optionally install it.

    \b
    Discovery uses the catalog in config_assessment/fetch/catalog.json, which
    maps a service to a public STIG (via stigviewer.com). The download is a
    DISA-style XCCDF file that 'plugin add' consumes directly.

    \b
    See what's available:   sca plugin fetch --list
    Download + install:     sca plugin fetch nginx --then-install
    Download only:          sca plugin fetch nginx -o ~/benchmarks/
    """
    from config_assessment.fetch.benchmark_fetcher import BenchmarkFetcher, FetchError
    from config_assessment.reports.scan_features import search_catalog

    fetcher = BenchmarkFetcher()

    def _print_rows(rows, header_note=""):
        click.echo()
        click.echo(f"  {'SERVICE':<16}  {'BENCHMARK':<40}  SOURCE")
        click.echo("  " + "─" * 72)
        for r in rows:
            src = r["sources"][0] if r["sources"] else {"type": "-"}
            click.echo(f"  {r['service']:<16}  {r['service_name']:<40}  {src['type']}")
        click.echo()
        if header_note:
            click.echo(click.style(f"  {header_note}", dim=True))
            click.echo()

    if search_term:
        rows = search_catalog(fetcher.list_available(), search_term)
        if not rows:
            click.echo(click.style(
                f"No catalog match for '{search_term}'. "
                "Try 'sca plugin fetch --list'.", fg="yellow"), err=True)
            sys.exit(1)
        _print_rows(rows, f"{len(rows)} match(es) for '{search_term}'. "
                          "Fetch with: sca plugin fetch <service> --then-install")
        return

    if list_only:
        rows = fetcher.list_available()
        _print_rows(rows, f"{len(rows)} services. "
                          "Fetch with: sca plugin fetch <service> --then-install")
        return

    if not service:
        click.echo(click.style(
            "Error: give a SERVICE, or use --list to see what's available.",
            fg="red"), err=True)
        sys.exit(2)

    click.echo(f"\nFetching benchmark for '{service}'...")
    try:
        path = fetcher.fetch(service, output)
    except FetchError as exc:
        click.echo(click.style(f"  {exc}", fg="red"), err=True)
        sys.exit(1)

    click.echo(click.style(f"  ✓ Downloaded: {path}", fg="green"))

    if not then_install:
        hint = f"sca plugin add --source {path}"
        if manual:
            # --manual only takes effect during install; without --then-install
            # there's no plugin to ingest it into. Fold it into the printed hint.
            hint += f" --manual {manual}"
            click.echo(click.style(
                "  Note: --manual is ingested during install; add --then-install "
                "(or run the command below).", fg="yellow"), err=True)
        click.echo(f"\nInstall with: {click.style(hint, bold=True)}")
        click.echo()
        return

    # Hand off to the existing 'plugin add' flow on the downloaded file.
    # --then-install is a non-interactive pipeline (often run in the container
    # entrypoint), so always auto-confirm plugin add — otherwise it blocks on
    # the [y/N] "Generate plugin?" prompt with no TTY to answer it.
    click.echo()
    ctx.invoke(plugin_add, source=path, manual=manual, dry_run=False,
               no_llm=False, yes=True, verbose_list=False, model=model)
