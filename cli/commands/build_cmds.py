"""
cli/commands/build_cmds.py — build-time commands: build, fetch-exploits, refresh.

Everything here may use the network and/or an LLM — the heavy work that runs
once so scans stay offline. Registered on the group in cli/main.py.
"""

from __future__ import annotations

import sys
from typing import Callable

import click

from cli._discovery import _discover_plugins


def run_build_job(benchmark: str, model: str, ollama_url: str, target: str,
                   dry_run: bool, db_path: str,
                   emit: Callable[[str], None]) -> int:
    """The `build` command's actual work, factored out so both the CLI
    command (emit=click.echo) and the REST job runner (emit=db.append_job_log)
    drive the exact same logic. Returns the misconfiguration count; raises on
    an unknown target so callers can report failure uniformly."""
    if target == "apache-httpd":
        from config_assessment.plugins.apache_httpd.build_llm import run_build
    elif target == "nginx":
        from config_assessment.plugins.nginx.build_nginx import run_build
    else:
        raise ValueError(f"Target '{target}' not implemented.")

    emit(f"  Building '{target}' with {model}...")
    count = run_build(
        benchmark_path=benchmark,
        db_path=db_path,
        model=model,
        ollama_url=ollama_url,
        dry_run=dry_run,
    )
    emit(f"  Concluído: {count} misconfigurations.")
    return count


@click.command("build")
@click.option("--benchmark", "-b", required=True)
@click.option("--model", "-m", default="qwen2.5:14b", show_default=True)
@click.option("--ollama-url", default="http://localhost:11434", show_default=True)
@click.option("--target", "-t", default="apache-httpd", show_default=True)
@click.option("--dry-run", is_flag=True)
@click.pass_context
def build(ctx, benchmark, model, ollama_url, target, dry_run) -> None:
    """Populate the database using a local LLM (Ollama).

    \b
    Example:
      caspar build --benchmark plugins/apache_httpd/Benchmark.pdf
    """
    try:
        run_build_job(benchmark, model, ollama_url, target, dry_run,
                      ctx.obj["db_path"], emit=click.echo)
    except ValueError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)


@click.command(name="fetch-exploits")
@click.option("--product", "-p", default=None,
              help="Target product (e.g. apache-httpd). Default: all config_assessment.plugins.")
@click.option("--version", "-V", "versions", multiple=True,
              help="Specific version(s) to fetch. Default: the plugin's curated list.")
@click.pass_context
def fetch_exploits(ctx, product, versions) -> None:
    """Pre-fetch version exploitability (NVD + Exploit-DB) into the local DB.

    \b
    Runs the network lookups once, at build time, so scans stay offline.
      caspar fetch-exploits                        # all plugins, curated versions
      caspar fetch-exploits -p apache-httpd        # one product, curated versions
      caspar fetch-exploits -p apache-httpd -V 2.4.49
    """
    _discover_plugins()
    from config_assessment.core.runtime import registered_plugins
    from config_assessment.enrichment.version_prefetch import fetch_versions
    from config_assessment.core.db.database import Database

    # Build the {product: [versions]} plan from plugins (or the explicit args).
    plan: dict[str, list[str]] = {}
    for p in registered_plugins():
        m = p.metadata()
        if product and m.name != product:
            continue
        vlist = list(versions) if versions else list(m.prefetch_versions)
        if vlist:
            plan[m.name] = vlist

    if not plan:
        click.echo("Nothing to fetch (no curated versions; use -p/-V).", err=True)
        return

    with Database(ctx.obj["db_path"]) as db:
        for prod, vlist in plan.items():
            click.echo(f"\n  {prod} — {len(vlist)} version(s)")
            click.echo("  " + "─" * 50)
            results = fetch_versions(db, prod, vlist)
            for r in results:
                if not r["ok"] and r.get("empty"):
                    click.echo(click.style(
                        f"  ? {r['version']:<10} 0 CVEs (inconclusive — empty CPE "
                        f"or NVD; not stored)", fg="yellow"))
                elif not r["ok"]:
                    click.echo(click.style(
                        f"  ✗ {r['version']:<10} NVD unavailable (try again)",
                        fg="yellow"))
                elif r["exploit_count"] > 0:
                    click.echo(click.style(
                        f"  ⚠ {r['version']:<10} {r['cve_count']} CVEs, "
                        f"{r['exploit_count']} exploits", fg="red"))
                else:
                    click.echo(click.style(
                        f"  ✓ {r['version']:<10} {r['cve_count']} CVEs, "
                        f"no exploits", fg="green"))
    click.echo()


@click.command("refresh")
@click.option("--target", "-t", default="apache-httpd", show_default=True)
@click.option("--nvd-key", default="", help="NVD API key (overrides .env).")
@click.option("--dry-run", is_flag=True)
@click.pass_context
def refresh(ctx, target, nvd_key, dry_run) -> None:
    """Update GEL/GRL scores with NVD + CISA KEV data.

    \b
    Example:
      caspar refresh
      caspar refresh --dry-run
    """
    from config_assessment.plugins.apache_httpd.refresh_cve import refresh_cve
    stats = refresh_cve(
        db_path=ctx.obj["db_path"],
        api_key=nvd_key,
        dry_run=dry_run,
        target=target,
    )
    click.echo()
    click.echo(f"  CVE Refresh {'(dry-run) ' if dry_run else ''}— {target}")
    click.echo(f"  {'─' * 40}")
    click.echo(f"  Total:        {stats.get('total', 0)}")
    click.echo(f"  Updated:      {stats.get('updated', 0)}")
    click.echo(f"  GEL=High:     {stats.get('gel_h', 0)}  (CISA KEV)")
    click.echo(f"  GEL=Medium:   {stats.get('gel_m', 0)}")
    click.echo(f"  GEL=Low:      {stats.get('gel_l', 0)}")
    click.echo()
    if stats.get("gel_h", 0) > 0:
        click.echo(click.style(
            f"  ⚠  {stats['gel_h']} entry/entries in CISA KEV!",
            fg="bright_red", bold=True,
        ))
        click.echo()
