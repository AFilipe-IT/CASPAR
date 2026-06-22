"""
cli/main.py — CCSS-Scan CLI com 4 modos de scan e relatório HTML.

  ccss scan /tmp/httpd.conf
  ccss scan /etc/apache2/
  ccss scan --live apache2
  ccss scan docker://httpd:2.4
  ccss scan docker://ccss-test-apache:vulnerable --report --format html
"""

from __future__ import annotations

import importlib
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import click

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.WARNING,
    stream=sys.stderr,
)
logger = logging.getLogger("ccss")

_AV_DESC  = {"L": "Local", "A": "Adjacent", "N": "Network"}
_AU_DESC  = {"M": "Multiple", "S": "Single", "N": "None"}
_AC_DESC  = {"H": "High", "M": "Medium", "L": "Low"}
_CIA_DESC = {"N": "None", "P": "Partial", "C": "Complete"}
_GEL_DESC = {"N": "None", "L": "Low", "M": "Medium", "H": "High", "ND": "Not Defined"}
_GRL_DESC = {"U": "Unavailable", "W": "Workaround", "H": "Official (CIS)", "ND": "Not Defined"}


# ── Helpers visuais ────────────────────────────────────────────────

def _sev_color(score: float) -> str:
    if score >= 9.0: return "bright_red"
    if score >= 7.0: return "red"
    if score >= 4.0: return "yellow"
    if score > 0.0:  return "cyan"
    return "green"

def _bar(score: float, w: int = 18) -> str:
    f = round(score / 10 * w)
    return click.style("█" * f, fg=_sev_color(score)) + click.style("░" * (w - f), fg="white", dim=True)

def _dedup_issues(issues: list) -> list:
    """Agrupar issues com mesmo directive+bad_value, acumulando localizações."""
    from collections import OrderedDict
    groups: dict = OrderedDict()
    for issue in issues:
        key = (issue.directive, issue.bad_value)
        if key not in groups:
            groups[key] = {"issue": issue, "locs": []}
        src = issue.source_directive
        if src and src.source_file:
            loc = f"{src.source_file}:{src.line_number}"
            if src.context and src.context != "global":
                loc += f" [{src.context}]"
            if loc not in groups[key]["locs"]:
                groups[key]["locs"].append(loc)
    return list(groups.values())

def _dedup_chains(chains: list) -> list:
    """Remover chains com as mesmas directivas."""
    seen: set = set()
    result = []
    for c in chains:
        key = frozenset(c.triggered_by)
        if key not in seen:
            seen.add(key)
            result.append(c)
    return result


# ── Auto-descoberta de plugins ─────────────────────────────────────

def _discover_plugins() -> None:
    plugins_dir = Path(__file__).parent.parent / "config_assessment" / "plugins"
    if not plugins_dir.exists():
        return
    for plugin_dir in sorted(plugins_dir.iterdir()):
        if plugin_dir.is_dir() and (plugin_dir / "__init__.py").exists():
            try:
                importlib.import_module(f"config_assessment.plugins.{plugin_dir.name}")
            except Exception as exc:
                logger.warning("Plugin '%s' não carregado: %s", plugin_dir.name, exc)


# ── Relatório terminal ─────────────────────────────────────────────

def _print_result(result, resolved=None) -> None:
    from config_assessment.core.ccss import severity_label as sl

    groups = _dedup_issues(sorted(result.issues, key=lambda x: -x.temporal_score))
    active_chains = sorted(
        _dedup_chains([c for c in result.chains if c.active]),
        key=lambda x: -x.amplified_score,
    )
    score = result.global_temporal_score
    sc = _sev_color(score)

    click.echo()
    click.echo(click.style("  ══════════════════════════════════════════════════════════════", dim=True))
    click.echo()

    # Modo e input
    mode_labels = {"file": "ficheiro", "directory": "directório", "live": "serviço", "docker": "Docker"}
    input_str = result.input_path
    mode_str = ""
    if resolved:
        mode_str = f"  [{click.style(mode_labels.get(resolved.mode, resolved.mode), fg='cyan')}]"
        if resolved.mode == "docker":
            input_str = resolved.metadata.get("image", result.input_path)
        elif resolved.mode == "live":
            svc = resolved.metadata.get("service", "")
            ver = resolved.metadata.get("version", "")
            input_str = f"{svc} {ver}".strip() if ver and ver != "unknown" else svc

    click.echo(
        f"  {click.style(f'{score:.1f}', bold=True, fg=sc)}/10  "
        f"{click.style(f'[{result.severity}]', bold=True, fg=sc)}"
        f"{mode_str}  {click.style(input_str, dim=True)}"
    )
    click.echo(f"  {_bar(score, 30)}")
    click.echo()

    # Perfil numa linha
    av_str = f"AV:{result.profile.av}={_AV_DESC.get(result.profile.av, '?')}"
    au_str = f"Au:{result.profile.au}={_AU_DESC.get(result.profile.au, '?')}"
    click.echo(
        f"  {click.style(av_str, dim=True)}  {click.style(au_str, dim=True)}"
        f"  ·  {result.total_directives_scanned} directivas  ·  {result.timestamp.strftime('%Y-%m-%d %H:%M')}"
    )
    click.echo()

    if not result.issues:
        click.echo(click.style("  ✓  Nenhum problema detectado.", fg="green", bold=True))
        click.echo()
        click.echo(click.style("  ══════════════════════════════════════════════════════════════", dim=True))
        click.echo()
        return

    # Contadores por severidade
    counts: dict[str, int] = {}
    for g in groups:
        sev = sl(g["issue"].temporal_score)
        counts[sev] = counts.get(sev, 0) + 1

    summary_parts = []
    for sev, color in [("Critical", "bright_red"), ("High", "red"), ("Medium", "yellow"), ("Low", "cyan")]:
        if counts.get(sev, 0):
            summary_parts.append(click.style(f"{counts[sev]} {sev}", fg=color, bold=sev in ("Critical", "High")))
    click.echo(f"  {click.style('ISSUES', bold=True)}  {' · '.join(summary_parts)}")
    click.echo()

    for sev_name in ["Critical", "High", "Medium", "Low"]:
        sev_groups = [g for g in groups if sl(g["issue"].temporal_score) == sev_name]
        if not sev_groups:
            continue
        sc2 = {"Critical": "bright_red", "High": "red", "Medium": "yellow", "Low": "cyan"}[sev_name]
        click.echo(f"  {click.style(f'── {sev_name} ({len(sev_groups)})', fg=sc2, bold=True)}")
        click.echo()
        for g in sorted(sev_groups, key=lambda x: -x["issue"].temporal_score):
            _print_issue_compact(g)

    if active_chains:
        click.echo(f"  {click.style('ATTACK CHAINS', bold=True)}  {click.style(f'({len(active_chains)})', dim=True)}")
        click.echo()
        for chain in active_chains:
            _print_chain_compact(chain)

    click.echo(click.style("  ══════════════════════════════════════════════════════════════", dim=True))
    click.echo()


def _print_issue_compact(g: dict) -> None:
    issue = g["issue"]
    locs = g["locs"]
    color = _sev_color(issue.temporal_score)
    cia = f"C:{issue.c} I:{issue.i} A:{issue.a}"

    click.echo(
        f"  {click.style(f'{issue.temporal_score:.1f}', bold=True, fg=color)}"
        f"  {click.style(issue.directive, bold=True)} = {click.style(issue.bad_value, dim=True)}"
        f"   {click.style(cia, dim=True)}  {click.style(f'AC:{issue.ac}', dim=True)}"
    )
    click.echo(
        f"       {_bar(issue.temporal_score, 16)}"
        f"  Base {issue.base_score:.1f} → Temporal {issue.temporal_score:.1f}"
        f"  GEL:{issue.gel} GRL:{issue.grl}"
    )
    if issue.cves:
        click.echo(f"       CVEs: {'  '.join(click.style(c, fg='yellow') for c in issue.cves)}")
    if locs:
        if len(locs) == 1:
            click.echo(f"       {click.style(locs[0], dim=True)}")
        else:
            preview = " | ".join(locs[:2]) + ("  ..." if len(locs) > 2 else "")
            click.echo(f"       {click.style(f'{len(locs)} ocorrências: {preview}', dim=True)}")
    if issue.justification:
        just = issue.justification[:120] + ("…" if len(issue.justification) > 120 else "")
        click.echo(f"       {click.style(just, dim=True)}")
    if issue.recommendation:
        rec = issue.recommendation[:110]
        click.echo(f"       {click.style('→ ', fg='green')}{click.style(rec, fg='green')}")
    click.echo()


def _print_chain_compact(chain) -> None:
    color = _sev_color(chain.amplified_score)
    dirs = " + ".join(click.style(d, bold=True) for d in chain.triggered_by)
    # amp multiplier hidden by design — score already reflects amplification
    click.echo(
        f"  {click.style(f'{chain.amplified_score:.1f}', bold=True, fg=color)}"
        f"  {click.style(chain.chain_id, bold=True)}"
    )
    click.echo(f"       {_bar(chain.amplified_score, 16)}  {dirs}")
    if chain.justification:
        just = chain.justification[:120] + ("…" if len(chain.justification) > 120 else "")
        click.echo(f"       {click.style(just, dim=True)}")
    click.echo()


# ── SARIF helper ───────────────────────────────────────────────────

def _to_sarif(result) -> dict:
    rules, results = [], []
    for issue in result.issues:
        rid = f"CCSS-{issue.directive.upper().replace(' ', '_')}"
        rules.append({
            "id": rid,
            "name": issue.directive,
            "shortDescription": {"text": f"{issue.directive} misconfiguration"},
            "fullDescription": {"text": issue.justification or ""},
            "defaultConfiguration": {"level": "error" if issue.temporal_score >= 7 else "warning"},
            "properties": {"ccss-temporal-score": issue.temporal_score, "cve-ids": issue.cves},
        })
        results.append({
            "ruleId": rid,
            "message": {"text": issue.recommendation or ""},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": result.input_path},
                "region": {"startLine": (
                    issue.source_directive.line_number
                    if issue.source_directive and issue.source_directive.line_number else 1
                )},
            }}],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "CCSS-Scan", "version": "0.1.0", "rules": rules}}, "results": results}],
    }


# ── CLI ────────────────────────────────────────────────────────────

@click.group()
@click.option("--db", default="ccss.db", show_default=True)
@click.option("--verbose", "-v", is_flag=True)
@click.pass_context
def cli(ctx: click.Context, db: str, verbose: bool) -> None:
    """CASPAR — Configuration Assessment and Security Posture Automated Review.

    Framework de scoring de configurações de segurança (baseado em CCSS).
    """
    if verbose:
        logging.getLogger().setLevel(logging.INFO)
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db


@cli.command()
@click.argument("input_path", metavar="CONFIG")
@click.option("--live", "-l", is_flag=True, default=False,
              help="Detectar serviço instalado (ex: --live apache2).")
@click.option("--report", "-r", is_flag=True, default=False,
              help="Guardar relatório em ficheiro.")
@click.option("--format", "-f", "fmt", default="html",
              type=click.Choice(["html", "dashboard", "json", "sarif"], case_sensitive=False),
              show_default=True)
@click.option("--output", "-o", default=None,
              help="Directory for reports (default: <project>/reports/).")
@click.option("--online", is_flag=True, default=False,
              help="Use online charts (ECharts via CDN) for the dashboard format.")
@click.option("--threshold", "-t", default=0.0, type=float,
              help="Exit 1 se score > threshold (CI/CD).")
@click.pass_context
def scan(ctx, input_path, live, report, fmt, output, threshold, online) -> None:
    """Analisar configurações Apache — 4 modos.

    \b
    Modo 1 — ficheiro:      ccss scan /tmp/httpd.conf
    Modo 2 — directório:    ccss scan /etc/apache2/
    Modo 3 — serviço live:  ccss scan --live apache2
    Modo 4 — Docker:        ccss scan docker://httpd:2.4
    """
    from config_assessment.core.db.database import Database
    from config_assessment.core.input_resolver import resolve
    from config_assessment.core import runtime

    _discover_plugins()
    db_path: str = ctx.obj["db_path"]

    if not Path(db_path).exists():
        click.echo(
            click.style(f"DB '{db_path}' não encontrada.\n", fg="yellow") +
            "Corre: " + click.style("ccss build --benchmark <pdf>", bold=True),
            err=True,
        )
        sys.exit(2)

    try:
        resolved = resolve(input_path, live=live)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        click.echo(click.style(f"Erro: {e}", fg="red"), err=True)
        sys.exit(2)

    # Mostrar o que foi detectado
    if resolved.mode == "live":
        v = resolved.metadata.get("version", "")
        vs = f" {v}" if v and v != "unknown" else ""
        click.echo(click.style(f"  Serviço: {resolved.metadata.get('service', '')}{vs}", fg="cyan"))
        click.echo(click.style(f"  Config: {resolved.path}", dim=True))
        click.echo()
    elif resolved.mode == "docker":
        click.echo(click.style(f"  Imagem: {resolved.metadata.get('image', '')}", fg="cyan"))
        click.echo()
    elif resolved.mode == "directory":
        click.echo(click.style(
            f"  Dir: {resolved.metadata.get('root_dir', '')}  [{resolved.metadata.get('entry_file', '')}]",
            fg="cyan",
        ))
        click.echo()

    _deferred_cleanup = resolved.cleanup if resolved.cleanup else None
    try:
        with Database(db_path) as db:
            detected_version = resolved.metadata.get("version") or None
            if detected_version == "unknown":
                detected_version = None
            result = runtime.scan(resolved.path, db, version=detected_version)
    except Exception:
        if _deferred_cleanup:
            _deferred_cleanup()
        raise

    _print_result(result, resolved=resolved)

    if report:
        # Default: a reports/ directory inside the project (next to cli/),
        # so reports are collected in the repo regardless of the cwd.
        if output:
            od = Path(output)
        else:
            od = Path(__file__).resolve().parent.parent / "reports"
        od.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = (
            input_path
            .replace("://", "_").replace("/", "_").replace(":", "_")
            .strip("_")[:30]
        ) or "scan"

        if fmt == "html":
            from config_assessment.reports.report_html import generate_html
            p = od / f"ccss_{stem}_{ts}.html"
            p.write_text(generate_html(result, resolved=resolved), encoding="utf-8")
            click.echo(f"  HTML: {click.style(str(p), fg='cyan')}")
        elif fmt == "dashboard":
            if online:
                from config_assessment.reports.report_dashboard_online import generate_dashboard_online as _gen_dash
                _suffix = "dashboard_online"
            else:
                from config_assessment.reports.report_dashboard import generate_dashboard as _gen_dash
                _suffix = "dashboard"
            p = od / f"ccss_{stem}_{ts}_{_suffix}.html"
            p.write_text(_gen_dash(result, resolved=resolved), encoding="utf-8")
            _label = "Dashboard (online)" if online else "Dashboard"
            click.echo(f"  {_label}: {click.style(str(p), fg='cyan')}")
        elif fmt == "json":
            p = od / f"ccss_{stem}_{ts}.json"
            p.write_text(result.model_dump_json(indent=2), encoding="utf-8")
            click.echo(f"  JSON: {click.style(str(p), fg='cyan')}")
        else:
            p = od / f"ccss_{stem}_{ts}.sarif"
            p.write_text(json.dumps(_to_sarif(result), indent=2), encoding="utf-8")
            click.echo(f"  SARIF: {click.style(str(p), fg='cyan')}")
        click.echo()

    # Cleanup temp files (e.g. Docker extraction dir) AFTER reports are written,
    # so the HTML snippet feature can still read the config file.
    if _deferred_cleanup:
        _deferred_cleanup()

    if threshold > 0.0 and result.global_temporal_score > threshold:
        click.echo(
            click.style(f"  Score {result.global_temporal_score:.1f} > {threshold:.1f} — FAIL", fg="red", bold=True),
            err=True,
        )
        sys.exit(1)


@cli.command()
@click.option("--benchmark", "-b", required=True)
@click.option("--model", "-m", default="qwen2.5:14b", show_default=True)
@click.option("--ollama-url", default="http://localhost:11434", show_default=True)
@click.option("--target", "-t", default="apache-httpd", show_default=True)
@click.option("--dry-run", is_flag=True)
@click.pass_context
def build(ctx, benchmark, model, ollama_url, target, dry_run) -> None:
    """Popular a base de dados com LLM local (Ollama).

    \b
    Exemplo:
      ccss build --benchmark plugins/apache_httpd/Benchmark.pdf
    """
    if target == "apache-httpd":
        from config_assessment.plugins.apache_httpd.build_llm import run_build
        click.echo(f"  A construir '{target}' com {model}...")
        count = run_build(
            benchmark_path=benchmark,
            db_path=ctx.obj["db_path"],
            model=model,
            ollama_url=ollama_url,
            dry_run=dry_run,
        )
        click.echo(click.style(f"  Concluído: {count} misconfigurations.", fg="green"))
    elif target == "nginx":
        from config_assessment.plugins.nginx.build_nginx import run_build
        click.echo(f"  A construir '{target}' com {model}...")
        count = run_build(
            benchmark_path=benchmark,
            db_path=ctx.obj["db_path"],
            model=model,
            ollama_url=ollama_url,
            dry_run=dry_run,
        )
        click.echo(click.style(f"  Concluído: {count} misconfigurations.", fg="green"))
    else:
        click.echo(f"Target '{target}' não implementado.", err=True)
        sys.exit(1)


@cli.command(name="fetch-exploits")
@click.option("--product", "-p", default=None,
              help="Target product (e.g. apache-httpd). Default: all config_assessment.plugins.")
@click.option("--version", "-V", "versions", multiple=True,
              help="Specific version(s) to fetch. Default: the plugin's curated list.")
@click.pass_context
def fetch_exploits(ctx, product, versions) -> None:
    """Pre-fetch version exploitability (NVD + Exploit-DB) into the local DB.

    \b
    Runs the network lookups once, at build time, so scans stay offline.
      ccss fetch-exploits                          # all plugins, curated versions
      ccss fetch-exploits -p apache-httpd          # one product, curated versions
      ccss fetch-exploits -p apache-httpd -V 2.4.49
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
        click.echo("Nada a buscar (nenhuma versão curada; usa -p/-V).", err=True)
        return

    with Database(ctx.obj["db_path"]) as db:
        for prod, vlist in plan.items():
            click.echo(f"\n  {prod} — {len(vlist)} versão(ões)")
            click.echo("  " + "─" * 50)
            results = fetch_versions(db, prod, vlist)
            for r in results:
                if not r["ok"] and r.get("empty"):
                    click.echo(click.style(
                        f"  ? {r['version']:<10} 0 CVEs (inconclusivo — CPE ou "
                        f"NVD vazio; não gravado)", fg="yellow"))
                elif not r["ok"]:
                    click.echo(click.style(
                        f"  ✗ {r['version']:<10} NVD indisponível (tenta de novo)",
                        fg="yellow"))
                elif r["exploit_count"] > 0:
                    click.echo(click.style(
                        f"  ⚠ {r['version']:<10} {r['cve_count']} CVEs, "
                        f"{r['exploit_count']} exploits", fg="red"))
                else:
                    click.echo(click.style(
                        f"  ✓ {r['version']:<10} {r['cve_count']} CVEs, "
                        f"sem exploits", fg="green"))
    click.echo()


@cli.group("plugin")
def plugin_group():
    """Manage CCSS-Scan config_assessment.plugins."""


@plugin_group.command("add")
@click.option("--source", "-s", required=True, type=click.Path(exists=True),
              help="CIS Benchmark PDF")
@click.option("--dry-run", is_flag=True, help="Show spec without installing")
@click.option("--no-llm", is_flag=True,
              help="Heuristic extraction only (skip LLM for ambiguous)")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.option("--verbose", "verbose_list", is_flag=True,
              help="List all extracted controls, not just a preview")
@click.option("--model", "-m", default="qwen2.5:14b", show_default=True)
@click.pass_context
def plugin_add(ctx, source, dry_run, no_llm, yes, verbose_list, model) -> None:
    """Install a new plugin from a CIS Benchmark PDF."""
    from pathlib import Path as _Path
    from config_assessment.build.plugin_detector import detect_service_from_pdf
    from config_assessment.build.benchmark_extractor import extract_all
    from config_assessment.build.rag import BenchmarkIndex
    from config_assessment.build.plugin_scaffolder import PluginSpec, scaffold_plugin
    from config_assessment.build.llm_client import make_client

    src_name = _Path(source).name
    click.echo(f"\nAnalysing {src_name}...")

    llm = None if no_llm else make_client(
        backend="ollama", model=model, fallback_to_stub=True)

    # ── Peça 4: detect service ─────────────────────────────────────────
    info = detect_service_from_pdf(source, llm=llm)
    if info is None:
        click.echo(click.style(
            "  Service not recognised in known-services list.", fg="yellow"))
        if not yes and not click.confirm(
                "  Proceed anyway with a generic key_value plugin?", default=False):
            click.echo("  Aborted.")
            return
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
    n_high = sum(1 for c in candidates if c.confidence == "high" and not c.needs_review)
    n_llm = sum(1 for c in candidates if c.method == "LLM")
    n_review = sum(1 for c in candidates if c.needs_review)
    usable = [c for c in candidates if c.directive and not c.needs_review]
    n_skipped = len(idx.sections) - len(usable)

    click.echo(f"  Heuristic (high):  {n_high:3}")
    if not no_llm:
        click.echo(f"  LLM (medium/low):  {n_llm:3}")
    click.echo(f"  Skipped:           {n_skipped:3}    (procedures/out-of-scope)")
    click.echo(f"  Total:             {len(usable):3} controls\n")

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
    click.echo(f"Benchmark: {idx.sections[0].title[:40] if idx.sections else src_name}")

    # ── build the spec ─────────────────────────────────────────────────
    entries = [(c.directive, c.bad_value, c.good_value, c.section_id) for c in usable]
    spec = PluginSpec(
        service_name=info["service_name"], target_id=info["target_id"],
        config_format=info["config_format"], config_paths=info["config_paths"],
        config_filenames=info["config_filenames"],
        bind_directive=info["bind_directive"],
        version_exposing=info["version_exposing"], entries=entries,
        benchmark_source=src_name.replace(".pdf", "").replace("_", " "),
    )

    if dry_run:
        click.echo(click.style("\n[dry-run] No files created.", fg="cyan"))
        return

    # ── confirm ────────────────────────────────────────────────────────
    plugins_dir = _Path(__file__).resolve().parent.parent / "config_assessment" / "plugins"
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
        benchmark_path=str(plugin_dir / src_name),
        entries=mentries, db_path=ctx.obj["db_path"], model=model,
    )
    click.echo(click.style(
        f"\nPlugin '{info['target_id']}' installed successfully.", fg="green"))
    click.echo(f"  Misconfigs: {stats['misconfigs']} | Chains: {stats['chains']} "
               f"| Narratives: {stats['narratives']}/{stats['misconfigs']}")
    cf = info["config_paths"][0] if info["config_paths"] else info["config_filenames"][0]
    click.echo(f"\nRun: ccss scan {cf}")


@cli.command()
def targets() -> None:
    """Listar plugins disponíveis."""
    _discover_plugins()
    from config_assessment.core.runtime import registered_plugins
    plugins = registered_plugins()
    if not plugins:
        click.echo("Nenhum plugin registado.")
        return
    click.echo()
    click.echo(f"  {'PLUGIN':<22}  {'VERSÃO':<10}  BENCHMARK")
    click.echo("  " + "─" * 65)
    for p in plugins:
        m = p.metadata()
        click.echo(f"  {m.name:<22}  {m.version:<10}  {m.benchmark_source}")
    click.echo()


@cli.command()
@click.option("--target", "-t", default="apache-httpd", show_default=True)
@click.option("--nvd-key", default="", help="NVD API key (sobrepõe .env).")
@click.option("--dry-run", is_flag=True)
@click.pass_context
def refresh(ctx, target, nvd_key, dry_run) -> None:
    """Actualizar GEL/GRL com NVD + CISA KEV.

    \b
    Exemplo:
      ccss refresh
      ccss refresh --dry-run
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
    click.echo(f"  Actualizados: {stats.get('updated', 0)}")
    click.echo(f"  GEL=High:     {stats.get('gel_h', 0)}  (CISA KEV)")
    click.echo(f"  GEL=Medium:   {stats.get('gel_m', 0)}")
    click.echo(f"  GEL=Low:      {stats.get('gel_l', 0)}")
    click.echo()
    if stats.get("gel_h", 0) > 0:
        click.echo(click.style(
            f"  ⚠  {stats['gel_h']} entrada(s) na CISA KEV!",
            fg="bright_red", bold=True,
        ))
        click.echo()


if __name__ == "__main__":
    cli()
