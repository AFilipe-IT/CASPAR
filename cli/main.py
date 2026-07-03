"""
cli/main.py — CASPAR CLI with 4 scan modes and HTML reporting.

  caspar scan /tmp/httpd.conf
  caspar scan /etc/apache2/
  caspar scan --live apache2
  caspar scan docker://httpd:2.4
  caspar scan docker://ccss-test-apache:vulnerable --report --format html
"""

from __future__ import annotations

import importlib
import json
import logging
import os
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

def _plugin_dirs() -> list[Path]:
    """Directories to scan for plugins: the built-in package dir, plus the
    external $CASPAR_PLUGINS_DIR (a mounted volume) when set, so fetched
    plugins persist outside the image."""
    dirs = [Path(__file__).parent.parent / "config_assessment" / "plugins"]
    external = os.environ.get("CASPAR_PLUGINS_DIR")
    if external:
        dirs.append(Path(external))
    return dirs


def _discover_plugins() -> None:
    seen: set[str] = set()
    for plugins_dir in _plugin_dirs():
        if not plugins_dir.exists():
            continue
        for plugin_dir in sorted(plugins_dir.iterdir()):
            name = plugin_dir.name
            if name in seen:
                continue  # built-in dir wins on a name clash
            if plugin_dir.is_dir() and (plugin_dir / "__init__.py").exists():
                seen.add(name)
                try:
                    importlib.import_module(f"config_assessment.plugins.{name}")
                except Exception as exc:
                    logger.warning("Plugin '%s' not loaded: %s", name, exc)


# ── Relatório terminal ─────────────────────────────────────────────

def _print_result(result, resolved=None, show_uncovered=False) -> None:
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
    mode_labels = {"file": "file", "directory": "directory", "live": "service", "docker": "Docker"}
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
    # Explain WHAT drives the overall score, so a high overall from a chain is
    # not mistaken for a high individual issue.
    hi, hc = result.highest_issue_score, result.highest_chain_score
    if hi or hc:
        driver = "attack chain" if result.overall_driver == "chain" else "issue"
        click.echo(
            f"  {click.style('Highest issue', dim=True)} {hi:.1f}   "
            f"{click.style('Highest chain', dim=True)} {hc:.1f}   "
            f"{click.style(f'(overall driven by {driver})', dim=True)}"
        )
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
        click.echo(click.style("  ✓  No issues detected.", fg="green", bold=True))
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

    _print_unknown_directives(getattr(result, "unknown_directives", []),
                              show_all=show_uncovered)

    click.echo(click.style("  ══════════════════════════════════════════════════════════════", dim=True))
    click.echo()


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
    """Layer 3: build a RAG index (benchmark + optional --docs) and run the LLM
    over the surfaced unknown directives. Mutates result.unknown_directives.
    Degrades gracefully — any failure just leaves the LLM fields empty."""
    from config_assessment.build.llm_client import make_client
    from config_assessment.build.rag import BenchmarkIndex
    from config_assessment.core.unknown_directives import assess_unknown_with_llm

    indexes = []
    bench = _find_benchmark_file(result.target_name)
    for src in (bench, Path(docs_path) if docs_path else None):
        if src and src.exists():
            try:
                indexes.append(BenchmarkIndex(str(src)))
            except Exception as exc:
                logger.warning("Could not index %s for RAG: %s", src, exc)
    rag = _CombinedRAG(indexes) if indexes else None

    click.echo(click.style(
        f"  Assessing {len(result.unknown_directives)} uncovered directive(s) "
        f"with LLM{' + RAG' if rag else ''} (non-deterministic)…", dim=True))
    llm = make_client(backend="ollama", fallback_to_stub=True)
    assess_unknown_with_llm(
        result.unknown_directives, service=result.target_name,
        llm=llm, rag_index=rag)


def _print_unknown_directives(unknowns: list, show_all: bool = False) -> None:
    """Show directives the knowledge base does not cover (unknown-directive
    detection). By default only the *suspicious* ones are listed in full, with
    the benign remainder summarised — a real config has hundreds of benign
    unknowns (AddCharset, AddIcon…) that would bury the signal. `show_all`
    (--show-uncovered) lists every one. Never scored — a coverage-gap panel."""
    if not unknowns:
        return
    suspicious = [u for u in unknowns if u.suspicious]
    benign = [u for u in unknowns if not u.suspicious]
    assessed = [u for u in unknowns if u.llm_is_misconfig is not None]

    head = f"UNCOVERED DIRECTIVES  {click.style(f'({len(unknowns)})', dim=True)}"
    if suspicious:
        head += "  " + click.style(f"{len(suspicious)} suspicious", fg="yellow", bold=True)
    click.echo(f"  {click.style(head, bold=True)}")
    click.echo(click.style(
        "  not in the knowledge base — surfaced, not scored", dim=True))
    click.echo()

    def _line(u):
        if u.suspicious:
            mark = click.style("⚠", fg="yellow", bold=True)
            detail = click.style("  ← " + "; ".join(u.risk_signals), fg="yellow")
        else:
            mark = click.style("·", dim=True)
            detail = ""
        loc = ""
        if u.source_file and u.line_number:
            loc = click.style(f"  {u.source_file}:{u.line_number}", dim=True)
        val = f" = {u.value}" if u.value else ""
        click.echo(f"  {mark} {click.style(u.name, bold=u.suspicious)}{val}{loc}{detail}")
        if u.llm_is_misconfig:
            sc = f"~{u.llm_estimated_score:.1f}?" if u.llm_estimated_score else "?"
            click.echo(click.style(
                f"       LLM (low-confidence): possible misconfig {sc} "
                f"{u.llm_impact}  {u.llm_justification}", fg="magenta"))
        elif u.llm_is_misconfig is False and u.llm_justification:
            click.echo(click.style(
                f"       LLM (low-confidence): likely benign — {u.llm_justification}",
                dim=True))

    # Always show suspicious in full. Show benign too only with --show-uncovered
    # (or when the LLM assessed them, so verdicts aren't hidden).
    for u in suspicious:
        _line(u)
    shown_benign = benign if (show_all or assessed) else []
    for u in shown_benign:
        _line(u)
    hidden = len(benign) - len(shown_benign)
    if hidden:
        click.echo(click.style(
            f"  … and {hidden} more benign uncovered directive(s) "
            "— use --show-uncovered to list all", dim=True))
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
            click.echo(f"       {click.style(f'{len(locs)} occurrences: {preview}', dim=True)}")
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
        "runs": [{"tool": {"driver": {"name": "CASPAR", "version": "0.1.0", "rules": rules}}, "results": results}],
    }


# ── CLI ────────────────────────────────────────────────────────────

@click.group()
@click.option("--db", default=lambda: os.environ.get("CASPAR_DB", "ccss.db"),
              show_default="ccss.db (or $CASPAR_DB)")
@click.option("--verbose", "-v", is_flag=True)
@click.pass_context
def cli(ctx: click.Context, db: str, verbose: bool) -> None:
    """CASPAR — Configuration Assessment and Security Posture Automated Review.

    Security configuration scoring framework based on CCSS/NISTIR 7502.
    """
    if verbose:
        logging.getLogger().setLevel(logging.INFO)
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db


@cli.command()
@click.argument("input_path", metavar="CONFIG")
@click.option("--live", "-l", is_flag=True, default=False,
              help="Detect an installed service (e.g. --live apache2).")
@click.option("--report", "-r", is_flag=True, default=False,
              help="Save the report to a file.")
@click.option("--format", "-f", "fmt", default="html",
              type=click.Choice(["html", "dashboard", "json", "sarif"], case_sensitive=False),
              show_default=True)
@click.option("--output", "-o", default=None,
              help="Directory for reports (default: <project>/reports/).")
@click.option("--online", is_flag=True, default=False,
              help="Use online charts (ECharts via CDN) for the dashboard format.")
@click.option("--threshold", "-t", default=0.0, type=float,
              help="Exit 1 if score > threshold (CI/CD).")
@click.option("--exit-code", "differentiated_exit", is_flag=True, default=False,
              help="Exit 2 if any Critical issue is present, 1 if over "
                   "--threshold, 0 otherwise (finer CI control).")
@click.option("--suppress-file", "suppress_file", default=None,
              help="Suppression file (default .caspar-suppress.json if present) "
                   "— accepted-risk issues are hidden and excluded from scoring "
                   "of the exit code.")
@click.option("--service-version", "service_version", default=None,
              help="Service version (e.g. 2.4.58) to cross-reference with "
                   "CVEs/exploits. If omitted, it is auto-detected (Docker tag, "
                   "binary, config).")
@click.option("--assess-unknown", "assess_unknown", is_flag=True, default=False,
              help="Also run an LLM (Ollama) over UNCOVERED directives to guess "
                   "if they are misconfigurations. Non-deterministic, opt-in; "
                   "results are low-confidence candidates, never scored.")
@click.option("--docs", "docs_path", default=None,
              help="Extra service documentation (file/dir) to ground the "
                   "--assess-unknown LLM via RAG, on top of the benchmark.")
@click.option("--show-uncovered", "show_uncovered", is_flag=True, default=False,
              help="List every uncovered directive, not just the suspicious "
                   "ones (a real config has hundreds of benign unknowns).")
@click.option("--profile", "env_profile", default=None,
              type=click.Choice(["production", "internal", "dev"]),
              help="Deployment profile — adjusts exposure (AV) used for scoring: "
                   "production=Network (default), internal=Adjacent, dev=Local.")
@click.pass_context
def scan(ctx, input_path, live, report, fmt, output, threshold,
         differentiated_exit, suppress_file, online, service_version,
         assess_unknown, docs_path, show_uncovered, env_profile) -> None:
    """Analyse service configurations — 4 modes.

    \b
    Mode 1 — file:        caspar scan /tmp/httpd.conf
    Mode 2 — directory:   caspar scan /etc/apache2/
    Mode 3 — live service: caspar scan --live apache2
    Mode 4 — Docker:      caspar scan docker://httpd:2.4
    """
    from config_assessment.core.db.database import Database
    from config_assessment.core.input_resolver import resolve
    from config_assessment.core import runtime

    _discover_plugins()
    db_path: str = ctx.obj["db_path"]

    if not Path(db_path).exists():
        click.echo(
            click.style(f"DB '{db_path}' not found.\n", fg="yellow") +
            "Run: " + click.style("caspar build --benchmark <pdf>", bold=True),
            err=True,
        )
        sys.exit(2)

    try:
        resolved = resolve(input_path, live=live)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)

    # Show what was detected
    if resolved.mode == "live":
        v = resolved.metadata.get("version", "")
        vs = f" {v}" if v and v != "unknown" else ""
        click.echo(click.style(f"  Service: {resolved.metadata.get('service', '')}{vs}", fg="cyan"))
        click.echo(click.style(f"  Config: {resolved.path}", dim=True))
        click.echo()
    elif resolved.mode == "docker":
        click.echo(click.style(f"  Image: {resolved.metadata.get('image', '')}", fg="cyan"))
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
            # Precedência: --service-version explícito > versão do resolver (--live).
            # Sem nenhuma, o runtime auto-detecta (tag Docker, binário, config).
            detected_version = (service_version
                                or resolved.metadata.get("version") or None)
            if detected_version == "unknown":
                detected_version = None
            image_hint = resolved.metadata.get("image")
            result = runtime.scan(resolved.path, db, version=detected_version,
                                  image=image_hint, env_profile=env_profile)
            # Record the scan for history/trending (#4). Best-effort — a failure
            # to persist history must never break the scan itself.
            try:
                db.save_scan_result(result)
            except Exception as exc:
                logger.warning("Could not save scan history: %s", exc)
    except Exception:
        if _deferred_cleanup:
            _deferred_cleanup()
        raise

    # Apply accepted-risk suppressions (#2): hide matching issues and drop them
    # from the exit-code decision. Only loads a file if given, or the default
    # exists — no surprise filtering.
    suppressed_issues: list = []
    from config_assessment.reports.scan_features import SuppressionStore
    _supp_path = suppress_file or SuppressionStore.DEFAULT_PATH
    if suppress_file or Path(_supp_path).exists():
        store = SuppressionStore(_supp_path)
        kept = []
        for issue in result.issues:
            i_dict = {"directive": issue.directive, "bad_value": issue.bad_value}
            if store.is_suppressed(i_dict):
                suppressed_issues.append(issue)
            else:
                kept.append(issue)
        if suppressed_issues:
            result.issues = kept

    # Layer 3 of unknown-directive detection (opt-in, non-deterministic): assess
    # the surfaced UNCOVERED directives with an LLM grounded in RAG context
    # (benchmark + optional --docs). Auto-fires only when there ARE unknowns.
    # Never touches the deterministic scores — fills each unknown's llm_* fields.
    if assess_unknown and result.unknown_directives:
        _assess_unknown_directives(result, docs_path)

    _print_result(result, resolved=resolved, show_uncovered=show_uncovered)
    if suppressed_issues:
        click.echo(click.style(
            f"  ({len(suppressed_issues)} issue(s) suppressed via {_supp_path})",
            dim=True))
        click.echo()

    if report:
        # Where reports go, in order of precedence:
        #   1. explicit -o/--output
        #   2. $CASPAR_REPORTS_DIR (the Docker image sets this to the mounted
        #      /reports volume, so reports survive a --rm container)
        #   3. a reports/ dir next to the package (native use / dev)
        if output:
            od = Path(output)
        elif os.environ.get("CASPAR_REPORTS_DIR"):
            od = Path(os.environ["CASPAR_REPORTS_DIR"])
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

    # Exit-code policy (#11). Default keeps the old contract (exit 1 over
    # threshold). --exit-code adds a Critical→2 tier for finer CI control.
    from config_assessment.core.ccss import severity_label
    from config_assessment.reports.scan_features import (
        classify_exit, EXIT_CRITICAL, EXIT_THRESHOLD)
    sevs = [severity_label(i.temporal_score) for i in result.issues]

    if differentiated_exit:
        code = classify_exit(sevs, result.global_temporal_score, threshold)
        if code == EXIT_CRITICAL:
            click.echo(click.style(
                "  Critical issue present — FAIL (exit 2)", fg="bright_red",
                bold=True), err=True)
        elif code == EXIT_THRESHOLD:
            click.echo(click.style(
                f"  Score {result.global_temporal_score:.1f} > {threshold:.1f} "
                "— FAIL (exit 1)", fg="red", bold=True), err=True)
        if code:
            sys.exit(code)
    elif threshold > 0.0 and result.global_temporal_score > threshold:
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
    """Populate the database using a local LLM (Ollama).

    \b
    Example:
      caspar build --benchmark plugins/apache_httpd/Benchmark.pdf
    """
    if target == "apache-httpd":
        from config_assessment.plugins.apache_httpd.build_llm import run_build
        click.echo(f"  Building '{target}' with {model}...")
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
        click.echo(f"  Building '{target}' with {model}...")
        count = run_build(
            benchmark_path=benchmark,
            db_path=ctx.obj["db_path"],
            model=model,
            ollama_url=ollama_url,
            dry_run=dry_run,
        )
        click.echo(click.style(f"  Concluído: {count} misconfigurations.", fg="green"))
    else:
        click.echo(f"Target '{target}' not implemented.", err=True)
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


@cli.group("plugin")
def plugin_group():
    """Manage CASPAR plugins."""


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
    # Write to the external plugins dir ($CASPAR_PLUGINS_DIR, a mounted volume)
    # when set, so a fetched plugin survives a --rm container; otherwise use the
    # in-package dir. Either way it imports as config_assessment.plugins.<id>,
    # because the package __path__ spans both (see plugins/__init__.py).
    _external_plugins = os.environ.get("CASPAR_PLUGINS_DIR")
    plugins_dir = (_Path(_external_plugins) if _external_plugins
                   else _Path(__file__).resolve().parent.parent
                   / "config_assessment" / "plugins")
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
    click.echo(f"\nRun: caspar scan {cf}")


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
@click.option("--yes", "-y", is_flag=True,
              help="Skip confirmation prompts during --then-install.")
@click.option("--model", "-m", default="qwen2.5:14b", show_default=True,
              help="LLM model used by --then-install.")
@click.pass_context
def plugin_fetch(ctx, service, list_only, search_term, output, then_install,
                 yes, model) -> None:
    """Download a benchmark from a public source and optionally install it.

    \b
    Discovery uses the catalog in config_assessment/fetch/catalog.json, which
    maps a service to a public STIG (via stigviewer.com). The download is a
    DISA-style XCCDF file that 'plugin add' consumes directly.

    \b
    See what's available:   caspar plugin fetch --list
    Download + install:     caspar plugin fetch nginx --then-install
    Download only:          caspar plugin fetch nginx -o ~/benchmarks/
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
                "Try 'caspar plugin fetch --list'.", fg="yellow"), err=True)
            sys.exit(1)
        _print_rows(rows, f"{len(rows)} match(es) for '{search_term}'. "
                          "Fetch with: caspar plugin fetch <service> --then-install")
        return

    if list_only:
        rows = fetcher.list_available()
        _print_rows(rows, f"{len(rows)} services. "
                          "Fetch with: caspar plugin fetch <service> --then-install")
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
        click.echo(f"\nInstall with: "
                   f"{click.style(f'caspar plugin add --source {path}', bold=True)}")
        click.echo()
        return

    # Hand off to the existing 'plugin add' flow on the downloaded file.
    # --then-install is a non-interactive pipeline (often run in the container
    # entrypoint), so always auto-confirm plugin add — otherwise it blocks on
    # the [y/N] "Generate plugin?" prompt with no TTY to answer it.
    click.echo()
    ctx.invoke(plugin_add, source=path, dry_run=False, no_llm=False,
               yes=True, verbose_list=False, model=model)


@cli.command()
def targets() -> None:
    """List available plugins."""
    _discover_plugins()
    from config_assessment.core.runtime import registered_plugins
    plugins = registered_plugins()
    if not plugins:
        click.echo("No plugins registered.")
        return
    click.echo()
    click.echo(f"  {'PLUGIN':<22}  {'VERSION':<10}  BENCHMARK")
    click.echo("  " + "─" * 65)
    for p in plugins:
        m = p.metadata()
        click.echo(f"  {m.name:<22}  {m.version:<10}  {m.benchmark_source}")
    click.echo()


@cli.command()
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


# ── diff (#1) ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("old_json", type=click.Path(exists=True))
@click.argument("new_json", type=click.Path(exists=True))
def diff(old_json, new_json) -> None:
    """Compare two scan JSONs (caspar scan --report -f json).

    \b
    Shows resolved issues, new issues, and the score delta:
      caspar diff reports/scan_old.json reports/scan_new.json
    """
    from config_assessment.reports.scan_features import load_scan, diff_scans

    try:
        d = diff_scans(load_scan(old_json), load_scan(new_json))
    except (ValueError, KeyError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)

    delta = d.score_delta
    arrow = "▲" if delta > 0 else ("▼" if delta < 0 else "=")
    color = "red" if delta > 0 else ("green" if delta < 0 else "white")
    click.echo()
    click.echo(f"  Score: {d.old_score:.1f} → {d.new_score:.1f}  "
               f"{click.style(f'{arrow} {abs(delta):.1f}', fg=color, bold=True)}")
    click.echo()
    click.echo(f"  {click.style('Resolved', fg='green')}: {len(d.resolved)}"
               f"   {click.style('New', fg='red')}: {len(d.new_issues)}"
               f"   Unchanged: {len(d.unchanged)}")
    if d.resolved:
        click.echo(f"\n  {click.style('── Resolved', fg='green', bold=True)}")
        for i in d.resolved:
            click.echo(f"    {click.style('✓', fg='green')} {i['directive']} = "
                       f"{i.get('bad_value','')}  ({i.get('temporal_score',0):.1f})")
    if d.new_issues:
        click.echo(f"\n  {click.style('── New', fg='red', bold=True)}")
        for i in d.new_issues:
            click.echo(f"    {click.style('✗', fg='red')} {i['directive']} = "
                       f"{i.get('bad_value','')}  ({i.get('temporal_score',0):.1f})")
    click.echo()
    # Exit 1 if the score got worse — useful in CI.
    if delta > 0:
        sys.exit(1)


# ── badge (#10) ────────────────────────────────────────────────────────

@cli.command()
@click.argument("scan_json", type=click.Path(exists=True))
@click.option("--label", default="CASPAR", show_default=True)
@click.option("--url-only", is_flag=True, help="Print just the URL, not markdown.")
def badge(scan_json, label, url_only) -> None:
    """Print a shields.io score badge (URL or markdown) for a scan JSON.

      caspar badge reports/scan.json          # markdown for a README
    """
    from config_assessment.reports.scan_features import load_scan, badge_url, badge_markdown
    try:
        score = load_scan(scan_json)["global_temporal_score"]
    except (ValueError, KeyError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)
    click.echo(badge_url(score, label) if url_only else badge_markdown(score, label))


# ── explain (#6) ───────────────────────────────────────────────────────

@cli.command()
@click.argument("directive")
@click.option("--target", "-t", required=True, help="Plugin/target (e.g. nginx).")
@click.pass_context
def explain(ctx, directive, target) -> None:
    """Show the full origin of a rule — no scan needed.

    \b
    Benchmark section, CCSS submetrics, CVEs and narrative for a directive:
      caspar explain keepalive_timeout --target nginx
    """
    from config_assessment.core.db.database import Database

    db_path = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(click.style(f"DB '{db_path}' not found.", fg="yellow"), err=True)
        sys.exit(2)

    with Database(db_path) as db:
        rules = [m for m in db.get_all_misconfigurations(target)
                 if m.directive.lower() == directive.lower()]
    if not rules:
        click.echo(click.style(
            f"No rule '{directive}' for target '{target}'. "
            f"See: caspar scan / caspar targets.", fg="yellow"), err=True)
        sys.exit(1)

    for m in rules:
        click.echo()
        click.echo(f"  {click.style(m.directive, bold=True)}"
                   + (f" = {m.bad_value}" if m.bad_value else "")
                   + f"   {click.style(f'[{target}]', dim=True)}")
        click.echo(f"  {'─' * 60}")
        click.echo(f"  Bad → Good:   {m.bad_value or '(absence)'} → {m.good_value}")
        click.echo(f"  CCSS:         AV:{m.av} Au:{m.au} AC:{m.ac}  "
                   f"C:{m.c} I:{m.i} A:{m.a}")
        click.echo(f"  Score:        Base {m.base_score:.1f} → "
                   f"Temporal {m.temporal_score:.1f}  (GEL:{m.gel} GRL:{m.grl})")
        if m.cis_section:
            click.echo(f"  Benchmark:    {m.cis_section}"
                       + (f"  ·  CCE {m.cce_id}" if m.cce_id else ""))
        if m.cves:
            click.echo(f"  CVEs:         {', '.join(m.cves)}")
        if m.justification:
            click.echo(f"  Why:          {m.justification}")
        if m.recommendation:
            click.echo(f"  {click.style('Fix:', fg='green')}          {m.recommendation}")
        if m.narrative:
            click.echo(f"\n  {click.style('Narrative:', dim=True)}\n  "
                       + m.narrative.replace("\n", "\n  "))
    click.echo()


# ── history (#4) ───────────────────────────────────────────────────────

@cli.command()
@click.argument("input_path", required=False)
@click.option("--last", "-n", default=10, show_default=True, type=int)
@click.pass_context
def history(ctx, input_path, last) -> None:
    """Show past scan scores recorded in the DB (score trending).

    \b
      caspar history                     # all recent scans
      caspar history nginx.conf --last 5 # only this input
    """
    from config_assessment.core.db.database import Database

    db_path = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(click.style(f"DB '{db_path}' not found.", fg="yellow"), err=True)
        sys.exit(2)

    with Database(db_path) as db:
        rows = db.get_scan_history(input_path=input_path, limit=last)

    if not rows:
        click.echo("  No scan history yet. Run a scan first "
                   "(history is recorded automatically).")
        return
    click.echo()
    click.echo(f"  {'WHEN':<20}  {'SCORE':>6}  {'SEV':<9}  INPUT")
    click.echo("  " + "─" * 68)
    prev = None
    for r in rows:
        score = r["global_temporal_score"]
        trend = ""
        if prev is not None:
            d = score - prev
            trend = ("▲" if d > 0 else "▼" if d < 0 else "=")
        click.echo(f"  {r['timestamp'][:19]:<20}  {score:>5.1f}{trend:<1}  "
                   f"{r['severity']:<9}  {r['input_path']}")
        prev = score
    click.echo()


# ── suppress (#2) ──────────────────────────────────────────────────────

@cli.command()
@click.argument("directive", required=False)
@click.option("--reason", "-r", default="", help="Why this risk is accepted.")
@click.option("--bad-value", default="", help="Only suppress this exact value.")
@click.option("--list", "list_only", is_flag=True, help="List suppressions.")
@click.option("--remove", default=None, help="Remove a directive's suppression.")
@click.option("--file", "supp_file", default=None,
              help="Suppression file (default .caspar-suppress.json).")
def suppress(directive, reason, bad_value, list_only, remove, supp_file) -> None:
    """Accept a misconfiguration as a known risk (suppressed in future scans).

    \b
      caspar suppress keepalive_timeout -r "Approved by architecture 2026-06-15"
      caspar suppress --list
      caspar suppress --remove keepalive_timeout
    """
    from datetime import date as _date
    from config_assessment.reports.scan_features import SuppressionStore

    store = SuppressionStore(supp_file)

    if list_only:
        if not store.items:
            click.echo("  No suppressions.")
            return
        click.echo()
        for s in store.items:
            val = f" = {s.bad_value}" if s.bad_value else ""
            click.echo(f"  {click.style(s.directive + val, bold=True)}"
                       f"  {click.style(f'({s.date})', dim=True) if s.date else ''}")
            click.echo(f"     {s.reason or '(no reason given)'}")
        click.echo()
        return

    if remove:
        before = len(store.items)
        store.items = [s for s in store.items
                       if s.directive.lower() != remove.lower()]
        store.save()
        click.echo(f"  Removed {before - len(store.items)} suppression(s) for '{remove}'.")
        return

    if not directive:
        click.echo(click.style(
            "Give a DIRECTIVE, or use --list / --remove.", fg="red"), err=True)
        sys.exit(2)
    if not reason:
        click.echo(click.style(
            "A --reason is required (accepting a risk should be justified).",
            fg="red"), err=True)
        sys.exit(2)

    store.add(directive, reason, bad_value, date=str(_date.today()))
    store.save()
    click.echo(click.style(
        f"  Suppressed '{directive}'{' = ' + bad_value if bad_value else ''} "
        f"→ {store.path}", fg="green"))


# ── report --merge (#5: executive multi-scan summary) ──────────────────

@cli.command()
@click.argument("scan_jsons", nargs=-1, required=True,
                type=click.Path(exists=True))
@click.option("--merge", "do_merge", is_flag=True, default=True,
              help="Merge the given scan JSONs into one summary (default).")
def report(scan_jsons, do_merge) -> None:
    """Combine several scan JSONs into one executive summary.

    \b
    Useful to see every service on a host at a glance — worst offender,
    per-target scores, totals:
      caspar report reports/*.json
    """
    from config_assessment.reports.scan_features import load_scan, merge_scans

    try:
        scans = [load_scan(p) for p in scan_jsons]
    except (ValueError, KeyError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)

    m = merge_scans(scans)
    click.echo()
    click.echo(f"  {click.style('MERGED REPORT', bold=True)}  "
               f"{click.style(f'{len(m.scans)} scans', dim=True)}")
    click.echo()
    click.echo(f"  Average score: {click.style(f'{m.average_score:.1f}', bold=True)}"
               f"   Worst: {click.style(f'{m.worst_score:.1f}', fg=_sev_color(m.worst_score), bold=True)}"
               f" ({m.worst_target})")
    click.echo(f"  Totals: {m.total_issues} issues · {m.total_chains} attack chains")
    click.echo()
    click.echo(f"  {'SCORE':>6}  {'SEV':<9}  {'ISSUES':>6}  {'CHAINS':>6}  TARGET")
    click.echo("  " + "─" * 60)
    for s in m.scans:
        col = _sev_color(s["score"])
        score_cell = click.style(f"{s['score']:>6.1f}", fg=col, bold=True)
        click.echo(f"  {score_cell}  "
                   f"{s['severity']:<9}  {s['issues']:>6}  {s['chains']:>6}  "
                   f"{s['target']}  {click.style(s['input'], dim=True)}")
    click.echo()


# ── doctor (#6: DB integrity) ──────────────────────────────────────────

@cli.command()
@click.option("--strict", is_flag=True, default=False,
              help="Also audit narratives for strong impact claims (RCE, "
                   "privilege escalation…) made without conditional language.")
@click.pass_context
def doctor(ctx, strict) -> None:
    """Check the database for integrity problems (read-only).

    \b
    Flags orphan rules, chains referencing non-existent directives, out-of-range
    scores, and missing reseed metadata. --strict also audits narratives for
    over-reaching impact claims. Exit 1 if any 'error' is found.
      caspar doctor
      caspar doctor --strict
    """
    from config_assessment.core.db.doctor import check

    db_path = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(click.style(f"DB '{db_path}' not found.", fg="yellow"), err=True)
        sys.exit(2)

    findings = check(db_path, strict=strict)
    if not findings:
        click.echo(click.style("  ✓ Database is healthy — no issues found.",
                               fg="green"))
        return

    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    click.echo()
    click.echo(f"  {click.style('DATABASE CHECK', bold=True)}  "
               + click.style(f"{len(errors)} error(s)", fg="red", bold=bool(errors))
               + " · "
               + click.style(f"{len(warnings)} warning(s)", fg="yellow"))
    click.echo()
    for f in errors + warnings:
        color = "red" if f.severity == "error" else "yellow"
        tag = click.style(f"[{f.severity}]", fg=color, bold=f.severity == "error")
        click.echo(f"  {tag} {click.style(f.category, dim=True)}: {f.message}")
    click.echo()
    if errors:
        sys.exit(1)


# ── fix (#1: assisted remediation) ─────────────────────────────────────

@cli.command()
@click.argument("input_path", metavar="CONFIG")
@click.option("--live", "-l", is_flag=True, default=False,
              help="Fix an installed service's config (e.g. --live apache2).")
@click.option("--dry-run", is_flag=True, default=False,
              help="Show the diff without writing anything.")
@click.option("--in-place", is_flag=True, default=False,
              help="Rewrite the file in place (default: write <file>.fixed).")
@click.option("--output", "-o", default=None,
              help="Write the fixed file here (instead of <file>.fixed).")
@click.pass_context
def fix(ctx, input_path, live, dry_run, in_place, output) -> None:
    """Generate config fixes from a scan's findings (detect → remediate).

    \b
    Rewrites directives with an insecure value to their secure value, using the
    good_value already in the DB. Only literal, safe values are applied; prose
    guidance and absence rules are listed as manual steps. Nothing is written
    with --dry-run.

      caspar fix nginx.conf --dry-run
      caspar fix nginx.conf                 # writes nginx.conf.fixed
      caspar fix nginx.conf --in-place
    """
    from config_assessment.core.db.database import Database
    from config_assessment.core.input_resolver import resolve
    from config_assessment.core import runtime
    from config_assessment.reports.remediation import (
        build_fix_plan, render_diff, apply_plan)

    _discover_plugins()
    db_path = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(click.style(f"DB '{db_path}' not found.", fg="yellow"), err=True)
        sys.exit(2)

    try:
        resolved = resolve(input_path, live=live)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)

    with Database(db_path) as db:
        result = runtime.scan(resolved.path, db)
    plan = build_fix_plan(result)

    if not plan.edits and not plan.manual:
        click.echo(click.style("  Nothing to fix — no issues found.", fg="green"))
        return

    click.echo()
    if plan.edits:
        click.echo(f"  {click.style('AUTOMATIC FIXES', bold=True)} "
                   f"{click.style(f'({len(plan.edits)})', dim=True)}")
        click.echo()
        click.echo(render_diff(plan))
        click.echo()
    if plan.manual:
        click.echo(f"  {click.style('MANUAL STEPS', bold=True)} "
                   f"{click.style(f'({len(plan.manual)})', dim=True)}  "
                   + click.style("(not auto-applied — see reason)", dim=True))
        click.echo()
        for m in sorted(plan.manual, key=lambda x: -x["score"]):
            score_str = click.style(f"{m['score']:.1f}", dim=True)
            click.echo(f"  {score_str}  "
                       f"{click.style(m['directive'], bold=True)} → "
                       f"{m['good_value'] or '(see recommendation)'}")
            click.echo(click.style(f"       {m['reason']}", dim=True))
            if m.get("recommendation"):
                click.echo(click.style(f"       → {m['recommendation'][:100]}", fg="green"))
        click.echo()

    if dry_run or not plan.edits:
        if dry_run:
            click.echo(click.style("  [dry-run] nothing written.", fg="cyan"))
        return

    if output:
        # Single-file scans only for an explicit output path.
        if len(plan.files) != 1:
            click.echo(click.style(
                "  --output needs a single target file; use --in-place for "
                "multi-file configs.", fg="yellow"), err=True)
            sys.exit(2)
        edits = plan.edits
        src = Path(next(iter(plan.files)))
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        for e in edits:
            i = e.line_number - 1
            if 0 <= i < len(lines):
                nl = "\n" if lines[i].endswith("\n") else ""
                lines[i] = e.new_line + nl
        Path(output).write_text("".join(lines), encoding="utf-8")
        written = [output]
    else:
        written = apply_plan(plan, in_place=in_place)

    for w in written:
        click.echo(f"  {click.style('✓ written:', fg='green')} {w}")
    if not in_place:
        click.echo(click.style(
            "  (originals untouched — review the .fixed file before replacing)",
            dim=True))
    click.echo()


# ── promote (#2: candidate → permanent rule) ───────────────────────────

@cli.command()
@click.argument("input_path", metavar="CONFIG")
@click.option("--directive", "-d", "only_directive", default=None,
              help="Promote only this directive (default: all confirmed).")
@click.option("--docs", "docs_path", default=None,
              help="Extra docs to ground the LLM assessment (RAG).")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
@click.pass_context
def promote(ctx, input_path, only_directive, docs_path, yes) -> None:
    """Promote an LLM-assessed unknown directive to a permanent DB rule.

    \b
    Runs the scan with --assess-unknown, then turns each directive the LLM
    flagged as a likely misconfiguration into a real rule (scored via the normal
    CCSS formulas), so future scans detect it deterministically. Review the
    good_value afterwards — promotion seeds the rule, it doesn't finalise it.

      caspar promote nginx.conf                 # all confirmed candidates
      caspar promote nginx.conf -d some_flag    # just one
    """
    from config_assessment.core.db.database import Database
    from config_assessment.core.input_resolver import resolve
    from config_assessment.core import runtime
    from config_assessment.core.unknown_directives import promote_to_misconfiguration

    _discover_plugins()
    db_path = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(click.style(f"DB '{db_path}' not found.", fg="yellow"), err=True)
        sys.exit(2)

    try:
        resolved = resolve(input_path, live=False)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)

    with Database(db_path) as db:
        result = runtime.scan(resolved.path, db)
        if not result.unknown_directives:
            click.echo("  No uncovered directives to assess.")
            return
        click.echo(f"  Assessing {len(result.unknown_directives)} uncovered "
                   "directive(s) with LLM…")
        _assess_unknown_directives(result, docs_path)

        candidates = [u for u in result.unknown_directives if u.llm_is_misconfig]
        if only_directive:
            candidates = [u for u in candidates
                          if u.name.lower() == only_directive.lower()]
        if not candidates:
            click.echo(click.style(
                "  No confirmed candidates to promote "
                "(the LLM found none, or needs Ollama).", fg="yellow"))
            return

        click.echo(f"\n  {click.style('CANDIDATES', bold=True)} "
                   f"{click.style(f'({len(candidates)})', dim=True)}")
        for u in candidates:
            sc = f"~{u.llm_estimated_score:.1f}" if u.llm_estimated_score else "?"
            click.echo(f"  {sc}  {click.style(u.name, bold=True)} = {u.value}  "
                       f"{u.llm_impact}")
            click.echo(click.style(f"       {u.llm_justification[:110]}", dim=True))

        if not yes and not click.confirm(
                f"\n  Promote {len(candidates)} rule(s) to '{result.target_name}'?",
                default=False):
            click.echo("  Aborted.")
            return

        n = 0
        for u in candidates:
            try:
                m = promote_to_misconfiguration(u, target_name=result.target_name)
                db.upsert_misconfiguration(m)
                n += 1
            except Exception as exc:
                logger.warning("Could not promote '%s': %s", u.name, exc)
    click.echo(click.style(
        f"\n  ✓ Promoted {n} rule(s). Review their good_value with "
        f"'caspar explain <directive> -t {result.target_name}'.", fg="green"))
    click.echo()


@cli.command()
@click.argument("input_path", metavar="CONFIG")
@click.option("--live", "-l", is_flag=True, default=False,
              help="CONFIG is an installed service name (e.g. apache2); watch "
                   "its config directory. Resolves the path like `scan --live`.")
@click.option("--service-version", "service_version", default=None,
              help="Service version for CVE/exploit cross-reference (the Docker "
                   "wrapper injects this from the host in --live mode).")
@click.option("--interval", "-i", default=1.0, type=float, show_default=True,
              help="Seconds between checks for a config change.")
@click.option("--profile", "env_profile", default=None,
              type=click.Choice(["production", "internal", "dev"]),
              help="Environment baseline for scoring (as in scan).")
@click.option("--log", "log_path", default=None, metavar="FILE",
              help="Append alerts to FILE instead of the terminal (for "
                   "background use: `caspar watch cfg --log watch.log &`).")
@click.option("--notify", is_flag=True, default=False,
              help="Also broadcast worsening alerts as a system notification "
                   "(wall / notify-send), so they reach any terminal.")
@click.pass_context
def watch(ctx, input_path, live, service_version, interval, env_profile,
          log_path, notify) -> None:
    """Continuously audit a config: alert on screen whenever it changes.

    Watches a file, a directory, or (with --live) an installed service's config
    directory. On every change it re-runs the deterministic scan and prints ONE
    compact log line: the new score and what changed — red when risk worsened,
    green when it improved. Runs in the background with the terminal free.

    With --log, alerts are appended to a file and the terminal stays clean —
    ideal for `caspar watch cfg --log watch.log &`; read it with `cat watch.log`.

    Full detail is intentionally omitted — run `caspar scan <config>` for the
    complete report. Data comes from the DB (zero-LLM, zero-network).

    \b
    caspar watch /etc/nginx/nginx.conf
    caspar watch /etc/apache2/ --profile production
    caspar watch --live apache2                    # find + watch its config dir
    caspar watch nginx.conf --log watch.log &      # background, terminal free
    """
    from config_assessment.core.db.database import Database
    from config_assessment.core.input_resolver import resolve
    from config_assessment.core import runtime
    from config_assessment.core.watch import watch as watch_loop

    _discover_plugins()
    db_path: str = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(click.style(f"DB '{db_path}' not found.", fg="yellow"), err=True)
        sys.exit(2)

    # Resolve once to fail fast. With --live, CONFIG is a service name resolved
    # to its config dir (same mapping as `scan --live`); otherwise a disk path.
    try:
        resolved = resolve(input_path, live=live)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)

    # Label: the service name in --live mode (clearer than the entry file's
    # basename), otherwise the path's basename.
    if live:
        name = resolved.metadata.get("service") or input_path
        click.echo(click.style(
            f"  Service: {name}  ({resolved.path})", fg="cyan"))
    else:
        name = Path(resolved.path).name

    # --log routes alerts to a file (append, colourless so it stays greppable).
    # The terminal then only gets a one-line pointer, so it stays free.
    _log_fh = None
    if log_path:
        try:
            _log_fh = open(log_path, "a", encoding="utf-8", buffering=1)  # line-buffered
        except OSError as e:
            # Common under the Docker wrapper: an absolute host path like
            # ~/watch.log isn't visible inside the container (only the mounted
            # cwd is). Point the user at a path that works, don't dump a trace.
            click.echo(click.style(
                f"Cannot write log to '{log_path}': {e.strerror}.", fg="red"),
                err=True)
            click.echo(
                "  In Docker, the log must land in the mounted working dir — "
                "use a path inside it, e.g. " +
                click.style("--log watch.log", bold=True) +
                " (relative), then read it with " +
                click.style("cat watch.log", bold=True) + ".", err=True)
            sys.exit(2)
        click.echo(
            f"  {click.style('○', fg='cyan')} watching {name} in background — "
            f"alerts → {click.style(log_path, bold=True)}"
            + click.style("  (stop: docker stop caspar-watch, or Ctrl-C)", dim=True))

    def _emit(styled_line: str) -> None:
        if _log_fh is not None:
            _log_fh.write(click.unstyle(styled_line) + "\n")
        else:
            click.echo("  " + styled_line)

    # Version for CVE/exploit cross-reference: explicit flag wins, else the
    # resolver's --live detection (same precedence as `scan`).
    _version = service_version or resolved.metadata.get("version") or None
    if _version == "unknown":
        _version = None

    def _scan():
        with Database(db_path) as db:
            return runtime.scan(resolved.path, db, version=_version,
                                env_profile=env_profile)

    prev = None   # previous ScanResult, for the delta
    try:
        for event in watch_loop(resolved.path, interval=interval):
            result = _scan()
            ts = datetime.now().strftime("%H:%M:%S")
            if event.previous is None:
                base = (
                    f"{click.style(f'[{ts}]', dim=True)} "
                    f"{click.style('○', fg='cyan')} watching {name} — "
                    f"baseline {result.global_temporal_score:.1f}/10 "
                    f"[{result.severity}]")
                # In terminal mode also show the poll cadence; in --log the
                # pointer line above already covered how to stop.
                if _log_fh is None:
                    base += click.style(
                        f"  (every {interval:g}s · Ctrl-C to stop)", dim=True)
                _emit(base)
            else:
                _emit(_watch_alert_line(ts, name, result, prev))
                # System notification on a WORSENING change, so the alert reaches
                # whoever is editing the config in another terminal.
                if notify and result.global_temporal_score > \
                        (prev.global_temporal_score if prev else 0.0) + 0.05:
                    _notify_system(
                        f"CASPAR: {name} risk {prev.global_temporal_score:.1f}"
                        f"→{result.global_temporal_score:.1f} [{result.severity}]")
            prev = result
    except KeyboardInterrupt:
        click.echo(click.style("\n  Stopped.", dim=True))
    finally:
        if _log_fh is not None:
            _log_fh.close()


def _notify_system(message: str) -> None:
    """Best-effort system notification, so an alert reaches any terminal.

    Three layers, all best-effort (a failure never breaks the watch):
      1. `notify-send` — desktop popup, if a GUI is present.
      2. `wall` — the standard util-linux broadcast (all the user's login
         terminals); works on a real Linux server / over SSH.
      3. Direct write to each writable /dev/pts/* — what wall does underneath,
         but WITHOUT needing utmp to be populated. This is the fallback that
         makes --notify work where wall can't: WSL2, containers, minimal
         systems with no login records."""
    import shutil
    import subprocess
    banner = f"\n\N{WARNING SIGN}  {message}\n"

    if shutil.which("notify-send"):
        try:
            subprocess.run(["notify-send", "CASPAR", message],
                           timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            pass

    delivered = False
    if shutil.which("wall"):
        try:
            # wall -n suppresses the banner header if permitted; ignore failure.
            subprocess.run(["wall"], input=message, text=True,
                           timeout=5, check=False)
            delivered = True
        except (OSError, subprocess.SubprocessError):
            pass

    # Fallback: write straight to the active PTYs. Independent of utmp, so it
    # reaches other terminals on WSL2 / in containers where wall stays silent.
    _write_to_ptys(banner)


def _write_to_ptys(text: str) -> None:
    """Write text to every /dev/pts/* we can open for writing (best-effort)."""
    import os
    import glob
    my_tty = None
    try:
        my_tty = os.ttyname(1)   # don't double-print on our own terminal
    except OSError:
        pass
    for pts in glob.glob("/dev/pts/[0-9]*"):
        if pts == my_tty:
            continue
        try:
            fd = os.open(pts, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            continue          # not ours / not writable — skip
        try:
            os.write(fd, text.encode("utf-8", "replace"))
        except OSError:
            pass
        finally:
            os.close(fd)


def _watch_alert_line(ts, name, result, prev) -> str:
    """One compact, colored log line describing a config change.

    Red when risk worsened (score up), green when it improved (score down),
    neutral when unchanged. Summarises the score move, the net issue
    count change, and the single worst driver — never the full report."""
    score = result.global_temporal_score
    old = prev.global_temporal_score if prev else 0.0
    worse = score > old + 0.05
    better = score < old - 0.05
    color = "red" if worse else "green" if better else "white"
    icon = "⚠" if worse else "✓" if better else "•"

    # Score move: "0.0 → 6.1".
    move = f"{old:.1f} → {score:.1f}" if prev else f"{score:.1f}"

    # Net issue delta and the newly-appearing worst issue, if any.
    prev_dirs = {i.directive for i in prev.issues} if prev else set()
    new_issues = [i for i in result.issues if i.directive not in prev_dirs]
    net = len(result.issues) - (len(prev.issues) if prev else 0)
    net_str = f"{net:+d} issue" + ("s" if abs(net) != 1 else "")

    parts = [
        click.style(f"[{ts}]", dim=True),
        click.style(f"{icon} {name}", fg=color, bold=worse),
        click.style(f"{move}  [{result.severity}]", fg=color, bold=worse),
        click.style(net_str, fg=color),
    ]
    if new_issues:
        top = max(new_issues, key=lambda i: i.temporal_score)
        val = f"={top.bad_value}" if getattr(top, "bad_value", "") else ""
        parts.append(click.style(
            f"↑ {top.directive}{val} ({top.temporal_score:.1f})", fg=color))
    return "  ".join(parts)


if __name__ == "__main__":
    cli()
