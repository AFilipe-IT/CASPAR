"""
cli/commands/report_cmds.py — read-only reporting/inspection commands:
targets, diff, badge, explain, history, report.

None of these mutate the DB or a config. Registered on the group in cli/main.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from cli._discovery import _discover_plugins
from cli._output import _sev_color
from config_assessment.core.engines.aggregation import sparkline as _sparkline


@click.command("targets")
@click.option("--all", "show_all", is_flag=True,
              help="Include plugins with no rules in the knowledge base.")
@click.pass_context
def targets(ctx: click.Context, show_all: bool) -> None:
    """List available plugins."""
    _discover_plugins()
    from config_assessment.core.runtime import registered_plugins
    # 'dummy' is a test fixture, not a technology anyone scans. It has to stay
    # registered (the suite builds scans on it), but listing it among the
    # supported targets misrepresents what CASPAR covers.
    plugins = [p for p in registered_plugins() if p.metadata().name != "dummy"]

    # A plugin whose code ships but whose rules were never built into the
    # knowledge base would be announced as supported and then find nothing —
    # worse than not listing it. Hide those unless asked, and say so.
    rule_counts = _rule_counts(ctx.obj.get("db_path") if ctx.obj else None)
    hidden = []
    if rule_counts is not None and not show_all:
        kept = []
        for p in plugins:
            if rule_counts.get(p.metadata().name, 0) > 0:
                kept.append(p)
            else:
                hidden.append(p.metadata().name)
        plugins = kept

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
    if hidden:
        names = ", ".join(sorted(hidden))
        click.echo(click.style(
            f"  {len(hidden)} plugin(s) not shown — no rules in this database: "
            f"{names}", dim=True))
        click.echo(click.style(
            "  Build them with 'caspar build --target <name>', or list them "
            "with 'caspar targets --all'.", dim=True))
        click.echo()


def _rule_counts(db_path: str | None) -> dict[str, int] | None:
    """Rules per target name, or None if the database cannot be read."""
    if not db_path or not Path(db_path).exists():
        return None
    import sqlite3
    try:
        with sqlite3.connect(db_path) as conn:
            return {name: n for name, n in conn.execute(
                "SELECT t.name, COUNT(m.id) FROM targets t "
                "LEFT JOIN misconfigurations m ON m.target_id = t.id "
                "GROUP BY t.name")}
    except sqlite3.Error:
        return None


# ── diff (#1) ──────────────────────────────────────────────────────────

@click.command("diff")
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

@click.command("badge")
@click.argument("scan_json", type=click.Path(exists=True))
@click.option("--label", default="CVM", show_default=True)
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

@click.command("explain")
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

@click.command("history")
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


# ── trend (score drift over time, per input) ──────────────────────────

@click.command("trend")
@click.argument("input_filter", required=False, metavar="[INPUT]")
@click.option("--last", "-n", default=200, show_default=True, type=int,
              help="How many recent scans to consider (across all inputs).")
@click.pass_context
def trend(ctx, input_filter, last) -> None:
    """Configuration drift, quantified: score trajectory per scanned input.

    \b
    Every scan is recorded automatically; this shows where each config's risk
    is HEADING — one sparkline per input, first→last score and net drift.
    `history` lists individual scans; `trend` shows the direction.

      caspar trend                # every input with 2+ scans
      caspar trend nginx          # only inputs matching 'nginx'
    """
    from config_assessment.core.db.database import Database
    from config_assessment.core.engines.aggregation import aggregate_trend

    db_path = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(click.style(f"DB '{db_path}' not found.", fg="yellow"), err=True)
        sys.exit(2)

    with Database(db_path) as db:
        rows = db.get_scan_history(limit=last)

    series = aggregate_trend(rows, input_filter=input_filter)
    if not series:
        click.echo("  Not enough history to trend (need 2+ scans of an input). "
                   "Scans are recorded automatically — just scan again later.")
        return

    click.echo()
    click.echo(f"  {click.style('TREND', bold=True)}  "
               f"{click.style(f'{len(series)} input(s)', dim=True)}")
    click.echo()
    for s in series:
        worse = s.delta > 0.05
        better = s.delta < -0.05
        color = "red" if worse else "green" if better else "white"
        arrow = "▲" if worse else "▼" if better else "="
        span = f"{s.timestamps[0][:10]} → {s.timestamps[-1][:10]}"
        click.echo(f"  {click.style(s.sparkline, fg=color)}  "
                   f"{s.first:.1f} → {s.last:.1f}  "
                   f"{click.style(f'{arrow} {abs(s.delta):.1f}', fg=color, bold=True)}"
                   f"  {click.style(f'({s.verdict})', fg=color)}")
        click.echo(click.style(
            f"      {len(s.scores)} scans · {span} · {s.input_path}", dim=True))
        click.echo()


# ── report --merge (#5: executive multi-scan summary) ──────────────────

@click.command("report")
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
