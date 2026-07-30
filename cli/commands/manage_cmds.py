"""
cli/commands/manage_cmds.py — commands that manage state:
suppress (accepted risks), doctor (DB integrity), fix (assisted remediation),
promote (candidate → permanent rule).

Registered on the group in cli/main.py.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from cli._discovery import _discover_plugins
from cli._knowledge import _assess_unknown_directives

logger = logging.getLogger("ccss")


# ── suppress (#2) ──────────────────────────────────────────────────────

@click.command("suppress")
@click.argument("directive", required=False)
@click.option("--reason", "-r", default="", help="Why this risk is accepted.")
@click.option("--bad-value", default="", help="Only suppress this exact value.")
@click.option("--list", "list_only", is_flag=True, help="List suppressions.")
@click.option("--remove", default=None, help="Remove a directive's suppression.")
@click.option("--file", "supp_file", default=None,
              help="Suppression file (default .aegis-suppress.json).")
def suppress(directive, reason, bad_value, list_only, remove, supp_file) -> None:
    """Accept a misconfiguration as a known risk (suppressed in future scans).

    \b
      sca suppress keepalive_timeout -r "Approved by architecture 2026-06-15"
      sca suppress --list
      sca suppress --remove keepalive_timeout
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


# ── doctor (#6: DB integrity) ──────────────────────────────────────────

@click.command("doctor")
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
      sca doctor
      sca doctor --strict
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

@click.command("fix")
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

      sca fix nginx.conf --dry-run
      sca fix nginx.conf                 # writes nginx.conf.fixed
      sca fix nginx.conf --in-place
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

# The attribution marker promote_to_misconfiguration stamps into a promoted
# rule's justification — how the learning loop's output is counted later.
_PROMOTED_MARK = "promoted from unknown-directive assessment"


def _promote_stats(db) -> None:
    """The learning-loop scoreboard: per target, how much of the knowledge base
    came from candidate→rule promotions (vs benchmark extraction), and how many
    promoted rules still await operator review (empty good_value)."""
    rows = []
    for t in db.get_target_names():
        rules = db.get_all_misconfigurations(t)
        promoted = [m for m in rules if _PROMOTED_MARK in (m.justification or "")]
        if not rules:
            continue
        pending = sum(1 for m in promoted if not m.good_value)
        rows.append((t, len(rules), len(promoted), pending))

    click.echo()
    click.echo(f"  {click.style('LEARNING LOOP', bold=True)}  "
               + click.style("(candidate → rule promotions)", dim=True))
    click.echo()
    click.echo(f"  {'TARGET':<18}  {'RULES':>5}  {'PROMOTED':>8}  {'%':>5}  NEEDS REVIEW")
    click.echo("  " + "─" * 58)
    total_r = total_p = 0
    for t, n, p, pend in rows:
        pct = f"{100 * p / n:.0f}%" if n else "-"
        mark = click.style(str(pend), fg="yellow") if pend else "0"
        click.echo(f"  {t:<18}  {n:>5}  {p:>8}  {pct:>5}  {mark}")
        total_r += n
        total_p += p
    click.echo("  " + "─" * 58)
    click.echo(f"  {'total':<18}  {total_r:>5}  {total_p:>8}  "
               f"{(f'{100 * total_p / total_r:.0f}%' if total_r else '-'):>5}")
    click.echo()
    if total_p:
        click.echo(click.style(
            "  Promoted rules stay attributable (marked in their justification) "
            "and need review:\n  set a concrete good_value via "
            "'sca explain <directive> -t <target>'.", dim=True))
        click.echo()


@click.command("promote")
@click.argument("input_path", metavar="[CONFIG]", required=False)
@click.option("--directive", "-d", "only_directive", default=None,
              help="Promote only this directive (default: all confirmed).")
@click.option("--docs", "docs_path", default=None,
              help="Extra docs to ground the LLM assessment (RAG).")
@click.option("--stats", "show_stats", is_flag=True, default=False,
              help="Show the learning-loop scoreboard: how many rules per "
                   "target came from promotions, and how many await review.")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
@click.pass_context
def promote(ctx, input_path, only_directive, docs_path, show_stats, yes) -> None:
    """Promote an LLM-assessed unknown directive to a permanent DB rule.

    \b
    Runs the scan with --assess-unknown, then turns each directive the LLM
    flagged as a likely misconfiguration into a real rule (scored via the normal
    CCSS formulas), so future scans detect it deterministically. Review the
    good_value afterwards — promotion seeds the rule, it doesn't finalise it.

      sca promote nginx.conf                 # all confirmed candidates
      sca promote nginx.conf -d some_flag    # just one
      sca promote --stats                    # measure the learning loop
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

    if show_stats:
        with Database(db_path) as db:
            _promote_stats(db)
        return

    if not input_path:
        click.echo(click.style(
            "Give a CONFIG to assess, or use --stats.", fg="red"), err=True)
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
        f"'sca explain <directive> -t {result.target_name}'.", fg="green"))
    click.echo()
