"""
cli/_output.py — terminal rendering and SARIF export for scan results.

Pure presentation: nothing here touches the DB, the network, or an LLM.
Split out of cli/main.py (which re-exports these names for compatibility).
"""

from __future__ import annotations

import shutil
from itertools import zip_longest

import click

_BANNER = [
    r" ██████╗ █████╗ ███████╗██████╗  █████╗ ██████╗ ",
    r"██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗",
    r"██║     ███████║███████╗██████╔╝███████║██████╔╝",
    r"██║     ██╔══██║╚════██║██╔═══╝ ██╔══██║██╔══██╗",
    r"╚██████╗██║  ██║███████║██║     ██║  ██║██║  ██║",
    r" ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝",
]
_RISK_BOX_W = 28

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


# ── Cabeçalho: banner + Risk Score box ──────────────────────────────

def _boxed_center(plain: str, inner_w: int, **style_kw) -> str:
    """Center `plain` inside a box row of interior width `inner_w`, styling
    only the text so ANSI codes never throw off the padding math."""
    pad = inner_w - len(plain)
    left = pad // 2
    right = pad - left
    return "│" + " " * left + click.style(plain, **style_kw) + " " * right + "│"


def _risk_box_lines(score: float, severity: str) -> list[str]:
    """Right-hand 'Risk Score' panel: bordered box with a block-bar meter."""
    color = _sev_color(score)
    w = _RISK_BOX_W
    inner_w = w - 2
    top = "┌─" + " Risk Score ".center(w - 4, "─") + "─┐"
    bot = "└" + "─" * inner_w + "┘"
    blank = "│" + " " * inner_w + "│"

    score_line = _boxed_center(f"{score:.1f}/10", inner_w, bold=True, fg=color)
    sev_line = _boxed_center(severity.upper(), inner_w, bold=True, fg=color)

    filled = round(score / 10 * (w - 4))
    meter = click.style("█" * filled, fg=color) + click.style("░" * (w - 4 - filled), dim=True)
    meter_line = "│ " + meter + " │"

    return [
        click.style(top, dim=True),
        blank,
        score_line,
        sev_line,
        blank,
        meter_line,
        click.style(bot, dim=True),
    ]


def _print_header(result, resolved, score: float) -> None:
    """Banner + Risk Score box side by side (falls back to stacked on narrow
    terminals so redirected/CI output never wraps mid-box)."""
    from config_assessment.core.ccss import severity_label as sl

    term_w = shutil.get_terminal_size(fallback=(100, 24)).columns
    banner = list(_BANNER)
    box = _risk_box_lines(score, sl(score))
    banner_w = max(len(l) for l in banner)

    mode_labels = {"file": "file", "directory": "directory", "live": "service", "docker": "Docker"}
    input_str = result.input_path
    mode_str = mode_labels.get(resolved.mode, resolved.mode) if resolved else "file"
    if resolved:
        if resolved.mode == "docker":
            input_str = resolved.metadata.get("image", result.input_path)
        elif resolved.mode == "live":
            svc = resolved.metadata.get("service", "")
            ver = resolved.metadata.get("version", "")
            input_str = f"{svc} {ver}".strip() if ver and ver != "unknown" else svc

    click.echo()
    if term_w >= banner_w + _RISK_BOX_W + 6:
        for b_line, box_line in zip_longest(banner, box, fillvalue=""):
            pad = " " * (banner_w - len(b_line) + 3)
            click.echo(f"  {click.style(b_line, fg='bright_red', bold=True)}{pad}{box_line}")
    else:
        for line in banner:
            click.echo(f"  {click.style(line, fg='bright_red', bold=True)}")
        click.echo()
        for line in box:
            click.echo(f"  {line}")

    click.echo()
    click.echo(f"  {click.style('CASPAR', bold=True)} · Configuration Vulnerability Meter (CVM) reference implementation")
    click.echo()
    click.echo(click.style("  Scan_Summary" + "‗" * 54, dim=True))
    click.echo()
    click.echo(f"  {click.style('Target:', dim=True)}   {input_str}")
    click.echo(f"  {click.style('Mode:', dim=True)}     {mode_str}")
    click.echo(f"  {click.style('Profile:', dim=True)}  AV:{result.profile.av} Au:{result.profile.au}")
    click.echo(f"  {click.style('Date:', dim=True)}     {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    click.echo()


# ── Relatório terminal ─────────────────────────────────────────────

def _print_result(result, resolved=None, show_uncovered=False) -> None:
    from config_assessment.core.ccss import severity_label as sl

    groups = _dedup_issues(sorted(result.issues, key=lambda x: -x.temporal_score))
    active_chains = sorted(
        _dedup_chains([c for c in result.chains if c.active]),
        key=lambda x: -x.amplified_score,
    )
    score = result.global_temporal_score

    _print_header(result, resolved, score)

    hi, hc = result.highest_issue_score, result.highest_chain_score
    driver = "attack chain" if result.overall_driver == "chain" else "issue"
    click.echo(
        f"  {click.style('Total Score (worst-case):', bold=True)} "
        f"{click.style(f'{score:.1f}/10', bold=True, fg=_sev_color(score))} "
        f"({result.severity.upper()})   "
        f"{click.style('Total Findings:', dim=True)} {len(groups)}"
    )
    if hi or hc:
        click.echo(
            f"  {click.style('Highest issue', dim=True)} {hi:.1f}   "
            f"{click.style('Highest chain', dim=True)} {hc:.1f}   "
            f"{click.style(f'(overall driven by {driver})', dim=True)}"
        )
    click.echo(f"  {click.style('Attack Chains Triggered:', dim=True)} "
               f"{len(active_chains)}   "
               f"{click.style('Directives Scanned:', dim=True)} {result.total_directives_scanned}")
    click.echo()

    if not result.issues:
        click.echo(click.style("  ✓  No issues detected.", fg="green", bold=True))
        click.echo()
        click.echo(click.style("  Reproducibility" + "‗" * 51, dim=True))
        click.echo()
        _print_manifest_line(getattr(result, "manifest", {}))
        return

    # Contadores por severidade
    counts: dict[str, int] = {}
    for g in groups:
        sev = sl(g["issue"].temporal_score)
        counts[sev] = counts.get(sev, 0) + 1

    click.echo(click.style("  Top_Findings" + "‗" * 54, dim=True))
    click.echo()
    top_sorted = sorted(groups, key=lambda g: -g["issue"].temporal_score)[:10]
    for g in top_sorted:
        issue = g["issue"]
        sc2 = _sev_color(issue.temporal_score)
        sev_lbl = f"[{sl(issue.temporal_score).upper()}]"
        sec = issue.cis_section or "—"
        detail = issue.justification[:44] if issue.justification else issue.bad_value
        click.echo(
            f"  {click.style(sev_lbl.ljust(11), fg=sc2, bold=True)}"
            f"{click.style(sec.ljust(7), dim=True)}"
            f"{click.style(issue.directive.ljust(20), bold=True)}"
            f" : {click.style(detail.ljust(46), dim=True)}"
            f" {click.style(f'{issue.temporal_score:.1f}', bold=True, fg=sc2)}"
        )
    click.echo()

    if active_chains:
        click.echo(click.style("  Attack_Chains_Triggered" + "‗" * 42, dim=True))
        click.echo()
        for chain in active_chains:
            sc2 = _sev_color(chain.amplified_score)
            dirs = " -> ".join(chain.triggered_by)
            click.echo(
                f"  {click.style(f'[{sl(chain.amplified_score).upper()}]', fg=sc2, bold=True)} "
                f"{chain.chain_id}: {dirs}   "
                f"{click.style(f'Score: {chain.amplified_score:.1f}', bold=True, fg=sc2)}"
            )
        click.echo()

    top_finding = top_sorted[0]["issue"] if top_sorted else None
    if top_finding and top_finding.recommendation:
        click.echo(click.style("  Recommendation_(Top_Priority)" + "‗" * 36, dim=True))
        click.echo()
        click.echo(f"  1. {top_finding.recommendation}")
        click.echo()

    summary_parts = []
    for sev, color in [("Critical", "bright_red"), ("High", "red"), ("Medium", "yellow"), ("Low", "cyan")]:
        if counts.get(sev, 0):
            summary_parts.append(click.style(f"{counts[sev]} {sev}", fg=color, bold=sev in ("Critical", "High")))
    click.echo(f"  {click.style('ISSUES (detail)', bold=True)}  {' · '.join(summary_parts)}")
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
        click.echo(f"  {click.style('ATTACK CHAINS (detail)', bold=True)}  {click.style(f'({len(active_chains)})', dim=True)}")
        click.echo()
        for chain in active_chains:
            _print_chain_compact(chain)

    _print_unknown_directives(getattr(result, "unknown_directives", []),
                              show_all=show_uncovered)

    click.echo(click.style("  Reproducibility" + "‗" * 51, dim=True))
    click.echo()
    _print_manifest_line(getattr(result, "manifest", {}))


def _print_manifest_line(manifest: dict) -> None:
    """One dim footer line stating what produced these scores — the auditable
    face of the determinism claim (same manifest + same input ⇒ same scores)."""
    if not manifest:
        return
    db_sha = manifest.get("db_sha256")
    parts = [f"caspar {manifest.get('caspar_version', '?')}"]
    if db_sha:
        parts.append(f"kb sha256:{db_sha[:12]}")
    if manifest.get("rules_for_target") is not None:
        parts.append(f"{manifest['rules_for_target']} rules ({manifest.get('target', '?')})")
    click.echo(click.style(
        "  reproducible: " + " · ".join(parts), dim=True))
    click.echo()


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
