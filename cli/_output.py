"""
cli/_output.py — terminal rendering and SARIF export for scan results.

Pure presentation: nothing here touches the DB, the network, or an LLM.
Split out of cli/main.py (which re-exports these names for compatibility).
"""

from __future__ import annotations

import re
import shutil
from itertools import zip_longest

import click

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    """Visible width of a styled string: padding math must ignore colour codes,
    which occupy no columns but plenty of characters."""
    return _ANSI_RE.sub("", s)


def _elide_left(text: str, width: int) -> str:
    """Trim from the left, keeping the tail. For a path the filename and line
    number carry the information; the leading directories rarely do.

    The marker is ASCII "..." rather than "…": U+2026 has East-Asian width
    "Ambiguous", so terminals disagree on whether it occupies one column or
    two, and a box aligned beside it bows by a column on exactly the rows that
    were truncated.
    """
    if len(text) <= width:
        return text
    return "..." + text[-(width - 3):]

_BANNER = [
    r" ██████╗ █████╗ ███████╗██████╗  █████╗ ██████╗ ",
    r"██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗",
    r"██║     ███████║███████╗██████╔╝███████║██████╔╝",
    r"██║     ██╔══██║╚════██║██╔═══╝ ██╔══██║██╔══██╗",
    r"╚██████╗██║  ██║███████║██║     ██║  ██║██║  ██║",
    r" ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝",
]
_RISK_BOX_W = 44

# The score meter is a segmented scale with a numbered axis rather than a solid
# bar: a reader can place 7.8 against the 7.5 tick without re-reading the digits,
# and the segment colours make the band boundaries (4.0 / 7.0 / 9.0) visible as
# positions rather than as a single colour that only makes sense once you know
# the number.
_METER_SEGMENTS = 24

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


# ── Identidade: wordmark (só em `caspar about`) ─────────────────────

# The wordmark is deliberately absent from `scan`. A security CLI is run many
# times a day and the logo carries no information the second time it is seen;
# it lives here, where someone asking "what is this tool" actually wants it.
_WORDMARK = [
    r" ██████╗ █████╗ ███████╗██████╗  █████╗ ██████╗ ",
    r"██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗",
    r"██║     ███████║███████╗██████╔╝███████║██████╔╝",
    r"██║     ██╔══██║╚════██║██╔═══╝ ██╔══██║██╔══██╗",
    r"╚██████╗██║  ██║███████║██║     ██║  ██║██║  ██║",
    r" ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝",
]


def print_about() -> None:
    """The wordmark, the version, and what CASPAR is versus what CVM is."""
    from config_assessment.core.manifest import CASPAR_VERSION

    click.echo()
    for line in _WORDMARK:
        click.echo("  " + click.style(line, fg="bright_blue"))
    click.echo()
    click.echo(f"  {click.style('CASPAR', bold=True)} "
               f"{click.style(CASPAR_VERSION, dim=True)}"
               f"   {click.style('Configuration Assessment, Scoring '
                                 'and Prioritisation of Attack Routes', dim=True)}")
    click.echo()
    # The distinction the header's one-liner has no room for: CVM is the
    # methodology being proposed, CASPAR is one implementation of it.
    click.echo(f"  {click.style('Configuration Vulnerability Meter (CVM)', bold=True)}")
    click.echo("  A methodology for quantitative, reproducible scoring of")
    click.echo("  security misconfigurations, built on CCSS (NISTIR 7502) and")
    click.echo("  extended with attack-chain composition. CASPAR is its")
    click.echo("  reference implementation.")
    click.echo()
    click.echo(f"  {click.style('caspar scan --help', fg='green')}"
               f"   {click.style('# assess a configuration', dim=True)}")
    click.echo(f"  {click.style('caspar demo', fg='green')}"
               f"          {click.style('# example configurations to try', dim=True)}")
    click.echo()


# ── Cabeçalho: identidade compacta + Risk Score box ─────────────────

def _boxed_center(plain: str, inner_w: int, **style_kw) -> str:
    """Center `plain` inside a box row of interior width `inner_w`, styling
    only the text so ANSI codes never throw off the padding math."""
    pad = inner_w - len(plain)
    left = pad // 2
    right = pad - left
    return "│" + " " * left + click.style(plain, **style_kw) + " " * right + "│"


def _meter_line(score: float, width: int) -> str:
    """Segmented score meter: each segment carries the colour of the band it
    sits in, so the scale itself shows where Medium becomes High becomes
    Critical.

    The empty track uses a lighter glyph rather than a dimmed full block. With
    the same block on both sides the meter read as full at every score, and
    anywhere colour is lost — a redirected file, a report pasted into the
    dissertation, a monochrome terminal — the bar carried no information at all.
    """
    filled = round(score / 10 * width)
    out = []
    for i in range(width):
        # Value at this segment's midpoint, so a segment is coloured by the
        # band it actually represents rather than by the overall score.
        seg_value = (i + 0.5) / width * 10
        if i < filled:
            out.append(click.style("█", fg=_sev_color(seg_value)))
        else:
            out.append(click.style("░", fg="white", dim=True))
    return "".join(out)


def _meter_axis(width: int) -> str:
    """The 0 / 2.5 / 5 / 7.5 / 10 tick row beneath the meter.

    The end labels are anchored flush to the meter's edges rather than centred
    on their tick: a centred "10" would sit a column short of the scale's end
    and read as if the meter stopped before it does.
    """
    axis = [" "] * width
    ticks = ((0, "0"), (2.5, "2.5"), (5, "5"), (7.5, "7.5"), (10, "10"))
    for value, label in ticks:
        if value == 0:
            start = 0
        elif value == 10:
            start = width - len(label)
        else:
            start = round(value / 10 * (width - 1)) - (len(label) - 1) // 2
            start = min(max(start, 0), width - len(label))
        for j, ch in enumerate(label):
            axis[start + j] = ch
    return "".join(axis)


def _risk_box_lines(score: float, severity: str) -> list[str]:
    """Right-hand score panel: title, big score, segmented meter, numbered
    axis and the severity band."""
    color = _sev_color(score)
    inner_w = _RISK_BOX_W - 2
    meter_w = inner_w - 4

    top = "┌" + "─" * inner_w + "┐"
    bot = "└" + "─" * inner_w + "┘"
    blank = "│" + " " * inner_w + "│"

    title = _boxed_center("CONFIGURATION VULNERABILITY SCORE", inner_w,
                          fg="bright_cyan", bold=True)

    # The score and the "/ 10" denominator differ in weight, so build this row
    # by hand instead of via _boxed_center (which styles one run uniformly).
    score_plain = f"{score:.1f} / 10"
    pad = inner_w - len(score_plain)
    left = pad // 2
    score_line = ("│" + " " * left
                  + click.style(f"{score:.1f}", fg=color, bold=True)
                  + click.style(" / ", dim=True)
                  + click.style("10", bold=True)
                  + " " * (pad - left) + "│")

    meter_line = "│  " + _meter_line(score, meter_w) + "  │"
    axis_line = "│  " + click.style(_meter_axis(meter_w), dim=True) + "  │"
    sev_line = _boxed_center(severity.upper(), inner_w, bold=True, fg=color)

    return [
        click.style(top, dim=True),
        title,
        blank,
        score_line,
        blank,
        meter_line,
        axis_line,
        blank,
        sev_line,
        click.style(bot, dim=True),
    ]


def _print_header(result, resolved, score: float) -> None:
    """Identity line, assessment summary and the score panel side by side
    (falls back to stacked on narrow terminals so redirected/CI output never
    wraps mid-box)."""
    from config_assessment.core.ccss import severity_label as sl

    term_w = shutil.get_terminal_size(fallback=(100, 24)).columns
    box = _risk_box_lines(score, sl(score))

    # Three distinct concepts that were previously collapsed into "Target":
    # the service running on the host, the plugin whose rules were applied, and
    # the configuration actually read. In --live mode they differ (apache2 /
    # apache-httpd / /etc/apache2/apache2.conf) and conflating them made the
    # NEXT STEPS suggest `--live apache-httpd`, which is not a service name.
    mode_labels = {"file": "file", "directory": "directory",
                   "live": "installed service", "docker": "container image"}
    mode_str = mode_labels.get(resolved.mode, resolved.mode) if resolved else "file"

    rows = [("Plugin", result.target_name)]
    if resolved and resolved.mode == "live":
        svc = resolved.metadata.get("service", "")
        ver = resolved.metadata.get("version", "")
        rows.insert(0, ("Service", f"{svc} {ver}".strip()
                        if ver and ver != "unknown" else svc))
        rows.append(("Configuration", result.input_path))
    elif resolved and resolved.mode == "docker":
        rows.insert(0, ("Image", resolved.metadata.get("image", result.input_path)))
        rows.append(("Configuration", result.input_path))
    else:
        rows.append(("Configuration", result.input_path))

    rows += [
        ("Mode", mode_str),
        ("Date", result.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
        ("Profile", f"AV:{result.profile.av} Au:{result.profile.au}"),
    ]

    # Compact identity block. The wordmark moved to `caspar --about`: an
    # operational tool is run many times a day and the logo carries no
    # information the second time it is seen.
    from config_assessment.core.manifest import CASPAR_VERSION as _ver
    click.echo()
    click.echo(f"  {click.style('CASPAR', fg='bright_blue', bold=True)} "
               f"{click.style(_ver, dim=True)}")
    click.echo(f"  {click.style('Configuration Vulnerability Meter', bold=True)} "
               f"{click.style('· Reference Implementation', dim=True)}")
    click.echo()
    click.echo(click.style("  " + "─" * min(term_w - 4, 96), dim=True))
    click.echo()

    label_w = max(len(r[0]) for r in rows)

    # Side by side when the terminal allows it; stacked otherwise, so a narrow
    # or redirected terminal never wraps a box mid-row.
    summary_w = label_w + 3 + 46
    if term_w >= summary_w + _RISK_BOX_W + 8:
        value_w = summary_w - label_w - 3
        summary_lines = [click.style("ASSESSMENT SUMMARY", fg="bright_cyan", bold=True), ""]
        summary_lines += [
            f"{click.style(k.ljust(label_w), dim=True)} : {_elide_left(v, value_w)}"
            for k, v in rows
        ]
        # Pad every row to exactly summary_w, then one fixed gutter. Using a
        # `max(..., n)` floor here would push any row that reached full width
        # further right than its neighbours and bow the box's left edge.
        for s_line, box_line in zip_longest(summary_lines, box, fillvalue=""):
            plain_len = len(_strip_ansi(s_line))
            click.echo(f"  {s_line}{' ' * (summary_w - plain_len)}   {box_line}")
    else:
        click.echo(click.style("  ASSESSMENT SUMMARY", fg="bright_cyan", bold=True))
        click.echo()
        for k, v in rows:
            click.echo(f"  {click.style(k.ljust(label_w), dim=True)} : {v}")
        click.echo()
        for line in box:
            click.echo(f"  {line}")
    click.echo()


_SEV_BANDS = [
    ("CRITICAL", "Critical", "bright_red"),
    ("HIGH", "High", "red"),
    ("MEDIUM", "Medium", "yellow"),
    ("LOW", "Low", "cyan"),
    ("NONE", "None", "green"),
]


def _print_severity_band(counts: dict[str, int]) -> None:
    """The five-cell severity tally: the whole distribution at a glance,
    including the empty bands — 0 Critical is information, not absence."""
    term_w = shutil.get_terminal_size(fallback=(100, 24)).columns
    total_w = min(term_w - 4, 96)
    cell_w = (total_w - 6) // 5

    click.echo(click.style("  FINDINGS BY SEVERITY", fg="bright_cyan", bold=True))
    click.echo()
    click.echo(click.style("  ┌" + "┬".join(["─" * cell_w] * 5) + "┐", dim=True))

    heads, nums = [], []
    for label, key, color in _SEV_BANDS:
        n = counts.get(key, 0)
        # An empty band stays dim so the eye lands on what was actually found.
        heads.append(_centered(label, cell_w, fg=color, bold=True) if n
                     else _centered(label, cell_w, dim=True))
        nums.append(_centered(str(n), cell_w, fg=color, bold=True) if n
                    else _centered("0", cell_w, dim=True))

    sep = click.style("│", dim=True)
    click.echo("  " + sep + sep.join(heads) + sep)
    click.echo("  " + sep + sep.join(nums) + sep)
    click.echo(click.style("  └" + "┴".join(["─" * cell_w] * 5) + "┘", dim=True))
    click.echo()


def _centered(text: str, width: int, **style_kw) -> str:
    """Center `text` in `width` columns, styling only the text so the padding
    math stays right in the presence of ANSI codes."""
    pad = width - len(text)
    left = pad // 2
    return " " * left + click.style(text, **style_kw) + " " * (pad - left)


def _print_findings_table(groups: list) -> None:
    """TOP FINDINGS as an aligned table.

    The CCSS vector is shown in full next to each score: it is what makes the
    number auditable — a reader can see that 8.7 comes from AV:N/C:C and not
    from an opaque weighting.
    """
    from config_assessment.core.ccss import severity_label as sl

    term_w = shutil.get_terminal_size(fallback=(100, 24)).columns
    # Fixed columns: #(3) sev(10) score(6) vector(30); directive and location
    # share what is left, with the location favoured since paths are long.
    fixed = 3 + 10 + 6 + 30 + 5
    spare = max(term_w - 4 - fixed, 34)
    dir_w = min(max(spare // 3, 14), 22)
    loc_w = max(spare - dir_w, 20)

    header = (f"  {'#'.ljust(3)}{'Severity'.ljust(10)}{'Directive'.ljust(dir_w)}"
              f"{'Score'.rjust(6)}  {'CCSS Vector'.ljust(30)}{'File / Location'}")
    click.echo(click.style(header, dim=True))
    click.echo(click.style("  " + "─" * min(term_w - 4, 96), dim=True))

    for n, g in enumerate(groups, 1):
        issue = g["issue"]
        color = _sev_color(issue.temporal_score)
        sev = sl(issue.temporal_score).upper()
        vector = (f"AV:{issue.av} AC:{issue.ac} Au:{issue.au} "
                  f"C:{issue.c} I:{issue.i} A:{issue.a}")

        loc = g["locs"][0] if g["locs"] else "-"
        if len(g["locs"]) > 1:
            loc += f" (+{len(g['locs']) - 1})"
        loc = _elide_left(loc, loc_w)

        directive = issue.directive
        if len(directive) > dir_w - 1:
            directive = directive[:dir_w - 4] + "..."

        click.echo(
            f"  {click.style(str(n).ljust(3), dim=True)}"
            f"{click.style(sev.ljust(10), fg=color, bold=True)}"
            f"{click.style(directive.ljust(dir_w), bold=True)}"
            f"{click.style(f'{issue.temporal_score:.1f}'.rjust(6), fg=color, bold=True)}  "
            f"{click.style(vector.ljust(30), dim=True)}"
            f"{click.style(loc, dim=True)}"
        )


# ── Relatório terminal ─────────────────────────────────────────────

def _print_result(result, resolved=None, show_uncovered=False,
                  verbose=False, show_chains=False) -> None:
    from config_assessment.core.ccss import severity_label as sl

    groups = _dedup_issues(sorted(result.issues, key=lambda x: -x.temporal_score))
    active_chains = sorted(
        _dedup_chains([c for c in result.chains if c.active]),
        key=lambda x: -x.amplified_score,
    )
    score = result.global_temporal_score

    _print_header(result, resolved, score)

    # Score attribution. The score is the worst individual finding; the chain
    # figure sits beside it precisely because it is *not* in the number, and a
    # reader comparing the two would otherwise assume it was.
    hi, hc = result.highest_issue_score, result.highest_chain_score
    if hi or hc:
        note = ("→ chains not scored" if not active_chains
                else "→ score from findings; chains not scored")
        click.echo(
            f"  {click.style('Highest finding', dim=True)} {hi:.1f}   "
            f"{click.style('Highest chain', dim=True)} {hc:.1f}   "
            f"{click.style('Chains triggered', dim=True)} {len(active_chains)}   "
            f"{click.style(note, fg='bright_cyan')}"
        )
        click.echo()

    if not result.issues:
        click.echo(click.style("  ✓  No issues detected.", fg="green", bold=True))
        click.echo()
        click.echo(click.style("  REPRODUCIBILITY", fg="bright_cyan", bold=True))
        click.echo()
        _print_manifest_line(getattr(result, "manifest", {}))
        return

    # Contadores por severidade
    counts: dict[str, int] = {}
    for g in groups:
        sev = sl(g["issue"].temporal_score)
        counts[sev] = counts.get(sev, 0) + 1

    _print_severity_band(counts)

    click.echo(click.style("  TOP FINDINGS", fg="bright_cyan", bold=True))
    click.echo()
    top_sorted = sorted(groups, key=lambda g: -g["issue"].temporal_score)[:10]
    _print_findings_table(top_sorted)
    click.echo()

    if active_chains:
        # Capped like TOP FINDINGS above it. The chains are already sorted
        # worst-first, and the ones that matter for the score are at the top;
        # --show-chains carries the complete analysis.
        shown_chains = active_chains if (verbose or show_chains) else active_chains[:5]
        head = click.style("  ATTACK CHAINS TRIGGERED", fg="bright_cyan", bold=True)
        if len(shown_chains) < len(active_chains):
            head += click.style(
                f"   top {len(shown_chains)} of {len(active_chains)}", dim=True)
        click.echo(head)
        click.echo()
        for chain in shown_chains:
            sc2 = _sev_color(chain.amplified_score)
            dirs = " -> ".join(chain.triggered_by)
            click.echo(
                f"  {click.style(f'[{sl(chain.amplified_score).upper()}]', fg=sc2, bold=True)} "
                f"{chain.chain_id}: {dirs}   "
                f"{click.style(f'Score: {chain.amplified_score:.1f}', bold=True, fg=sc2)}"
            )
        click.echo()

    _print_recommendation(result, top_sorted, active_chains)

    # Per-finding detail is opt-in. A real service configuration produces a
    # page of it, which buries the summary the operator actually came for.
    if verbose:
        summary_parts = []
        for sev, color in [("Critical", "bright_red"), ("High", "red"),
                           ("Medium", "yellow"), ("Low", "cyan")]:
            if counts.get(sev, 0):
                summary_parts.append(click.style(
                    f"{counts[sev]} {sev}", fg=color,
                    bold=sev in ("Critical", "High")))
        click.echo(click.style("  ALL FINDINGS", fg="bright_cyan", bold=True)
                   + f"  {' · '.join(summary_parts)}")
        click.echo()

        for sev_name in ["Critical", "High", "Medium", "Low"]:
            sev_groups = [g for g in groups if sl(g["issue"].temporal_score) == sev_name]
            if not sev_groups:
                continue
            sc2 = {"Critical": "bright_red", "High": "red",
                   "Medium": "yellow", "Low": "cyan"}[sev_name]
            click.echo(f"  {click.style(f'── {sev_name} ({len(sev_groups)})', fg=sc2, bold=True)}")
            click.echo()
            for g in sorted(sev_groups, key=lambda x: -x["issue"].temporal_score):
                _print_issue_compact(g)

    if active_chains and (verbose or show_chains):
        click.echo(f"  {click.style('ATTACK CHAINS (detail)', bold=True)}  "
                   f"{click.style(f'({len(active_chains)})', dim=True)}")
        click.echo()
        for chain in active_chains:
            _print_chain_compact(chain)

    _print_coverage(result, show_uncovered)

    if not (verbose and show_uncovered):
        _print_more_hints(verbose, show_chains, show_uncovered, bool(active_chains))

    _print_next_steps(result, resolved)

    click.echo(click.style("  REPRODUCIBILITY", fg="bright_cyan", bold=True))
    click.echo()
    _print_manifest_line(getattr(result, "manifest", {}))


def _print_coverage(result, show_uncovered: bool) -> None:
    """Knowledge-base coverage for this scan.

    Framed as coverage rather than as a findings section. "244 uncovered
    directives" listed under the findings reads as 244 unassessed risks; what
    it actually states is how much of this configuration the current knowledge
    base has rules for. The suspicious subset still surfaces, because an
    uncovered directive that looks dangerous is worth a human's attention even
    though it carries no score.
    """
    unknowns = getattr(result, "unknown_directives", []) or []
    manifest = getattr(result, "manifest", {}) or {}
    rules = manifest.get("rules_for_target")

    total = result.total_directives_scanned
    covered = total - len(unknowns)

    click.echo(click.style("  COVERAGE", fg="bright_cyan", bold=True))
    click.echo()
    # Phrased as "n of m read", not as three independent totals: the reader
    # needs to see that the uncovered set is a fraction of this file, and that
    # the rule count is a property of the knowledge base rather than of the
    # configuration. Listed as a bare "244 uncovered" it reads as 244 unassessed
    # risks, which is the opposite of what it means.
    click.echo(f"  {click.style(f'{covered} of {total}', bold=True)} "
               f"directives read from the configuration were matched against "
               f"the knowledge base")
    if unknowns:
        tail = "" if show_uncovered else click.style(
            " — use --show-uncovered to list them", dim=True)
        click.echo(click.style(
            f"  {len(unknowns)} directive(s) have no rule yet", dim=True) + tail)
    if rules:
        click.echo(click.style(
            f"  {rules} rules available for {result.target_name}", dim=True))
    click.echo()

    # The suspicious ones are shown regardless: they are the reason the
    # uncovered set is surfaced at all rather than silently dropped.
    _print_unknown_directives(unknowns, show_all=show_uncovered)


def _print_more_hints(verbose: bool, show_chains: bool,
                      show_uncovered: bool, has_chains: bool) -> None:
    """What the summary left out, and the flag that reveals it."""
    hints = []
    if not verbose:
        hints.append(("--verbose", "every finding in full detail"))
    if has_chains and not (verbose or show_chains):
        hints.append(("--show-chains", "full attack-chain analysis"))
    if not show_uncovered:
        hints.append(("--show-uncovered", "every uncovered directive"))
    if not hints:
        return

    width = max(len(f) for f, _ in hints)
    for flag, what in hints:
        click.echo(f"  {click.style(flag.ljust(width), fg='green')}"
                   f"   {click.style('# ' + what, dim=True)}")
    click.echo()


def _print_recommendation(result, top_sorted: list, active_chains: list) -> None:
    """The verdict in prose, then the single highest-value action.

    The score always traces to one finding, so the highest-value fix is always
    nameable. What the score cannot express is composition: when a chain is
    scored above the headline, this says so explicitly, because a reader who
    fixes only the table's first row would leave the more urgent problem in
    place. That warning is the reason chains are computed at all.
    """
    score = result.global_temporal_score
    color = _sev_color(score)
    sev = result.severity.upper()

    click.echo(click.style("  RECOMMENDATION", fg="bright_cyan", bold=True))
    click.echo()
    click.echo(f"  {click.style('!', fg=color, bold=True)}  "
               f"This configuration scores {click.style(f'{score:.1f}', fg=color, bold=True)}"
               f" — {click.style(sev, fg=color, bold=True)} overall vulnerability.")

    if top_sorted:
        issue = top_sorted[0]["issue"]
        click.echo(f"     Highest-value fix: {click.style(issue.directive, bold=True)}"
                   f" ({issue.temporal_score:.1f})")
        if issue.recommendation:
            click.echo(f"     → {issue.recommendation}")

    if result.chain_exceeds_score and active_chains:
        top_chain = active_chains[0]
        click.echo()
        click.echo(f"     {click.style('Note:', fg='bright_cyan', bold=True)} these findings "
                   f"compose into {click.style(top_chain.chain_id, bold=True)}, rated "
                   f"{click.style(f'{top_chain.amplified_score:.1f}', bold=True, fg=_sev_color(top_chain.amplified_score))}"
                   f" — higher than any single finding.")
        click.echo(f"     Chain: {click.style(' + '.join(top_chain.triggered_by), bold=True)}")
        click.echo("     The score reflects individual findings; breaking this chain")
        click.echo("     removes more risk than its component scores suggest.")
    click.echo()


def _print_next_steps(result, resolved) -> None:
    """Three commands that follow naturally from this scan, with the actual
    target substituted in, so the next step is copy-pasteable rather than a
    docs lookup."""
    if resolved and resolved.mode == "live":
        arg = f"--live {resolved.metadata.get('service', '')}".strip()
    else:
        # Relative to the working directory when that is shorter — these lines
        # are meant to be copied, and an absolute path can be longer than the
        # terminal is wide.
        import os
        arg = result.input_path
        try:
            rel = os.path.relpath(arg)
            if len(rel) < len(arg):
                arg = rel
        except ValueError:      # different drive on Windows
            pass

    steps = [
        (f"caspar scan {arg} --report -f html -o reports", "Full HTML report"),
        (f"caspar fix {arg} --dry-run", "Preview remediation"),
        (f"caspar watch {arg}", "Continuous monitoring"),
    ]

    # A wrapped command is not copy-pasteable, which defeats the point of this
    # section. When the target's path is long enough to overflow, drop the
    # aligned comments and let each command own its line.
    term_w = shutil.get_terminal_size(fallback=(100, 24)).columns
    width = max(len(cmd) for cmd, _ in steps)
    inline_notes = width + 25 <= term_w

    click.echo(click.style("  NEXT STEPS", fg="bright_cyan", bold=True))
    click.echo()
    for cmd, note in steps:
        if inline_notes:
            click.echo(f"  {click.style(cmd.ljust(width), fg='green')}"
                       f"   {click.style('# ' + note, dim=True)}")
        else:
            click.echo(f"  {click.style('# ' + note, dim=True)}")
            click.echo(f"  {click.style(cmd, fg='green')}")
    click.echo()


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
    """List the directives the knowledge base does not cover.

    The body of the COVERAGE section, which supplies the counts and the
    heading. By default only the *suspicious* ones are listed, with the benign
    remainder left to the count above — a real config has hundreds of benign
    unknowns (AddCharset, AddIcon…) that would bury the signal. `show_all`
    (--show-uncovered) lists every one. Never scored.
    """
    if not unknowns:
        return
    suspicious = [u for u in unknowns if u.suspicious]
    benign = [u for u in unknowns if not u.suspicious]
    assessed = [u for u in unknowns if u.llm_is_misconfig is not None]

    if suspicious:
        click.echo("  " + click.style(
            f"{len(suspicious)} uncovered directive(s) look suspicious "
            "— surfaced, not scored", fg="yellow", bold=True))
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
    if suspicious or shown_benign:
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
