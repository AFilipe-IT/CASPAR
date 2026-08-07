"""
core/engines/aggregation.py
-----------------------------
Aggregation Engine (CVM Core).

Rolls up scores across several axes:
  - aggregate_scan            — within one scan: issues + chains -> global score
  - aggregate_trend           — across scans of the same input, over time
  - aggregate_hosts           — across targets (e.g. every service on a host)
  - aggregate_by_file         — Configuration File level: issues grouped by source file
  - aggregate_categories      — Operating System level: score per configuration category
  - aggregate_chain_category  — the "Cadeias de ataque" category (chain-level, not rule-level)

All follow the same worst-case principle as engines.scoring.aggregate: the
global risk is driven by the most severe unresolved finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from config_assessment.core.engines import scoring
from config_assessment.core.engines.categorization import ATTACK_CHAINS, categorize
from config_assessment.core.models import AttackChain, Misconfiguration

_SPARK = "▁▂▃▄▅▆▇█"


# ── within one scan ─────────────────────────────────────────────────────

def aggregate_scan(
    issues: list[Misconfiguration],
    chains: list[AttackChain],
) -> tuple[float, float]:
    """Aggregate one scan's issues + active chains into (base, temporal).

    Moved verbatim from runtime.scan() step 7: worst-case across issue
    temporal scores and active chains' amplified scores.
    """
    all_temporal_scores = [m.temporal_score for m in issues]
    all_temporal_scores += [c.amplified_score for c in chains if c.active]
    global_temporal = scoring.aggregate(all_temporal_scores)
    global_base = scoring.aggregate([m.base_score for m in issues])
    return global_base, global_temporal


# ── across scans of the same input (trend) ──────────────────────────────

def sparkline(scores: list[float]) -> str:
    """Map 0..10 scores onto ▁▂▃▄▅▆▇█ — the whole history in one glance."""
    return "".join(_SPARK[min(7, max(0, int(s / 10 * 8)))] for s in scores)


@dataclass
class TrendSeries:
    input_path: str
    scores: list[float] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)

    @property
    def first(self) -> float:
        return self.scores[0] if self.scores else 0.0

    @property
    def last(self) -> float:
        return self.scores[-1] if self.scores else 0.0

    @property
    def delta(self) -> float:
        return round(self.last - self.first, 1)

    @property
    def verdict(self) -> str:
        if self.delta > 0.05:
            return "risk increased"
        if self.delta < -0.05:
            return "risk reduced"
        return "stable"

    @property
    def sparkline(self) -> str:
        return sparkline(self.scores)


def aggregate_trend(
    history_rows: list[dict],
    input_filter: str | None = None,
) -> list[TrendSeries]:
    """Group scan-history rows (most-recent-first, as returned by
    Database.get_scan_history) chronologically per input, keeping only
    inputs with 2+ scans. Promoted from report_cmds.py::trend()'s inline
    grouping/sparkline math, stripped of click/echo — pure data in, data out.
    """
    groups: dict[str, list[dict]] = {}
    for r in reversed(history_rows):
        if input_filter and input_filter.lower() not in r["input_path"].lower():
            continue
        groups.setdefault(r["input_path"], []).append(r)

    series = []
    for path, seq in sorted(groups.items()):
        if len(seq) < 2:
            continue
        series.append(TrendSeries(
            input_path=path,
            scores=[s["global_temporal_score"] for s in seq],
            timestamps=[s["timestamp"] for s in seq],
        ))
    return series


# ── across targets (executive multi-scan / host summary) ───────────────

@dataclass
class HostRollup:
    scans: list[dict] = field(default_factory=list)   # per-target summary rows
    total_issues: int = 0
    total_chains: int = 0
    worst_score: float = 0.0
    worst_target: str = ""

    @property
    def average_score(self) -> float:
        if not self.scans:
            return 0.0
        return round(sum(s["score"] for s in self.scans) / len(self.scans), 1)


def aggregate_hosts(scan_dicts: list[dict]) -> HostRollup:
    """Aggregate several scan JSONs (e.g. every service on a host) into one
    executive summary — per-target scores, worst offender, totals.

    Promoted from reports/scan_features.py::merge_scans (kept there as a
    thin wrapper for backward compatibility).
    """
    rollup = HostRollup()
    for d in scan_dicts:
        score = d.get("global_temporal_score", 0.0)
        row = {
            "target": d.get("target_name", "?"),
            "input": d.get("input_path", ""),
            "score": score,
            "severity": d.get("severity", "None"),
            "issues": len(d.get("issues", [])),
            "chains": len([c for c in d.get("chains", [])
                           if c.get("active", True)]),
        }
        rollup.scans.append(row)
        rollup.total_issues += row["issues"]
        rollup.total_chains += row["chains"]
        if score > rollup.worst_score:
            rollup.worst_score, rollup.worst_target = score, row["target"]
    # Worst-first ordering for the report.
    rollup.scans.sort(key=lambda s: -s["score"])
    return rollup


# ── Configuration File level ────────────────────────────────────────────

@dataclass
class FileRollup:
    file_path: str
    issues: list[Misconfiguration] = field(default_factory=list)
    base_score: float = 0.0
    temporal_score: float = 0.0
    severity: str = "None"


def aggregate_by_file(issues: list[Misconfiguration]) -> dict[str, FileRollup]:
    """Group a scan's issues by their source config file, worst-case per file.

    Uses m.source_directive.source_file — already populated by every parser,
    previously only used as report citation text. Issues with no
    source_directive are grouped under "(unknown)".
    """
    groups: dict[str, list[Misconfiguration]] = {}
    for m in issues:
        key = m.source_directive.source_file if m.source_directive else "(unknown)"
        groups.setdefault(key, []).append(m)

    result: dict[str, FileRollup] = {}
    for path, ms in groups.items():
        temporal = scoring.aggregate([m.temporal_score for m in ms])
        base = scoring.aggregate([m.base_score for m in ms])
        result[path] = FileRollup(
            file_path=path, issues=ms, base_score=base,
            temporal_score=temporal, severity=scoring.severity_label(temporal),
        )
    return result


# ── Operating System level: category taxonomy ───────────────────────────

@dataclass
class CategoryScore:
    category: str
    score: float = 0.0
    severity: str = "None"
    issue_count: int = 0
    top_issues: list[Misconfiguration] = field(default_factory=list)


def aggregate_categories(issues: list[Misconfiguration]) -> dict[str, CategoryScore]:
    """Worst-case score per configuration category, across every issue passed
    in — the caller collects issues from every service scan tagged to one
    host, so this is the Operating System level's per-category rollup
    ("Categoria é um agregado ao nível do SO — score por categoria dentro de
    um host"). A rule may land in multiple categories via categorize().
    """
    buckets: dict[str, list[Misconfiguration]] = {}
    for m in issues:
        for cat in categorize(m):
            buckets.setdefault(cat, []).append(m)

    out: dict[str, CategoryScore] = {}
    for cat, ms in buckets.items():
        score = scoring.aggregate([m.temporal_score for m in ms])
        out[cat] = CategoryScore(
            category=cat, score=score, severity=scoring.severity_label(score),
            issue_count=len(ms),
            top_issues=sorted(ms, key=lambda m: -m.temporal_score)[:5],
        )
    return out


def aggregate_chain_category(chains: list[AttackChain]) -> CategoryScore:
    """The "Cadeias de ataque / risco composto" category score: worst-case
    amplified_score across active chains from every service scan tagged to
    one host. Kept separate from aggregate_categories since AttackChain is
    not a Misconfiguration — the caller combines both into one category list.
    """
    active = [c for c in chains if c.active]
    score = scoring.aggregate([c.amplified_score for c in active])
    return CategoryScore(
        category=ATTACK_CHAINS, score=score, severity=scoring.severity_label(score),
        issue_count=len(active),
    )
