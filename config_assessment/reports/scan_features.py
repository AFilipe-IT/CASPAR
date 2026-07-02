"""
config_assessment/reports/scan_features.py
-------------------------------------------
Pure, offline helpers built on top of the scan JSON (ScanResult.model_dump_json).
These power the product-level CLI features — diff, badge, suppressions,
exit-code classification, catalog search — with no network, no LLM and no
scanning logic, so they are trivially testable.

Everything here operates on plain dicts loaded from a scan's JSON output, or on
the shipped fetch catalog, keeping the CLI layer thin.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path


# ── issue identity ─────────────────────────────────────────────────────

def issue_key(issue: dict) -> str:
    """A stable identity for a misconfiguration across scans: directive +
    bad_value (the pair that defines the rule), lowercased."""
    return f"{issue.get('directive','')}={issue.get('bad_value','')}".lower()


def load_scan(path: str | Path) -> dict:
    """Load a scan JSON produced by `caspar scan --report -f json`."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "global_temporal_score" not in data:
        raise ValueError(f"{path}: not a CASPAR scan JSON "
                         "(missing 'global_temporal_score')")
    return data


# ── #1 diff ────────────────────────────────────────────────────────────

@dataclass
class ScanDiff:
    old_score: float
    new_score: float
    resolved: list[dict] = field(default_factory=list)   # in old, gone in new
    new_issues: list[dict] = field(default_factory=list)  # in new, not in old
    unchanged: list[dict] = field(default_factory=list)

    @property
    def score_delta(self) -> float:
        return round(self.new_score - self.old_score, 1)


def diff_scans(old: dict, new: dict) -> ScanDiff:
    """Compare two scan JSONs of (presumably) the same target."""
    old_by = {issue_key(i): i for i in old.get("issues", [])}
    new_by = {issue_key(i): i for i in new.get("issues", [])}
    resolved = [old_by[k] for k in old_by if k not in new_by]
    added = [new_by[k] for k in new_by if k not in old_by]
    same = [new_by[k] for k in new_by if k in old_by]
    return ScanDiff(
        old_score=old.get("global_temporal_score", 0.0),
        new_score=new.get("global_temporal_score", 0.0),
        resolved=sorted(resolved, key=lambda i: -i.get("temporal_score", 0)),
        new_issues=sorted(added, key=lambda i: -i.get("temporal_score", 0)),
        unchanged=same,
    )


# ── #10 badge ──────────────────────────────────────────────────────────

def _severity_color(score: float) -> str:
    if score >= 9.0:
        return "critical"          # shields.io named colors
    if score >= 7.0:
        return "red"
    if score >= 4.0:
        return "yellow"
    if score > 0.0:
        return "green"
    return "brightgreen"


def badge_url(score: float, label: str = "CASPAR") -> str:
    """A shields.io badge URL for a scan score."""
    color = _severity_color(score)
    value = f"{score:.1f}/10"
    return (f"https://img.shields.io/badge/"
            f"{label}-{value.replace('/', '%2F').replace(' ', '%20')}-{color}")


def badge_markdown(score: float, label: str = "CASPAR") -> str:
    return f"![{label} Score]({badge_url(score, label)})"


# ── #11 differentiated exit codes ──────────────────────────────────────

# Contract for CI: 0 = clean/under threshold, 1 = over threshold (or High),
# 2 = a Critical issue is present. Critical dominates.
EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_CRITICAL = 2


def classify_exit(result_severities: list[str], global_score: float,
                  threshold: float) -> int:
    """Decide the process exit code from the issues' severities and threshold.

    - Any 'Critical' issue → EXIT_CRITICAL (2), regardless of threshold.
    - Else if a threshold is set and the score exceeds it → EXIT_THRESHOLD (1).
    - Else 0.
    """
    if "Critical" in result_severities:
        return EXIT_CRITICAL
    if threshold > 0.0 and global_score > threshold:
        return EXIT_THRESHOLD
    return EXIT_OK


# ── #2 suppressions ────────────────────────────────────────────────────

@dataclass
class Suppression:
    directive: str
    reason: str
    bad_value: str = ""          # "" = suppress the directive regardless of value
    date: str = ""

    def matches(self, issue: dict) -> bool:
        if issue.get("directive", "").lower() != self.directive.lower():
            return False
        if self.bad_value and issue.get("bad_value", "").lower() != self.bad_value.lower():
            return False
        return True


class SuppressionStore:
    """A small JSON file of accepted-risk suppressions (default .caspar-suppress.json)."""

    DEFAULT_PATH = ".caspar-suppress.json"

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or self.DEFAULT_PATH)
        self.items: list[Suppression] = []
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self.items = [Suppression(**d) for d in raw.get("suppressions", [])]

    def add(self, directive: str, reason: str, bad_value: str = "",
            date: str = "") -> None:
        # Replace an existing suppression for the same (directive, bad_value).
        self.items = [s for s in self.items
                      if not (s.directive.lower() == directive.lower()
                              and s.bad_value.lower() == bad_value.lower())]
        self.items.append(Suppression(directive, reason, bad_value, date))

    def save(self) -> None:
        self.path.write_text(json.dumps(
            {"suppressions": [s.__dict__ for s in self.items]}, indent=2),
            encoding="utf-8")

    def is_suppressed(self, issue: dict) -> Suppression | None:
        for s in self.items:
            if s.matches(issue):
                return s
        return None

    def partition(self, issues: list[dict]) -> tuple[list[dict], list[dict]]:
        """Split issues into (active, suppressed)."""
        active, suppressed = [], []
        for i in issues:
            (suppressed if self.is_suppressed(i) else active).append(i)
        return active, suppressed


# ── #9 catalog fuzzy search ────────────────────────────────────────────

def search_catalog(rows: list[dict], term: str, limit: int = 10) -> list[dict]:
    """Fuzzy-search catalog rows (from BenchmarkFetcher.list_available) by
    service key and benchmark title. Returns the best matches, best first."""
    term = term.lower().strip()
    scored: list[tuple[float, dict]] = []
    for r in rows:
        hay = f"{r.get('service','')} {r.get('service_name','')}".lower()
        # Substring match dominates; otherwise fall back to fuzzy ratio.
        if term in hay:
            score = 1.0
        else:
            # Fuzzy against the service key and each word of the display name,
            # so "postgres" matches "PostgreSQL" without matching "sles12".
            words = r.get("service_name", "").lower().split() + [r.get("service", "")]
            score = max((SequenceMatcher(None, term, w).ratio() for w in words),
                        default=0.0)
        if score >= 0.6:
            scored.append((score, r))
    scored.sort(key=lambda x: (-x[0], x[1].get("service", "")))
    return [r for _, r in scored[:limit]]
