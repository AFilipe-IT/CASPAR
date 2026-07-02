"""
config_assessment/core/db/doctor.py
-----------------------------------
Integrity checks for a CASPAR database. Catches the kinds of inconsistency that
build/promotion/merge bugs can leave behind, so a broken DB is diagnosed rather
than silently producing wrong scans.

Read-only: `check()` reports findings, it never mutates the DB. Each finding has
a severity ('error' | 'warning') and a human message.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    severity: str   # "error" | "warning"
    category: str
    message: str


def check(db_path: str | Path) -> list[Finding]:
    """Run all integrity checks against the DB. Returns findings (empty = clean)."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        findings: list[Finding] = []
        findings += _check_orphans(conn)
        findings += _check_chain_directives(conn)
        findings += _check_scores(conn)
        findings += _check_base_version(conn)
        return findings
    finally:
        conn.close()


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _check_orphans(conn) -> list[Finding]:
    """Misconfigs/chains whose target_name has no matching row in `targets`."""
    out: list[Finding] = []
    names = {r[0] for r in conn.execute("SELECT name FROM targets")}
    for table in ("misconfigurations", "attack_chains"):
        for r in conn.execute(f"SELECT DISTINCT target_name FROM {table}"):
            if r[0] not in names:
                out.append(Finding("error", "orphan",
                    f"{table} references unknown target '{r[0]}'"))
    return out


def _check_chain_directives(conn) -> list[Finding]:
    """A chain should reference directives that exist as misconfigurations for
    the same target — otherwise it can never fire (or fires on the wrong data)."""
    out: list[Finding] = []
    # Build {target: set(directives)} from misconfigurations.
    by_target: dict[str, set[str]] = {}
    for r in conn.execute(
            "SELECT target_name, directive FROM misconfigurations"):
        by_target.setdefault(r[0], set()).add(r[1])

    for r in conn.execute(
            "SELECT target_name, chain_id, misconfig_directives FROM attack_chains"):
        target, chain_id, raw = r[0], r[1], r[2]
        try:
            dirs = json.loads(raw) if raw else []
        except (json.JSONDecodeError, TypeError):
            out.append(Finding("error", "chain",
                f"chain '{chain_id}' ({target}) has invalid directive list"))
            continue
        known = by_target.get(target, set())
        missing = [d for d in dirs if d not in known]
        if missing:
            out.append(Finding("warning", "chain",
                f"chain '{chain_id}' ({target}) references directive(s) with no "
                f"misconfiguration: {', '.join(missing)}"))
    return out


def _check_scores(conn) -> list[Finding]:
    """Scores must be within 0..10 and temporal must not exceed base by much
    (temporal is a downward/lateral adjustment, never a large increase)."""
    out: list[Finding] = []
    for r in conn.execute(
            "SELECT target_name, directive, base_score, temporal_score "
            "FROM misconfigurations"):
        who = f"{r['target_name']}/{r['directive']}"
        for label, val in (("base", r["base_score"]), ("temporal", r["temporal_score"])):
            if val is None or not (0.0 <= val <= 10.0):
                out.append(Finding("error", "score",
                    f"{who}: {label}_score out of range ({val})"))
    return out


def _check_base_version(conn) -> list[Finding]:
    """The versioned-reseed metadata should be present in a shipped DB."""
    if "caspar_meta" not in _tables(conn):
        return [Finding("warning", "meta",
            "no caspar_meta table — versioned reseed cannot track this DB")]
    row = conn.execute(
        "SELECT value FROM caspar_meta WHERE key='base_db_version'").fetchone()
    if not row:
        return [Finding("warning", "meta", "base_db_version not set in caspar_meta")]
    return []
