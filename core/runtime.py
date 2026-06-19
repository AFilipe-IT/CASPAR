"""
core/runtime.py
---------------
Runtime scan engine.

This is the performance-critical, zero-LLM, deterministic path.
For any given input file, it always produces the same ScanResult.

Pipeline (executed for every scan):
  1. detect()           — select the right plugin(s) for this input
  2. parse_config()     — extract normalised directives (via plugin)
  3. get_profile()      — infer system-level AV and Au (via plugin rule engine)
  4. scan()             — lookup each directive in the database
  5. score()            — adjust AV/Au, recompute temporal scores
  6. detect_chains()    — subset-match active directives against known chains
  7. aggregate()        — compute global score from worst-case temporal scores
  8. report()           — assemble ScanResult

Zero external calls.  All knowledge is in the database, pre-calculated
at build time.  Lookup is O(1) per directive (index on target+directive+value).
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import core.ccss as ccss
from core.db.database import Database
from core.models import (
    AttackChain,
    Misconfiguration,
    ScanResult,
    SystemProfile,
)
from core.target import Target

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Plugin registry                                                      #
# ------------------------------------------------------------------ #

_REGISTRY: list[Target] = []


def register_plugin(plugin: Target) -> None:
    """Register a plugin instance.  Called from plugins/<name>/__init__.py."""
    _REGISTRY.append(plugin)
    meta = plugin.metadata()
    logger.debug("Registered plugin: %s v%s", meta.name, meta.version)


def registered_plugins() -> list[Target]:
    """Return a copy of the current plugin registry."""
    return list(_REGISTRY)


# ------------------------------------------------------------------ #
# Detection                                                            #
# ------------------------------------------------------------------ #

def _select_plugin(path: str) -> Target:
    """
    Choose the best plugin for *path*.

    Raises RuntimeError if no plugin matches.
    If multiple match, the one with the highest metadata.priority wins.
    """
    candidates = [p for p in _REGISTRY if p.detect(path)]
    if not candidates:
        raise RuntimeError(
            f"No registered plugin can handle input: {path}\n"
            f"Registered plugins: {[p.metadata().name for p in _REGISTRY]}"
        )
    return max(candidates, key=lambda p: p.detection_confidence(path))


# ------------------------------------------------------------------ #
# Input hashing                                                        #
# ------------------------------------------------------------------ #

def _hash_input(path: str) -> str:
    """SHA-256 of the input file (or directory tree, sorted)."""
    p = Path(path)
    h = hashlib.sha256()
    if p.is_dir():
        for f in sorted(p.rglob("*")):
            if f.is_file():
                h.update(f.read_bytes())
    else:
        h.update(p.read_bytes())
    return h.hexdigest()


# ------------------------------------------------------------------ #
# Absence detection                                                    #
# ------------------------------------------------------------------ #

def _check_condition(required_when: str, all_parsed_names: set[str]) -> bool:
    """
    Evaluate the firing condition of an absence rule against the set of
    directive names parsed from the config.

    Supported forms:
      "always"              — fire unconditionally
      "if_directive:X"      — fire only when directive X is present
      "if_not_directive:X"  — fire only when directive X is absent

    Scope note (v1 limitation): all_parsed_names is the *global* union
    across all server/location blocks. A condition on ssl_certificate fires
    if ssl_certificate appears anywhere in the config, not per-server.
    This is correct for directives configured at the http{} level (ssl_protocols)
    and a documented approximation for per-server directives.
    """
    if required_when == "always":
        return True
    if required_when.startswith("if_directive:"):
        return required_when[len("if_directive:"):] in all_parsed_names
    if required_when.startswith("if_not_directive:"):
        return required_when[len("if_not_directive:"):] not in all_parsed_names
    return False


def _detect_absences(
    absence_rules: list[Misconfiguration],
    all_parsed_names: set[str],
) -> list[Misconfiguration]:
    """
    Return absence rules whose condition is met and whose directive is
    not present anywhere in the parsed config.

    Each returned rule has detected_in_scan=True and source_directive=None
    (there is no source line — the issue is the absence of a line).
    """
    found: list[Misconfiguration] = []
    for rule in absence_rules:
        if not _check_condition(rule.required_when, all_parsed_names):
            continue
        if rule.directive not in all_parsed_names:
            rule.detected_in_scan = True
            rule.source_directive = None
            found.append(rule)
    return found


# ------------------------------------------------------------------ #
# Chain detection                                                      #
# ------------------------------------------------------------------ #

def _detect_chains(
    active_directives: set[str],
    misconfig_directives: set[str],
    chains: list[AttackChain],
) -> list[AttackChain]:
    """
    Subset-match directive names against known attack chains.

    A chain fires when TWO conditions are both true:
      1. ALL of its required directives are present in the config (parsed).
      2. AT LEAST ONE of those directives is a confirmed misconfiguration.

    Condition 2 prevents clean configs from triggering chains just because
    a neutral directive like Listen happens to be present.
    """
    fired: list[AttackChain] = []
    for chain in chains:
        required = set(chain.misconfig_directives)
        present = required & active_directives
        has_misconfig = bool(present & misconfig_directives)
        if present == required and has_misconfig:
            chain.active = True
            chain.triggered_by = list(present)
            fired.append(chain)
            logger.info("Chain fired: %s (directives: %s)", chain.chain_id, present)
    return fired


# ------------------------------------------------------------------ #
# Score adjustment and chain amplification                             #
# ------------------------------------------------------------------ #

def _score_issues(
    issues: list[Misconfiguration],
    profile: SystemProfile,
) -> list[Misconfiguration]:
    """
    Adjust AV/Au on each issue using the system profile (worst-case),
    then recompute BaseScore and TemporalScore.
    """
    for issue in issues:
        adj_av, adj_au = ccss.adjust_av_au(
            misconfig_base_av=issue.av,
            misconfig_base_au=issue.au,
            system_av=profile.av,
            system_au=profile.au,
        )
        issue.av = adj_av
        issue.au = adj_au
        issue.base_score = ccss.base_score(adj_av, adj_au, issue.ac, issue.c, issue.i, issue.a)
        issue.temporal_score = ccss.temporal_score(issue.base_score, issue.gel, issue.grl)
    return issues


def _amplify_chains(
    chains: list[AttackChain],
    issues: list[Misconfiguration],
) -> list[AttackChain]:
    """
    For each active chain, compute the amplified score as:
        amplified = max(TemporalScore of constituent issues) × amplification
    capped at 10.0.
    """
    issue_map = {m.directive: m for m in issues}
    for chain in chains:
        if not chain.active:
            continue
        constituent_scores = [
            issue_map[d].temporal_score
            for d in chain.misconfig_directives
            if d in issue_map
        ]
        if constituent_scores:
            chain.amplified_score = ccss.amplified_score(
                max(constituent_scores), chain.amplification
            )
    return chains


# ------------------------------------------------------------------ #
# Main scan entry point                                                #
# ------------------------------------------------------------------ #

def scan(input_path: str, db: Database) -> ScanResult:
    """
    Run a full scan of *input_path* and return a ScanResult.

    This is the only public function in this module that external code
    should call.  Everything else is an implementation detail.

    Parameters
    ----------
    input_path:
        Path to the configuration file or directory to scan.
    db:
        Open Database handle (see core.db.database).

    Returns
    -------
    ScanResult
        Complete, self-contained result of the scan.
    """
    logger.info("[scan] Starting scan: %s", input_path)

    # 1. Detect
    plugin = _select_plugin(input_path)
    meta = plugin.metadata()
    logger.info("[scan] Plugin selected: %s", meta.name)

    # 2. Parse
    directives = plugin.parse_config(input_path)
    logger.info("[scan] Parsed %d directives", len(directives))

    # 3. Profile
    profile: SystemProfile = plugin.get_profile(directives)
    logger.info("[scan] Profile — AV:%s Au:%s", profile.av, profile.au)

    # 4. Scan — lookup each directive in the DB
    issues: list[Misconfiguration] = []
    for directive in directives:
        rows = db.get_misconfigurations(
            target_name=meta.name,
            directive=directive.name,
            bad_value=directive.value,
        )
        for row in rows:
            row.detected_in_scan = True
            row.source_directive = directive
            issues.append(row)

    logger.info("[scan] %d value-rule issues found before absence check", len(issues))

    # 4b. Absence detection — directives that should be present but are missing
    all_parsed_names: set[str] = {d.name for d in directives}
    absence_rules = db.get_absence_rules(meta.name)
    absence_issues = _detect_absences(absence_rules, all_parsed_names)
    issues.extend(absence_issues)
    if absence_issues:
        logger.info("[scan] %d absence issues detected", len(absence_issues))

    logger.info("[scan] %d total issues before scoring", len(issues))

    # 5. Score — adjust AV/Au, recompute scores with system profile
    issues = _score_issues(issues, profile)

    # 6. Detect chains
    # A chain fires when:
    #   (a) ALL its required directives are present in the config (parsed), AND
    #   (b) AT LEAST ONE of those directives is a confirmed misconfiguration (issue).
    # This prevents clean configs from triggering chains just because
    # a directive like Listen is present without any bad value.
    all_parsed_directives = all_parsed_names  # already computed in step 4b
    active_misconfig_directives = {m.directive for m in issues}
    known_chains = db.get_attack_chains(target_name=meta.name)
    fired_chains = _detect_chains(all_parsed_directives, active_misconfig_directives, known_chains)
    fired_chains = _amplify_chains(fired_chains, issues)

    # 7. Aggregate
    all_temporal_scores = [m.temporal_score for m in issues]
    # Also include chain amplified scores
    all_temporal_scores += [c.amplified_score for c in fired_chains if c.active]

    global_temporal = ccss.aggregate(all_temporal_scores)
    global_base = ccss.aggregate([m.base_score for m in issues])

    # 8. Assemble result
    result = ScanResult(
        target_name=meta.name,
        input_path=input_path,
        input_hash=_hash_input(input_path),
        profile=profile,
        issues=issues,
        chains=fired_chains,
        global_base_score=global_base,
        global_temporal_score=global_temporal,
        severity=ccss.severity_label(global_temporal),
        total_directives_scanned=len(directives),
        total_issues_found=len(issues),
        total_chains_detected=len(fired_chains),
    )

    logger.info(
        "[scan] Complete — score=%.1f (%s), issues=%d, chains=%d",
        result.global_temporal_score,
        result.severity,
        result.total_issues_found,
        result.total_chains_detected,
    )
    return result
