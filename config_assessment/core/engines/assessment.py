"""
core/engines/assessment.py
-----------------------------
Assessment Engine (CVM Core).

Detects the right plugin for an input, parses it into directives, infers
the system profile, and matches directives (present or absent) against the
Knowledge Base's rules to produce Misconfiguration issues.

This engine never contains technology-specific (Apache/SSH/Kubernetes/...)
logic — that lives entirely in Plugins (config_assessment/plugins/), which
implement the Target contract (core/target.py) that this engine consumes.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from config_assessment.core.engines import scoring
from config_assessment.core.models import Directive, Misconfiguration, SystemProfile
from config_assessment.core.target import Target

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


def select_plugin(path: str) -> Target:
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

def hash_input(path: str) -> str:
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

def check_condition(required_when: str, all_parsed_names: set[str]) -> bool:
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


def match_value_rules(db, target_name: str, directive: Directive) -> list[Misconfiguration]:
    """
    Return the value-rules a directive triggers.

    Two matching modes, in order:

    1. Exact match (the O(1) hot path) — bad_value == directive.value. Covers
       scalar directives like ``server_tokens on``.

    2. Token-subset match — for list-valued directives like
       ``ssl_protocols SSLv3 TLSv1 TLSv1.1`` a single config line carries several
       bad_value tokens stored as separate rules ('SSLv3', 'TLSv1 TLSv1.1'). A
       rule fires when *all* of its bad_value tokens appear among the directive's
       tokens. This is what makes detection robust on real-world configs, not
       just the worst-case fixtures where each bad_value sits on its own line.

    Results are de-duplicated by rule id so a rule matched both ways is not
    double-counted.
    """
    matched: dict[int, Misconfiguration] = {}

    for row in db.get_misconfigurations(
        target_name=target_name,
        directive=directive.name,
        bad_value=directive.value,
    ):
        matched[row.id] = row

    directive_tokens = set(directive.value.split())
    if len(directive_tokens) > 1:
        for rule in db.get_value_rules(target_name, directive.name):
            if rule.id in matched:
                continue
            rule_tokens = set(rule.bad_value.split())
            # Subset, but never an empty rule (would match everything).
            if rule_tokens and rule_tokens <= directive_tokens:
                matched[rule.id] = rule

    return list(matched.values())


def detect_absences(
    absence_rules: list[Misconfiguration],
    all_parsed_names: set[str],
    directives: list[Directive],
) -> list[Misconfiguration]:
    """
    Return absence rules whose condition is met and whose directive is absent.

    For rules with expected_value_prefix='': pure absence — the directive does
    not appear anywhere in the config.

    For rules with expected_value_prefix!='': multi-instance directives (e.g.
    add_header) — the directive is present but none of its instances has a value
    starting with expected_value_prefix.

    Each returned rule has detected_in_scan=True and source_directive=None.
    """
    found: list[Misconfiguration] = []
    for rule in absence_rules:
        if not check_condition(rule.required_when, all_parsed_names):
            continue
        if rule.expected_value_prefix:
            # Multi-instance: check that no matching directive instance exists.
            # Use token membership rather than startswith because the header name
            # may not be the first token (e.g. Apache "Header always set X-Frame-Options").
            prefix = rule.expected_value_prefix
            if not any(
                d.name == rule.directive and prefix in d.value.split()
                for d in directives
            ):
                rule.detected_in_scan = True
                rule.source_directive = None
                found.append(rule)
        else:
            # Pure absence: directive not present at all
            if rule.directive not in all_parsed_names:
                rule.detected_in_scan = True
                rule.source_directive = None
                found.append(rule)
    return found


# ------------------------------------------------------------------ #
# Score adjustment (AV/Au worst-case merge + environment profile cap)  #
# ------------------------------------------------------------------ #

# Access Vector ordering, most exposed → least. Used to cap AV downward for an
# environment profile (an internal service cannot be scored as Network-facing).
_AV_ORDER = {"N": 3, "A": 2, "L": 1}


def cap_av(av: str, ceiling: str) -> str:
    """Return the less-exposed of `av` and `ceiling` (cap AV at the ceiling)."""
    return av if _AV_ORDER.get(av, 3) <= _AV_ORDER.get(ceiling, 3) else ceiling


def score_issues(
    issues: list[Misconfiguration],
    profile: SystemProfile,
    av_ceiling: str | None = None,
) -> list[Misconfiguration]:
    """
    Adjust AV/Au on each issue using the system profile (worst-case),
    then recompute BaseScore and TemporalScore.

    When `av_ceiling` is set (an explicit environment profile), the effective
    Access Vector is *capped* at that level afterwards — so an 'internal' or
    'dev' deployment lowers exposure instead of the worst-case default. Without
    it, the original worst-case behaviour is unchanged.
    """
    for issue in issues:
        adj_av, adj_au = scoring.adjust_av_au(
            misconfig_base_av=issue.av,
            misconfig_base_au=issue.au,
            system_av=profile.av,
            system_au=profile.au,
        )
        if av_ceiling:
            adj_av = cap_av(adj_av, av_ceiling)
        issue.av = adj_av
        issue.au = adj_au
        issue.base_score = scoring.base_score(adj_av, adj_au, issue.ac, issue.c, issue.i, issue.a)
        issue.temporal_score = scoring.temporal_score(issue.base_score, issue.gel, issue.grl)
    return issues
