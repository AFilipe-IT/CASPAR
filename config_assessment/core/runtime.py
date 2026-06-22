"""
core/runtime.py
---------------
Runtime scan engine.

This is the performance-critical, zero-LLM path.
For any given input file (and version), it produces the same ScanResult.

Pipeline (executed for every scan):
  1. detect()           — select the right plugin(s) for this input
  2. parse_config()     — extract normalised directives (via plugin)
  3. get_profile()      — infer system-level AV and Au (via plugin rule engine)
  4. scan()             — lookup each directive in the database
  5. score()            — adjust AV/Au, recompute temporal scores
  5b version-amplify    — amplify version-exposing misconfigs (F1, see below)
  6. detect_chains()    — subset-match active directives against known chains
  7. aggregate()        — compute global score from worst-case temporal scores
  8. report()           — assemble ScanResult

Database knowledge is pre-calculated at build time; lookup is O(1) per directive.
EXCEPTION (F1): when a version is supplied, step 5b consults the NVD for the
version's exploitability. This is the one network-touching step in runtime — it
is online-first with a 24h persistent cache, and degrades to a ×1.0 no-op when
there is no version, no network, or an unknown product. Without a version the
runtime stays fully offline and deterministic, as before.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import config_assessment.core.ccss as ccss
from config_assessment.core.db.database import Database
from config_assessment.core.models import (
    AttackChain,
    Misconfiguration,
    ScanResult,
    SystemProfile,
)
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


def _match_value_rules(db, target_name: str, directive) -> list[Misconfiguration]:
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


def _detect_absences(
    absence_rules: list[Misconfiguration],
    all_parsed_names: set[str],
    directives: list,
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
        if not _check_condition(rule.required_when, all_parsed_names):
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

def _amplify_version_exposure(
    issues: list[Misconfiguration],
    product: str,
    version: str | None,
    exposing_directives: tuple[str, ...],
    db=None,
) -> tuple[list[dict], bool, int]:
    """Amplify version-exposing misconfigs and resolve public exploits (F1).

    A misconfig that discloses the service version (declared by the plugin via
    `exposing_directives`) becomes more critical when that version is actually
    exploitable. Multiplies its temporal_score by version_amplification(info),
    capped at 10.0. Other misconfigs are never touched.

    Independently of the amplification factor, the version's CVEs are looked up
    in Exploit-DB; the returned list of public exploits (as dicts) is attached to
    the ScanResult so the report can show them with an alert.

    Returns (exploits, lookup_failed, cves_checked). lookup_failed is True when
    the NVD query errored (report says "could not check"). cves_checked is the
    number of CVEs the lookup examined — >0 with no exploits means "checked and
    clean". Degrades to ([], False, 0) when there is no version, an unknown
    product, or no exposing directive present.
    """
    if not version or not exposing_directives:
        return [], False, 0
    exposed = [m for m in issues if m.directive in exposing_directives]
    if not exposed:
        return [], False, 0

    # Lazy imports: only reached when a version is present, so the offline path
    # never imports the network/exploit modules.
    from config_assessment.enrichment.cve_enricher import get_version_exploit_info, version_amplification
    from config_assessment.enrichment.exploit_enricher import search_exploits_for_cves

    # DB-first: a pre-fetched row is offline and deterministic.
    info = get_version_exploit_info(product, version, db=db)

    factor = version_amplification(info)
    if factor > 1.0:
        note = _version_risk_note(product, version, info)
        for m in exposed:
            m.temporal_score = min(round(m.temporal_score * factor, 1), 10.0)
            m.version_amplification = factor
            m.version_risk_note = note
            logger.info(
                "[scan] Version-amplified %s ×%.2f → %.1f (%s)",
                m.directive, factor, m.temporal_score, note,
            )

    # lookup_failed propagates the NVD failure so the report can distinguish
    # three states: exploits found / lookup failed / checked-and-clean.
    lookup_failed = bool(info and info.lookup_failed)
    cves_checked = info.cve_count if (info and not info.lookup_failed) else 0
    # If the info came from the DB it already carries resolved exploits — use
    # them directly (no searchsploit). Otherwise resolve from the CVE ids.
    if info and info.exploits is not None:
        exploits = list(info.exploits)
    elif info:
        exploits = [vars(e) for e in search_exploits_for_cves(info.cve_ids)]
    else:
        exploits = []
    if exploits:
        logger.info(
            "[scan] %d public exploit(s) found for %s %s",
            len(exploits), product, version,
        )
    return exploits, lookup_failed, cves_checked


def _version_risk_note(product: str, version: str, info) -> str:
    """One-line, human-readable reason shown in the dashboard drawer (F1)."""
    name = {"apache-httpd": "Apache", "nginx": "Nginx"}.get(product, product)
    if info is None:
        return f"{name} {version} — exploitable version detected"
    if info.kev_count > 0:
        return (f"{name} {version} — {info.kev_count} KEV-listed "
                f"CVE{'s' if info.kev_count != 1 else ''} detected")
    return (f"{name} {version} — {info.cve_count} known "
            f"CVE{'s' if info.cve_count != 1 else ''} detected")


def scan(input_path: str, db: Database, *, version: str | None = None) -> ScanResult:
    """
    Run a full scan of *input_path* and return a ScanResult.

    This is the only public function in this module that external code
    should call.  Everything else is an implementation detail.

    Parameters
    ----------
    input_path:
        Path to the configuration file or directory to scan.
    db:
        Open Database handle (see config_assessment.core.db.database).
    version:
        Detected service version (e.g. "2.4.51"), or None when the input mode
        cannot reveal it. Propagated to ScanResult.detected_version and used by
        version-aware scoring (F1). Optional and keyword-only — existing callers
        are unaffected.

    Returns
    -------
    ScanResult
        Complete, self-contained result of the scan.
    """
    logger.info("[scan] Starting scan: %s (version=%s)", input_path, version or "unknown")

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
        for row in _match_value_rules(db, meta.name, directive):
            row.detected_in_scan = True
            row.source_directive = directive
            issues.append(row)

    logger.info("[scan] %d value-rule issues found before absence check", len(issues))

    # 4b. Absence detection — directives that should be present but are missing
    all_parsed_names: set[str] = {d.name for d in directives}
    absence_rules = db.get_absence_rules(meta.name)
    absence_issues = _detect_absences(absence_rules, all_parsed_names, directives)
    issues.extend(absence_issues)
    if absence_issues:
        logger.info("[scan] %d absence issues detected", len(absence_issues))

    logger.info("[scan] %d total issues before scoring", len(issues))

    # 5. Score — adjust AV/Au, recompute scores with system profile
    issues = _score_issues(issues, profile)

    # 5b. Version-aware amplification + exploit lookup (F1). No-op without a
    # version. The plugin declares which directives expose the version, so the
    # core never hardcodes directive names.
    version_exploits, exploit_lookup_failed, version_cves_checked = _amplify_version_exposure(
        issues, meta.name, version, meta.version_exposing_directives, db=db,
    )

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
        detected_version=version,
        version_exploits=version_exploits,
        exploit_lookup_failed=exploit_lookup_failed,
        version_cves_checked=version_cves_checked,
    )

    logger.info(
        "[scan] Complete — score=%.1f (%s), issues=%d, chains=%d",
        result.global_temporal_score,
        result.severity,
        result.total_issues_found,
        result.total_chains_detected,
    )
    return result
