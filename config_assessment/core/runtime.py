"""
core/runtime.py
---------------
CVM Core — top-level pipeline orchestrator.

This is the performance-critical, zero-LLM path.
For any given input file (and version), it produces the same ScanResult.

Pipeline (executed for every scan), each step delegated to its named engine
under config_assessment.core.engines:
  1. detect()           — select the right plugin(s) for this input   [Assessment Engine]
  2. parse_config()     — extract normalised directives (via plugin)  [Plugin]
  3. get_profile()      — infer system-level AV and Au (via plugin)   [Plugin]
  4. scan()             — lookup each directive in the database       [Assessment Engine]
  5. score()             — adjust AV/Au, recompute temporal scores    [Assessment Engine]
  5b version-amplify    — amplify version-exposing misconfigs (F1)    [Assessment Engine]
  6. detect_chains()    — subset-match active directives              [Attack Chain Engine]
  7. aggregate()        — compute global score from worst-case scores [Aggregation Engine]
  8. report()            — assemble ScanResult

Database knowledge is pre-calculated at build time; lookup is O(1) per directive.
EXCEPTION (F1): when a version is supplied, step 5b consults the NVD for the
version's exploitability. This is the one network-touching step in runtime — it
is online-first with a 24h persistent cache, and degrades to a ×1.0 no-op when
there is no version, no network, or an unknown product. Without a version the
runtime stays fully offline and deterministic, as before.

This module is a thin orchestrator only — it contains no scoring, matching
or aggregation logic of its own. `scan()` is the only public function
external code should call.
"""

from __future__ import annotations

import logging

from config_assessment.core.db.database import Database
from config_assessment.core.engines import assessment, attack_chain
from config_assessment.core.engines.aggregation import aggregate_scan
from config_assessment.core.engines.assessment import (  # noqa: F401  (compat re-exports)
    _REGISTRY,
    cap_av as _cap_av,
    hash_input as _hash_input,
    register_plugin,
    registered_plugins,
    select_plugin as _select_plugin,
)
from config_assessment.core.engines.scoring import aggregate as _ccss_aggregate, severity_label
from config_assessment.core.manifest import build_manifest
from config_assessment.core.models import (
    Misconfiguration,
    ScanResult,
    SystemProfile,
)

logger = logging.getLogger(__name__)


# Environment profiles: override the system exposure (AV/Au) the scoring uses.
# The default (None) keeps the plugin's inferred profile (worst case). A named
# profile reflects how the service is actually deployed, which changes the
# Access Vector — an internal service is Adjacent, a dev box is Local.
ENV_PROFILES = {
    "production": ("N", "N"),   # internet-facing, no auth boundary (== default worst case)
    "internal":   ("A", "N"),   # reachable only from an adjacent/internal network
    "dev":        ("L", "N"),   # local/dev only, not network-exposed
}


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


def scan(input_path: str, db: Database, *, version: str | None = None,
         auto_detect_version: bool = True, image: str | None = None,
         env_profile: str | None = None) -> ScanResult:
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
        are unaffected. An explicit value here takes precedence over
        auto-detection.
    auto_detect_version:
        When True (default) and *version* is None, attempt a best-effort,
        offline detection of the service version (docker tag → binary on PATH →
        config text). Deterministic per environment.
    image:
        Optional Docker image reference (e.g. "httpd:2.4.58") used as a hint for
        version auto-detection.

    Returns
    -------
    ScanResult
        Complete, self-contained result of the scan.
    """
    logger.info("[scan] Starting scan: %s (version=%s)", input_path, version or "unknown")

    # 1. Detect
    plugin = assessment.select_plugin(input_path)
    meta = plugin.metadata()
    logger.info("[scan] Plugin selected: %s", meta.name)

    # 1b. Best-effort version detection (only if the caller didn't supply one).
    if version is None and auto_detect_version:
        from config_assessment.core.input_resolver import detect_version
        version = detect_version(meta.name, input_path, image=image)
        if version:
            logger.info("[scan] Auto-detected version: %s", version)

    # 2. Parse
    directives = plugin.parse_config(input_path)
    logger.info("[scan] Parsed %d directives", len(directives))

    # 3. Profile
    profile: SystemProfile = plugin.get_profile(directives)
    # An explicit environment profile overrides the inferred exposure (AV/Au):
    # e.g. an 'internal' deployment is Adjacent, not Network-facing.
    if env_profile:
        override = ENV_PROFILES.get(env_profile)
        if override:
            profile = SystemProfile(av=override[0], au=override[1])
            logger.info("[scan] Env profile '%s' → AV:%s Au:%s",
                        env_profile, profile.av, profile.au)
    logger.info("[scan] Profile — AV:%s Au:%s", profile.av, profile.au)

    # 4. Scan — lookup each directive in the DB
    issues: list[Misconfiguration] = []
    for directive in directives:
        for row in assessment.match_value_rules(db, meta.name, directive):
            row.detected_in_scan = True
            row.source_directive = directive
            issues.append(row)

    logger.info("[scan] %d value-rule issues found before absence check", len(issues))

    # 4b. Absence detection — directives that should be present but are missing
    all_parsed_names: set[str] = {d.name for d in directives}
    absence_rules = db.get_absence_rules(meta.name)
    absence_issues = assessment.detect_absences(absence_rules, all_parsed_names, directives)
    issues.extend(absence_issues)
    if absence_issues:
        logger.info("[scan] %d absence issues detected", len(absence_issues))

    logger.info("[scan] %d total issues before scoring", len(issues))

    # 4c. Unknown-directive detection (deterministic, Layers 1-2). Surface every
    # parsed directive the knowledge base has no rule for, with heuristic risk
    # triage. This is NOT scored — it flags coverage gaps (e.g. a directive new
    # in a later service version) so they are no longer invisible.
    from config_assessment.core.unknown_directives import surface_and_triage
    _target_rules = db.get_all_misconfigurations(meta.name)
    known_names = {m.directive for m in _target_rules}
    unknown_directives = surface_and_triage(directives, known_names)
    if unknown_directives:
        logger.info("[scan] %d unknown directive(s) surfaced (%d suspicious)",
                    len(unknown_directives),
                    sum(1 for u in unknown_directives if u.suspicious))

    # 5. Score — adjust AV/Au, recompute scores with system profile
    # An env profile caps the AV downward (internal=A, dev=L); production/None
    # keep the worst-case behaviour.
    _av_ceiling = ENV_PROFILES[env_profile][0] if env_profile in (
        "internal", "dev") else None
    issues = assessment.score_issues(issues, profile, av_ceiling=_av_ceiling)

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
    fired_chains = attack_chain.detect_chains(
        all_parsed_directives, active_misconfig_directives, known_chains)
    fired_chains = attack_chain.amplify_chains(fired_chains, issues)

    # 7. Aggregate
    global_base, global_temporal = aggregate_scan(issues, fired_chains)

    # 8. Assemble result
    result = ScanResult(
        target_name=meta.name,
        input_path=input_path,
        input_hash=assessment.hash_input(input_path),
        profile=profile,
        issues=issues,
        chains=fired_chains,
        global_base_score=global_base,
        global_temporal_score=global_temporal,
        severity=severity_label(global_temporal),
        total_directives_scanned=len(directives),
        total_issues_found=len(issues),
        total_chains_detected=len(fired_chains),
        detected_version=version,
        version_exploits=version_exploits,
        exploit_lookup_failed=exploit_lookup_failed,
        version_cves_checked=version_cves_checked,
        unknown_directives=unknown_directives,
        # Reproducibility manifest: what code + knowledge base produced these
        # scores. Matching manifest + matching input_hash ⇒ identical scores.
        manifest=build_manifest(db.path, meta.name,
                                rules_count=len(_target_rules), conn=db.conn),
    )

    logger.info(
        "[scan] Complete — score=%.1f (%s), issues=%d, chains=%d",
        result.global_temporal_score,
        result.severity,
        result.total_issues_found,
        result.total_chains_detected,
    )
    return result
