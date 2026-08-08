"""
core/engines/attack_chain.py
-----------------------------
Attack Chain Engine (CVM Core).

Subset-matches fired misconfigurations against known attack chains and
computes each active chain's amplified (composite-risk) score.
"""

from __future__ import annotations

import logging

from config_assessment.core.engines import scoring
from config_assessment.core.models import AttackChain, Misconfiguration

logger = logging.getLogger(__name__)


def detect_chains(
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
            # Ordered by the chain's own declaration, not by set iteration:
            # `list(a_set)` varies between processes (PYTHONHASHSEED), which
            # made two identical scans produce byte-different reports. The
            # declared order is also the meaningful one — it reads as the
            # attack's progression (ServerTokens -> ServerSignature).
            chain.triggered_by = [d for d in chain.misconfig_directives
                                  if d in present]
            fired.append(chain)
            logger.info("Chain fired: %s (directives: %s)", chain.chain_id, present)
    return fired


def amplify_chains(
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
        constituents = [issue_map[d] for d in chain.misconfig_directives
                        if d in issue_map]
        if constituents:
            amplified = scoring.amplified_score(
                max(m.temporal_score for m in constituents), chain.amplification
            )
            # Cap by impact kind: a pure information-disclosure chain (only
            # Confidentiality across its misconfigs) cannot reach Critical.
            # Deterministic, auditable ceiling — not a per-chain human call.
            impacts = [(m.c, m.i, m.a) for m in constituents]
            chain.amplified_score = scoring.impact_capped_score(amplified, impacts)
    return chains
