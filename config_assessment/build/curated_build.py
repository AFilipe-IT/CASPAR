"""
config_assessment/build/curated_build.py
----------------------------------------
Deterministic build for plugins whose rules are HAND-CURATED (the IaC targets:
kubernetes, dockerfile).

The LLM build pipeline exists to extract rules out of a 400-page benchmark
PDF. The IaC plugins don't need it: their rulesets are small, curated line by
line from the CIS benchmark with hand-reviewed CCSS metrics. This build is
therefore 100% deterministic — no LLM, no network: metrics in → NISTIR 7502
formulas → scores in the DB. Same invariant as the runtime, one stage earlier.

Idempotent: upserts by (target, directive, bad_value); safe to re-run.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from config_assessment.core import ccss
from config_assessment.core.db.database import Database
from config_assessment.core.models import AttackChain, Misconfiguration, TargetMetadata

logger = logging.getLogger("ccss")


def run_curated_build(*, meta: TargetMetadata, entries: list, absence_rules: list,
                      chains_json: Path | None, db_path: str) -> dict:
    """Seed one curated plugin's rules (and chains) into the DB.

    entries:       (directive, bad, good, section, ac, c, i, a, just, rec)
    absence_rules: (directive, good, section, ac, c, i, a, just, rec)
    Returns {"misconfigs": n, "chains": n}.
    """
    n_rules = n_chains = 0
    with Database(db_path) as db:
        db.upsert_target(meta)

        def _upsert(directive, bad, good, section, ac, c, i, a, just, rec,
                    rule_type):
            nonlocal n_rules
            bs = ccss.base_score("N", "N", ac, c, i, a)
            db.upsert_misconfiguration(Misconfiguration(
                target_name=meta.name, directive=directive, bad_value=bad,
                good_value=good, ac=ac, c=c, i=i, a=a,
                base_score=bs, temporal_score=ccss.temporal_score(bs, "ND", "ND"),
                gel="ND", grl="ND", cis_section=section,
                justification=just, recommendation=rec, rule_type=rule_type,
            ))
            n_rules += 1

        for (directive, bad, good, section, ac, c, i, a, just, rec) in entries:
            _upsert(directive, bad, good, section, ac, c, i, a, just, rec,
                    rule_type="value")
        for (directive, good, section, ac, c, i, a, just, rec) in absence_rules:
            _upsert(directive, "", good, section, ac, c, i, a, just, rec,
                    rule_type="absence")

        if chains_json and chains_json.exists():
            for c in json.loads(chains_json.read_text(encoding="utf-8")):
                db.upsert_attack_chain(AttackChain(
                    chain_id=c["chain_id"], target_name=c["target_name"],
                    misconfig_directives=c["misconfig_directives"],
                    amplification=c["amplification"],
                    justification=c["justification"],
                    cross_target=c.get("cross_target", False),
                ))
                n_chains += 1

    logger.info("[curated-build] %s: %d rules, %d chains",
                meta.name, n_rules, n_chains)
    return {"misconfigs": n_rules, "chains": n_chains}
