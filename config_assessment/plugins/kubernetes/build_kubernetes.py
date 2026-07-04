"""
plugins/kubernetes/build_kubernetes.py
--------------------------------------
Seed the curated Kubernetes ruleset (CIS K8s Benchmark §5) into the DB.
Deterministic — no LLM, no network (see build/curated_build.py).

Usage:
    python3 -m config_assessment.plugins.kubernetes.build_kubernetes [--db ccss.db]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from config_assessment.build.curated_build import run_curated_build
from config_assessment.plugins.kubernetes.rules import ABSENCE_RULES, ENTRIES


def run_build(db_path: str = "ccss.db") -> dict:
    from config_assessment.plugins.kubernetes import KubernetesPlugin
    return run_curated_build(
        meta=KubernetesPlugin().metadata(),
        entries=ENTRIES,
        absence_rules=ABSENCE_RULES,
        chains_json=Path(__file__).parent / "chains.json",
        db_path=db_path,
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="ccss.db")
    stats = run_build(ap.parse_args().db)
    print(f"kubernetes: {stats['misconfigs']} rules, {stats['chains']} chains seeded")
