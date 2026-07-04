"""
plugins/dockerfile/build_dockerfile.py
--------------------------------------
Seed the curated Dockerfile ruleset (CIS Docker Benchmark) into the DB.
Deterministic — no LLM, no network (see build/curated_build.py).

Usage:
    python3 -m config_assessment.plugins.dockerfile.build_dockerfile [--db ccss.db]
"""

from __future__ import annotations

import argparse

from config_assessment.build.curated_build import run_curated_build
from config_assessment.plugins.dockerfile.rules import ABSENCE_RULES, ENTRIES


def run_build(db_path: str = "ccss.db") -> dict:
    from config_assessment.plugins.dockerfile import DockerfilePlugin
    return run_curated_build(
        meta=DockerfilePlugin().metadata(),
        entries=ENTRIES,
        absence_rules=ABSENCE_RULES,
        chains_json=None,
        db_path=db_path,
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="ccss.db")
    stats = run_build(ap.parse_args().db)
    print(f"dockerfile: {stats['misconfigs']} rules seeded")
