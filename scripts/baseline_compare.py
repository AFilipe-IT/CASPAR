#!/usr/bin/env python3
"""
scripts/baseline_compare.py — CASPAR vs external baselines.

Compares CASPAR's findings against established scanners on the SAME input, to
position the AMiSA methodology in the dissertation:

  - Trivy (`trivy config`) on IaC (Terraform) and Dockerfiles.
  - OpenSCAP (`oscap`) on OS config — only if installed (optional).

The point is NOT "who finds more". It is a qualitative + quantitative contrast:
both detect misconfigurations, but CASPAR attaches a REPRODUCIBLE CCSS SCORE and
a narrative to each, where Trivy/OpenSCAP give a fixed severity label / pass-fail.
Overlap and gaps (each tool's blind spots) are the interesting findings.

Run:
    python -m scripts.baseline_compare                 # all available baselines
    python -m scripts.baseline_compare --json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _caspar_findings(rel_path: str) -> dict:
    """CASPAR's findings on a file: count, score, per-issue directive+score."""
    import cli.main as m
    m._discover_plugins()
    from config_assessment.core.db.database import Database
    from config_assessment.core import runtime
    with Database(str(ROOT / "ccss.db")) as db:
        r = runtime.scan(str(ROOT / rel_path), db)
    return {
        "count": len(r.issues),
        "score": round(r.global_temporal_score, 1),
        "severity": r.severity,
        "issues": sorted(
            [{"directive": i.directive, "score": round(i.temporal_score, 1)}
             for i in r.issues], key=lambda x: -x["score"]),
    }


def _trivy_findings(rel_path: str) -> dict:
    """Trivy `config` findings on the same file (severity-labelled, no score)."""
    if not shutil.which("trivy"):
        return {"skipped": "trivy not installed"}
    try:
        out = subprocess.run(
            ["trivy", "config", "-f", "json", "--quiet", str(ROOT / rel_path)],
            capture_output=True, text=True, timeout=180)
        data = json.loads(out.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"skipped": f"trivy error: {exc}"}

    findings, sev_counts = [], {}
    for res in data.get("Results", []) or []:
        for mc in res.get("Misconfigurations", []) or []:
            sev = mc.get("Severity", "UNKNOWN")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            findings.append({"id": mc.get("ID"), "severity": sev,
                             "title": (mc.get("Title") or "")[:60]})
    return {"count": len(findings), "by_severity": sev_counts,
            "findings": findings}


def _oscap_available() -> bool:
    return bool(shutil.which("oscap"))


# Files scanned by each IaC/container baseline (Trivy).
_TRIVY_TARGETS = [
    "test_target/azure_storage_vulnerable.tf",
    "test_target/Dockerfile.vulnerable",
]


def run() -> dict:
    report = {"trivy": {}, "oscap": {"available": _oscap_available()}}
    for rel in _TRIVY_TARGETS:
        if not (ROOT / rel).exists():
            report["trivy"][rel] = {"skipped": "fixture missing"}
            continue
        report["trivy"][rel] = {
            "caspar": _caspar_findings(rel),
            "trivy": _trivy_findings(rel),
        }
    return report


def _print(report: dict) -> None:
    print("\n" + "=" * 68)
    print("  CASPAR vs TRIVY — IaC / container misconfiguration detection")
    print("=" * 68)
    for rel, cmp in report["trivy"].items():
        name = Path(rel).name
        if "skipped" in cmp:
            print(f"\n  {name}: skipped ({cmp['skipped']})")
            continue
        c, t = cmp["caspar"], cmp["trivy"]
        print(f"\n  ── {name}")
        print(f"     CASPAR : {c['count']:>2} findings · "
              f"score {c['score']}/10 [{c['severity']}]  "
              f"(reproducible CCSS per finding)")
        if "skipped" in t:
            print(f"     Trivy  : skipped ({t['skipped']})")
        else:
            sev = " ".join(f"{k}:{v}" for k, v in sorted(t["by_severity"].items()))
            print(f"     Trivy  : {t['count']:>2} findings · "
                  f"[{sev}]  (fixed severity label)")
            # Overlap by directive name vs Trivy title/id is fuzzy — report the
            # counts and let the thesis discuss specific overlaps qualitatively.
    print("\n" + "=" * 68)
    if report["oscap"]["available"]:
        print("  OpenSCAP: installed — run the OS-config comparison separately")
        print("  (needs an Ubuntu config target; see handoff §8).")
    else:
        print("  OpenSCAP: NOT installed — `sudo apt-get install openscap-scanner`")
        print("  (needed for the Ubuntu OS-config baseline).")
    print("=" * 68 + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not (ROOT / "ccss.db").exists():
        print("ccss.db not found — restore from data/ccss_canonical.sql",
              file=sys.stderr)
        sys.exit(2)
    report = run()
    print(json.dumps(report, indent=2)) if args.json else _print(report)


if __name__ == "__main__":
    main()
