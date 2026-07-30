#!/usr/bin/env python3
"""
scripts/baseline_compare.py — AEGIS vs external baselines.

Compares AEGIS's findings against established scanners on the SAME input, to
position the AMiSA methodology in the dissertation:

  - Trivy (`trivy config`) on IaC (Terraform) and Dockerfiles.
  - OpenSCAP (`oscap`) on OS config — only if installed (optional).

The point is NOT "who finds more". It is a qualitative + quantitative contrast:
both detect misconfigurations, but AEGIS attaches a REPRODUCIBLE CCSS SCORE and
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
    """AEGIS's findings on a file: count, score, per-issue directive+score."""
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


def _oscap_datastream() -> Path | None:
    """Newest installed Ubuntu SSG datastream (SSG ships up to 22.04)."""
    base = Path("/usr/share/xml/scap/ssg/content")
    if not base.is_dir():
        return None
    dss = sorted(base.glob("ssg-ubuntu*-ds.xml"))
    return dss[-1] if dss else None


# AEGIS's ubuntu target covers these config-based control families; we compare
# OpenSCAP against AEGIS only on this overlapping subset (fair basis — both
# read the same kind of config value). OpenSCAP rule ids carry these tokens.
_OVERLAP_TOKENS = ("sysctl", "accept_redirects", "source_route", "rp_filter",
                   "send_redirects", "syncookies", "icmp_echo", "ip_forward",
                   "randomize_va_space", "suid_dumpable", "log_martians",
                   "pass_max_days", "pass_min_days", "pass_warn_age",
                   "encrypt_method", "login.defs", "password_maximum_age")


def _oscap_findings(profile: str = "cis_level1_server") -> dict:
    """Run `oscap xccdf eval` on the LIVE system with the CIS profile and
    return the results for the config-based subset AEGIS also covers.

    OpenSCAP scores whole-system state; we filter to the overlapping controls
    so the comparison is like-for-like (a config-file value, not a stat/module
    check). Best-effort — returns a skip reason if content is missing."""
    ds = _oscap_datastream()
    if ds is None:
        return {"skipped": "no Ubuntu SSG datastream (apt install ssg-debderived)"}
    import tempfile
    import xml.etree.ElementTree as ET

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
        results_xml = tf.name
    try:
        # eval returns non-zero when any rule fails — that's expected, not an
        # error. Capture as BYTES (no text=True): oscap can emit non-UTF-8 on
        # stderr (paths/locale), which would crash decoding. We don't read the
        # streams anyway — the results go to the --results XML that ET parses.
        subprocess.run(
            ["oscap", "xccdf", "eval",
             "--profile", f"xccdf_org.ssgproject.content_profile_{profile}",
             "--results", results_xml, str(ds)],
            capture_output=True, timeout=600)
        tree = ET.parse(results_xml)
    except (OSError, subprocess.SubprocessError, ET.ParseError) as exc:
        return {"skipped": f"oscap error: {exc}"}

    # rule-result carries idref + a <result> child. The result element uses
    # whatever default namespace the document declares, so match by localname.
    overlap = {"pass": 0, "fail": 0, "other": 0, "counts": {}, "rules": []}
    for el in tree.iter():
        if not el.tag.endswith("rule-result"):
            continue
        idref = (el.get("idref") or "").lower()
        if not any(tok in idref for tok in _OVERLAP_TOKENS):
            continue
        res = "unknown"
        for child in el:
            if child.tag.endswith("}result") or child.tag == "result":
                res = (child.text or "unknown").strip()
                break
        overlap["counts"][res] = overlap["counts"].get(res, 0) + 1
        if res == "pass":
            overlap["pass"] += 1
        elif res == "fail":
            overlap["fail"] += 1
        else:
            overlap["other"] += 1
        overlap["rules"].append({"id": idref.split("_rule_")[-1], "result": res})

    Path(results_xml).unlink(missing_ok=True)
    return {"datastream": ds.name, "profile": profile,
            "overlap_matched": len(overlap["rules"]),
            "overlap_pass": overlap["pass"], "overlap_fail": overlap["fail"],
            "overlap_other": overlap["other"],
            "result_breakdown": overlap["counts"], "rules": overlap["rules"][:40]}


# Files scanned by each IaC/container baseline (Trivy).
_TRIVY_TARGETS = [
    "test_target/azure_storage_vulnerable.tf",
    "test_target/Dockerfile.vulnerable",
]


def run(with_oscap: bool = False) -> dict:
    report = {"trivy": {}, "oscap": {"available": _oscap_available()}}
    for rel in _TRIVY_TARGETS:
        if not (ROOT / rel).exists():
            report["trivy"][rel] = {"skipped": "fixture missing"}
            continue
        report["trivy"][rel] = {
            "sca": _caspar_findings(rel),
            "trivy": _trivy_findings(rel),
        }
    # OpenSCAP evaluates the LIVE system, so it's opt-in (slower, and only
    # meaningful on the machine being audited). --oscap turns it on.
    if with_oscap and _oscap_available():
        report["oscap"]["result"] = _oscap_findings()
    return report


def _print(report: dict) -> None:
    print("\n" + "=" * 68)
    print("  AEGIS vs TRIVY — IaC / container misconfiguration detection")
    print("=" * 68)
    for rel, cmp in report["trivy"].items():
        name = Path(rel).name
        if "skipped" in cmp:
            print(f"\n  {name}: skipped ({cmp['skipped']})")
            continue
        c, t = cmp["sca"], cmp["trivy"]
        print(f"\n  ── {name}")
        print(f"     AEGIS : {c['count']:>2} findings · "
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
    print("  AEGIS vs OpenSCAP — Ubuntu OS hardening (config-based subset)")
    print("=" * 68)
    osc = report["oscap"]
    if not osc["available"]:
        print("\n  OpenSCAP not installed — `sudo apt-get install openscap-scanner`")
    elif "result" not in osc:
        print("\n  OpenSCAP installed. Re-run with --oscap to evaluate the live")
        print("  system (CIS L1 Server) on the overlapping sysctl/login.defs subset.")
    elif "skipped" in osc["result"]:
        print(f"\n  skipped: {osc['result']['skipped']}")
    else:
        r = osc["result"]
        cu = _caspar_findings("test_target/ubuntu_demo/sysctl.conf") \
            if (ROOT / "test_target/ubuntu_demo/sysctl.conf").exists() else None
        print(f"\n  OpenSCAP ({r['datastream']}, {r['profile']}):")
        print(f"     {r['overlap_matched']} overlapping config-based rules found")
        bd = " ".join(f"{k}:{v}" for k, v in sorted(r["result_breakdown"].items()))
        print(f"     verdict breakdown: {bd or '(none)'}")
        actionable = r["overlap_pass"] + r["overlap_fail"]
        if actionable == 0:
            print("     ⚠ no pass/fail verdicts on THIS host — OpenSCAP's OVAL "
                  "probes\n       need a real (non-WSL) system with the config "
                  "applied. Run on a\n       provisioned Ubuntu VM for actionable "
                  "pass/fail numbers.")
        else:
            print(f"     pass:{r['overlap_pass']}  fail:{r['overlap_fail']}  "
                  f"(binary verdict, no score)")
        if cu:
            print(f"\n  AEGIS (same control family, on a config file):")
            print(f"     {cu['count']} findings · score {cu['score']}/10 "
                  f"[{cu['severity']}]   (reproducible CCSS + narrative per finding)")
        print("\n  → Both cover the same control family; AEGIS scores a config")
        print("    FILE deterministically, OpenSCAP audits live-system STATE.")
        print("    That scope difference is itself a thesis finding.")
    print("=" * 68 + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--oscap", action="store_true",
                    help="Also run OpenSCAP on the LIVE system (CIS L1) and "
                         "compare on the overlapping config-based subset.")
    args = ap.parse_args()
    if not (ROOT / "ccss.db").exists():
        print("ccss.db not found — restore from data/ccss_canonical.sql",
              file=sys.stderr)
        sys.exit(2)
    report = run(with_oscap=args.oscap)
    print(json.dumps(report, indent=2)) if args.json else _print(report)


if __name__ == "__main__":
    main()
