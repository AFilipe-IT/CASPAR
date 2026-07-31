#!/usr/bin/env python3
"""
scripts/functional_check.py — end-to-end functional smoke test of CASPAR.

Exercises every user-facing capability against the real DB and reports PASS/FAIL
per check, so a functional evaluation on a fresh machine is one command. This is
NOT the unit test suite (that's `pytest tests/`) — it drives the CLI/runtime the
way a user does, to confirm the whole thing works together after install.

Run:
    python -m scripts.functional_check           # human-readable
    python -m scripts.functional_check --json     # machine-readable
Exit code: 0 if all checks pass, 1 otherwise (usable as a gate).
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = str(ROOT / "ccss.db")

_checks: list[dict] = []


def check(name: str):
    """Decorator: register a function as a named check. It returns a truthy
    'detail' string on success, or raises / returns False on failure."""
    def deco(fn):
        _checks.append({"name": name, "fn": fn})
        return fn
    return deco


def _scan(rel_or_abs: str):
    import cli.main as m
    m._discover_plugins()
    from config_assessment.core.db.database import Database
    from config_assessment.core import runtime
    path = rel_or_abs if Path(rel_or_abs).is_absolute() else str(ROOT / rel_or_abs)
    with Database(DB) as db:
        return runtime.scan(path, db)


# ── 1. Base health ─────────────────────────────────────────────────────
@check("db-present")
def _db_present():
    assert Path(DB).exists(), f"{DB} missing — restore from data/ccss_canonical.sql"
    return "ccss.db present"


@check("doctor-healthy")
def _doctor():
    from config_assessment.core.db.doctor import check as dbcheck
    findings = dbcheck(DB, strict=False)
    errors = [f for f in findings if f.severity == "error"]
    assert not errors, f"{len(errors)} DB integrity error(s)"
    return f"healthy ({len(findings)} non-error notes)"


@check("plugins-registered")
def _plugins():
    import cli.main as m
    m._discover_plugins()
    from config_assessment.core.runtime import registered_plugins
    names = {p.metadata().name for p in registered_plugins()}
    expected = {"apache-httpd", "nginx", "ssh", "mysql", "redis", "tomcat",
                "docker", "ubuntu", "kubernetes", "dockerfile", "azure-iac"}
    missing = expected - names
    assert not missing, f"missing plugins: {missing}"
    return f"{len(names)} plugins ({len(expected)} core targets present)"


# ── 2. Per-target scans (each must detect its family of misconfigs) ─────
_SCAN_CASES = [
    ("scan-nginx", "test_target/nginx.conf", "nginx", {"server_tokens"}),
    ("scan-apache", "test_target/httpd.conf", "apache-httpd", set()),
    ("scan-azure-tf", "test_target/azure_storage_vulnerable.tf", "azure-iac",
     {"min_tls_version"}),
    ("scan-k8s", "test_target/pod_vulnerable.yaml", "kubernetes", {"privileged"}),
    ("scan-dockerfile", "test_target/Dockerfile.vulnerable", "dockerfile",
     {"user"}),
    ("scan-ubuntu", "test_target/ubuntu_demo/sysctl.conf", "ubuntu",
     {"kernel.randomize_va_space"}),
]


def _make_scan_check(rel, target, must_find):
    def _fn():
        r = _scan(rel)
        assert r.target_name == target, f"routed to {r.target_name}, not {target}"
        found = {i.directive for i in r.issues}
        missing = must_find - found
        assert not missing, f"did not detect {missing}"
        assert r.global_temporal_score > 0, "score is 0"
        return f"{len(r.issues)} issues · {r.global_temporal_score:.1f}/10 [{r.severity}]"
    return _fn


for _name, _rel, _target, _find in _SCAN_CASES:
    check(_name)(_make_scan_check(_rel, _target, _find))


# ── 3. Determinism / reproducibility (the thesis claim) ─────────────────
@check("determinism")
def _determinism():
    a = _scan("test_target/azure_storage_vulnerable.tf")
    b = _scan("test_target/azure_storage_vulnerable.tf")
    assert a.global_temporal_score == b.global_temporal_score, "score differs"
    assert a.input_hash == b.input_hash, "input hash differs"
    return f"two scans identical ({a.global_temporal_score:.1f}/10)"


@check("manifest-present")
def _manifest():
    r = _scan("test_target/nginx.conf")
    man = r.manifest
    assert man.get("db_sha256"), "no db_sha256 in manifest"
    assert man.get("caspar_version"), "no version in manifest"
    return f"kb sha256:{man['db_sha256'][:12]} · caspar {man['caspar_version']}"


# ── 4. Report generation (each format writes a non-empty file) ──────────
@check("reports")
def _reports():
    import tempfile
    from cli._output import _to_sarif
    r = _scan("test_target/nginx.conf")
    # SARIF (pure function, no disk needed to validate structure)
    sarif = _to_sarif(r)
    assert sarif["version"] == "2.1.0" and sarif["runs"], "SARIF malformed"
    # JSON (model dump)
    js = json.loads(r.model_dump_json())
    assert js["manifest"]["db_sha256"], "JSON missing manifest"
    return "SARIF + JSON well-formed (manifest embedded)"


# ── 5. Clean config produces no issues (no false positives on hardened) ─
@check("clean-config")
def _clean():
    import tempfile
    p = Path(tempfile.mkdtemp()) / "sysctl.conf"
    p.write_text("net.ipv4.conf.all.accept_redirects = 0\n"
                 "kernel.randomize_va_space = 2\n"
                 "net.ipv4.tcp_syncookies = 1\n")
    r = _scan(str(p))
    assert not r.issues, f"{len(r.issues)} false positives on hardened config"
    return "hardened sysctl.conf → 0 issues (no false positives)"


def run() -> dict:
    results = []
    for c in _checks:
        entry = {"name": c["name"]}
        try:
            detail = c["fn"]()
            entry["status"] = "PASS"
            entry["detail"] = detail if isinstance(detail, str) else ""
        except Exception as exc:
            entry["status"] = "FAIL"
            entry["detail"] = f"{type(exc).__name__}: {exc}"
            entry["trace"] = traceback.format_exc().splitlines()[-3:]
        results.append(entry)
    n_pass = sum(1 for r in results if r["status"] == "PASS")
    return {"total": len(results), "passed": n_pass,
            "failed": len(results) - n_pass, "checks": results}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not Path(DB).exists():
        print("ccss.db not found — restore: sqlite3 ccss.db < data/ccss_canonical.sql",
              file=sys.stderr)
        sys.exit(2)

    report = run()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("\n" + "=" * 60)
        print("  CASPAR — functional smoke test")
        print("=" * 60)
        for c in report["checks"]:
            mark = "✓" if c["status"] == "PASS" else "✗"
            print(f"  [{mark}] {c['name']:<20} {c['detail']}")
        print("=" * 60)
        print(f"  {report['passed']}/{report['total']} checks passed")
        print("=" * 60 + "\n")
    sys.exit(0 if report["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
