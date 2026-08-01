#!/usr/bin/env python3
"""
scripts/perf_scan.py — VALIDACAO.md §4.1: latência, CPU e RAM do `caspar scan`.

Runs a set of fixtures N times each (default 10, 1 warm-up discarded) via
`/usr/bin/time -v` in a fresh subprocess per run — matches the protocol in
docs/VALIDACAO.md §4.1 (isolate interpreter/DB-open cost, N>=10, median +
mean+-stddev + p95, machine documented).

Energy (Joules) is estimated from CPU time x a declared average TDP, NOT
measured via RAPL/perf (unavailable in this environment — WSL2 has no
/sys/class/powercap access). This is explicitly an estimate, not a
measurement; see docs/VALIDACAO.md §4.1 "alternativa por estimativa".

Run:
    python -m scripts.perf_scan                    # default fixtures, 10 runs
    python -m scripts.perf_scan --runs 20
    python -m scripts.perf_scan --json > perf.json
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = str(ROOT / "ccss.db")

# Declared average TDP for the energy estimate (W). Conservative desktop/laptop
# CPU figure — not measured on this machine. Override with --tdp if you know
# your CPU's actual TDP for a less-wrong estimate.
DEFAULT_TDP_WATTS = 15.0

DEFAULT_FIXTURES = {
    "nginx.conf (pequeno)": "test_target/test_nginx.conf",
    "sysctl.conf real": "/etc/sysctl.conf",
    "pod_vulnerable.yaml (IaC)": "test_target/pod_vulnerable.yaml",
}

_TIME_V_PATTERNS = {
    "wall_s": re.compile(r"Elapsed \(wall clock\) time.*?: (?:(\d+):)?(\d+):(\d+(?:\.\d+)?)"),
    "user_s": re.compile(r"User time \(seconds\): (\d+(?:\.\d+)?)"),
    "sys_s": re.compile(r"System time \(seconds\): (\d+(?:\.\d+)?)"),
    "max_rss_kb": re.compile(r"Maximum resident set size \(kbytes\): (\d+)"),
    "cpu_pct": re.compile(r"Percent of CPU this job got: (\d+)%"),
}


def _parse_time_v(stderr_text: str) -> dict:
    out = {}
    m = _TIME_V_PATTERNS["wall_s"].search(stderr_text)
    if m:
        h, mn, s = m.groups()
        out["wall_s"] = (int(h) * 3600 if h else 0) + int(mn) * 60 + float(s)
    for key in ("user_s", "sys_s", "max_rss_kb", "cpu_pct"):
        m = _TIME_V_PATTERNS[key].search(stderr_text)
        if m:
            out[key] = float(m.group(1))
    return out


def run_once(target: str, _retries: int = 2, db: str = DB) -> dict:
    for attempt in range(_retries + 1):
        proc = subprocess.run(
            ["/usr/bin/time", "-v", sys.executable, "-m", "cli.main", "--db", db, "scan", target],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        measured = _parse_time_v(proc.stderr)
        if "wall_s" not in measured or "max_rss_kb" not in measured:
            # Rare, intermittent /usr/bin/time stderr truncation observed in this
            # environment (not reproducible on demand) — retry rather than fail
            # the whole batch, but say so loudly rather than silently discarding.
            if attempt < _retries:
                print(
                    f"  [warn] /usr/bin/time -v output not parseable for {target!r} "
                    f"(attempt {attempt + 1}/{_retries + 1}), retrying...",
                    file=sys.stderr,
                )
                continue
            raise RuntimeError(
                f"/usr/bin/time -v output not parseable for {target!r} after "
                f"{_retries + 1} attempts (exit={proc.returncode}). stderr tail: {proc.stderr[-500:]}"
            )
        # /usr/bin/time -v still reports valid wall_s/max_rss_kb even when the
        # timed command itself fails (e.g. a CLI arg error) — catch that here so
        # a broken invocation can't silently produce "successful" measurements.
        if proc.returncode != 0:
            raise RuntimeError(
                f"scan exited {proc.returncode} for {target!r} — not a valid measurement.\n"
                f"stdout tail: {proc.stdout[-500:]}\nstderr tail: {proc.stderr[-800:]}"
            )
        return measured
    raise AssertionError("unreachable")


def percentile(values: list[float], p: float) -> float:
    if len(values) == 1:
        return values[0]
    s = sorted(values)
    k = (len(s) - 1) * p
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def summarize(samples: list[dict], tdp_watts: float) -> dict:
    wall = [x["wall_s"] for x in samples]
    cpu_s = [x.get("user_s", 0.0) + x.get("sys_s", 0.0) for x in samples]
    rss_mb = [x["max_rss_kb"] / 1024 for x in samples]
    energy_j = [c * tdp_watts for c in cpu_s]  # estimate, see module docstring
    return {
        "n": len(samples),
        "wall_s": {
            "median": statistics.median(wall),
            "mean": statistics.mean(wall),
            "stdev": statistics.stdev(wall) if len(wall) > 1 else 0.0,
            "p95": percentile(wall, 0.95),
        },
        "cpu_s_total": {
            "median": statistics.median(cpu_s),
            "mean": statistics.mean(cpu_s),
            "stdev": statistics.stdev(cpu_s) if len(cpu_s) > 1 else 0.0,
        },
        "max_rss_mb": {
            "median": statistics.median(rss_mb),
            "mean": statistics.mean(rss_mb),
            "stdev": statistics.stdev(rss_mb) if len(rss_mb) > 1 else 0.0,
        },
        "energy_j_estimated": {
            "median": statistics.median(energy_j),
            "mean": statistics.mean(energy_j),
            "note": f"estimativa = cpu_s_total x {tdp_watts}W (TDP declarado, não medido via RAPL/perf)",
        },
    }


def machine_info() -> dict:
    cpuinfo = ""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpuinfo = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    meminfo_kb = None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    meminfo_kb = int(line.split()[1])
                    break
    except OSError:
        pass
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_model": cpuinfo or "unknown",
        "ram_total_mb": round(meminfo_kb / 1024) if meminfo_kb else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=10, help="corridas por fixture (default 10, protocolo exige N>=10)")
    ap.add_argument("--warmup", type=int, default=1, help="corridas de warm-up descartadas (default 1)")
    ap.add_argument("--tdp", type=float, default=DEFAULT_TDP_WATTS, help=f"TDP declarado em W para a estimativa de energia (default {DEFAULT_TDP_WATTS})")
    ap.add_argument("--json", action="store_true", help="output JSON em vez de tabela")
    ap.add_argument("--fixture", action="append", metavar="NAME=PATH", help="fixture extra (repetível); substitui os defaults se usado")
    ap.add_argument("--db", default=DB, help=f"caminho da BD a usar (default {DB})")
    args = ap.parse_args()

    if not Path("/usr/bin/time").exists():
        print("ERRO: /usr/bin/time não encontrado (pacote 'time' do apt).", file=sys.stderr)
        return 1

    fixtures = DEFAULT_FIXTURES.copy()
    if args.fixture:
        fixtures = {}
        for spec in args.fixture:
            name, _, path = spec.partition("=")
            fixtures[name] = path

    results = {}
    for name, rel_path in fixtures.items():
        target = rel_path if Path(rel_path).is_absolute() else str(ROOT / rel_path)
        if not Path(target).exists():
            print(f"  [skip] {name}: {target} não existe", file=sys.stderr)
            continue

        print(f"-- {name} ({target}) --", file=sys.stderr)
        for i in range(args.warmup):
            run_once(target, db=args.db)
            print(f"  warm-up {i + 1}/{args.warmup} descartado", file=sys.stderr)

        samples = []
        for i in range(args.runs):
            samples.append(run_once(target, db=args.db))
            print(f"  run {i + 1}/{args.runs}: wall={samples[-1]['wall_s']:.3f}s rss={samples[-1]['max_rss_kb']/1024:.1f}MB", file=sys.stderr)

        results[name] = {"target": target, "summary": summarize(samples, args.tdp), "raw_samples": samples}

    output = {"machine": machine_info(), "tdp_watts_declared": args.tdp, "results": results}

    if args.json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print()
        print(f"Máquina: {output['machine']['cpu_model']} · {output['machine']['ram_total_mb']} MB RAM · {output['machine']['platform']}")
        print(f"Energia: estimativa via CPU-time x {args.tdp}W TDP declarado (sem RAPL/perf disponível)")
        print()
        header = f"{'Fixture':<28} {'Wall p50 (s)':>13} {'Wall p95 (s)':>13} {'CPU total (s)':>14} {'RAM pico (MB)':>14} {'Energia (J, est.)':>18}"
        print(header)
        print("-" * len(header))
        for name, r in results.items():
            s = r["summary"]
            print(
                f"{name:<28} "
                f"{s['wall_s']['median']:>13.3f} "
                f"{s['wall_s']['p95']:>13.3f} "
                f"{s['cpu_s_total']['median']:>14.3f} "
                f"{s['max_rss_mb']['median']:>14.1f} "
                f"{s['energy_j_estimated']['median']:>18.2f}"
            )
        print()
        print(f"N={args.runs} corridas/fixture, {args.warmup} warm-up descartado. Mediana reportada; ver --json para média±σ e p95 completos.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
