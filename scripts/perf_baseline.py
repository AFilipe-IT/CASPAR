#!/usr/bin/env python3
"""
scripts/perf_baseline.py — VALIDACAO.md §6.2: latencia/CPU/RAM lado a lado
CASPAR vs Trivy (vs OpenSCAP, live-eval, não comparável ficheiro-a-ficheiro).

Mesmo protocolo do §4.1 (`scripts/perf_scan.py`): N corridas, 1 warm-up
descartado, subprocess fresco por corrida via `/usr/bin/time -v`, mediana +
media+-stddev + p95. Usa os MESMOS fixtures que scripts/baseline_compare.py
usa para a comparacao qualitativa do §6.1 (test_target/azure_storage_vulnerable.tf,
test_target/Dockerfile.vulnerable), para que os dois resultados (achados +
desempenho) sejam sobre exatamente o mesmo input.

Nota de equidade (ja no §6.2): Trivy e um binario Go, CASPAR e Python — isto
mede as IMPLEMENTACOES, nao as metodologias. OpenSCAP avalia o sistema vivo,
nao um ficheiro, por isso a sua linha nao e uma comparacao direta de input —
e reportada a parte.

Energia: mesma estimativa TDP-declarado do §4.1 (sem RAPL/perf disponivel).

Run:
    python -m scripts.perf_baseline --runs 10 --json > perf_baseline.json
    python -m scripts.perf_baseline --runs 10
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.perf_scan import (  # noqa: E402
    DB,
    DEFAULT_TDP_WATTS,
    ROOT,
    machine_info,
    percentile,
    run_once as _run_once_generic,
    summarize,
)

FIXTURES = {
    "azure_storage_vulnerable.tf": "test_target/azure_storage_vulnerable.tf",
    "Dockerfile.vulnerable": "test_target/Dockerfile.vulnerable",
}


def run_once_caspar(target: str) -> dict:
    from scripts.perf_scan import run_once
    return run_once(target)


def run_once_trivy(target: str, _retries: int = 2) -> dict:
    import subprocess
    from scripts.perf_scan import _parse_time_v

    for attempt in range(_retries + 1):
        proc = subprocess.run(
            ["/usr/bin/time", "-v", "trivy", "config", "-f", "json", "--quiet", target],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        measured = _parse_time_v(proc.stderr)
        if "wall_s" not in measured or "max_rss_kb" not in measured:
            if attempt < _retries:
                print(f"  [warn] trivy: /usr/bin/time -v not parseable (attempt {attempt + 1}/{_retries + 1}), retrying...", file=sys.stderr)
                continue
            raise RuntimeError(f"trivy: /usr/bin/time -v not parseable after {_retries + 1} attempts. stderr tail: {proc.stderr[-500:]}")
        if proc.returncode not in (0, 1):  # trivy exits 1 when findings > 0 by default policy
            raise RuntimeError(f"trivy exited {proc.returncode} for {target!r}: {proc.stderr[-500:]}")
        return measured
    raise AssertionError("unreachable")


def run_once_oscap(_retries: int = 2) -> dict:
    """oscap xccdf eval on the LIVE system — not file-based, not a like-for-like
    input comparison with CASPAR/Trivy. Reported separately in the output."""
    import subprocess
    from scripts.perf_scan import _parse_time_v
    from scripts.baseline_compare import _oscap_datastream  # type: ignore

    ds = _oscap_datastream()
    if ds is None:
        raise RuntimeError("no oscap datastream found (see scripts/baseline_compare.py _oscap_datastream)")

    for attempt in range(_retries + 1):
        proc = subprocess.run(
            ["/usr/bin/time", "-v", "oscap", "xccdf", "eval",
             "--profile", "cis_level1_server", "--results", "/dev/null", str(ds)],
            cwd=str(ROOT),
            capture_output=True,
        )
        stderr_text = proc.stderr.decode("utf-8", errors="replace")
        measured = _parse_time_v(stderr_text)
        if "wall_s" not in measured or "max_rss_kb" not in measured:
            if attempt < _retries:
                print(f"  [warn] oscap: /usr/bin/time -v not parseable (attempt {attempt + 1}/{_retries + 1}), retrying...", file=sys.stderr)
                continue
            raise RuntimeError(f"oscap: /usr/bin/time -v not parseable after {_retries + 1} attempts. stderr tail: {stderr_text[-500:]}")
        # oscap exits 2 when rules fail (expected — that's the whole point of the eval)
        if proc.returncode not in (0, 2):
            raise RuntimeError(f"oscap exited {proc.returncode}: {stderr_text[-500:]}")
        return measured
    raise AssertionError("unreachable")


def bench(fn, args_list: list, runs: int, warmup: int, tdp: float) -> dict:
    for _ in range(warmup):
        fn(*args_list)
    samples = [fn(*args_list) for _ in range(runs)]
    return summarize(samples, tdp)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--tdp", type=float, default=DEFAULT_TDP_WATTS)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--skip-oscap", action="store_true", help="oscap live-eval is slow/needs root-ish privileges; skip if unavailable")
    args = ap.parse_args()

    if not Path("/usr/bin/time").exists():
        print("ERRO: /usr/bin/time nao encontrado.", file=sys.stderr)
        return 1

    results: dict = {"caspar": {}, "trivy": {}}

    for name, rel_path in FIXTURES.items():
        target = str(ROOT / rel_path)
        if not Path(target).exists():
            print(f"  [skip] {name}: nao existe", file=sys.stderr)
            continue

        print(f"-- CASPAR: {name} --", file=sys.stderr)
        results["caspar"][name] = bench(run_once_caspar, [target], args.runs, args.warmup, args.tdp)

        if shutil.which("trivy"):
            print(f"-- Trivy: {name} --", file=sys.stderr)
            results["trivy"][name] = bench(run_once_trivy, [target], args.runs, args.warmup, args.tdp)
        else:
            print("  [skip] trivy nao instalado", file=sys.stderr)

    if not args.skip_oscap and shutil.which("oscap"):
        print("-- OpenSCAP: live system eval (nao comparavel ficheiro-a-ficheiro) --", file=sys.stderr)
        try:
            results["oscap_live_eval"] = bench(run_once_oscap, [], args.runs, args.warmup, args.tdp)
        except RuntimeError as exc:
            print(f"  [skip] oscap: {exc}", file=sys.stderr)
    else:
        print("  [skip] oscap nao instalado ou --skip-oscap", file=sys.stderr)

    output = {"machine": machine_info(), "tdp_watts_declared": args.tdp, "results": results}

    if args.json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print()
        print(f"Maquina: {output['machine']['cpu_model']} - {output['machine']['ram_total_mb']} MB RAM")
        print()
        for fixture in FIXTURES:
            print(f"=== {fixture} ===")
            header = f"{'Tool':<10} {'Wall p50 (s)':>13} {'Wall p95 (s)':>13} {'CPU total (s)':>14} {'RAM pico (MB)':>14}"
            print(header)
            print("-" * len(header))
            for tool in ("caspar", "trivy"):
                s = results.get(tool, {}).get(fixture)
                if not s:
                    continue
                print(
                    f"{tool:<10} "
                    f"{s['wall_s']['median']:>13.3f} "
                    f"{s['wall_s']['p95']:>13.3f} "
                    f"{s['cpu_s_total']['median']:>14.3f} "
                    f"{s['max_rss_mb']['median']:>14.1f}"
                )
            print()
        if "oscap_live_eval" in results:
            s = results["oscap_live_eval"]
            print("=== OpenSCAP (live system eval, sem input comum) ===")
            print(f"wall p50={s['wall_s']['median']:.3f}s p95={s['wall_s']['p95']:.3f}s "
                  f"cpu={s['cpu_s_total']['median']:.3f}s rss={s['max_rss_mb']['median']:.1f}MB")

    return 0


if __name__ == "__main__":
    sys.exit(main())
