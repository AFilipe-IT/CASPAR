#!/usr/bin/env python3
"""
scripts/determinism_experiment.py
---------------------------------
Experiência de determinismo da Stage 1 (classificação CCSS via LLM).

Motivação (reviews INForum, submissão 58): os três revisores questionam se a
construção da base de conhecimento, sendo feita por um LLM probabilístico,
produz classificações CCSS diferentes quando repetida sobre o mesmo documento.

Desenho:
  - Repete N vezes a Stage 1 do build (RAG → prompt → LLM → validação → score)
    sobre as ENTRIES do plugin Apache, com a configuração de produção
    (qwen2.5:14b, temperature=0.1), SEM escrever na base de dados.
  - Cada chamada é gravada incrementalmente em JSONL (sobrevive a interrupções).
  - O modo `analyze` calcula a concordância entre execuções:
      * unanimidade: % de entradas cujo vetor CCSS (AC,C,I,A,GEL,GRL) é
        idêntico nas N execuções
      * concordância modal: fração média de execuções que coincidem com o
        vetor mais frequente de cada entrada
      * concordância por métrica individual
      * estabilidade dos scores (amplitude max-min do base/temporal score)
      * estabilidade da banda DISA CAT (I/II/III) derivada do score
      * taxa de fallback (confidence == 0.0 → LLM falhou 3x)

Uso:
    python scripts/determinism_experiment.py run [--runs 5] [--out FICHEIRO]
    python scripts/determinism_experiment.py analyze [--in FICHEIRO]
"""

from __future__ import annotations

import argparse
import json
import logging
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_OUT = ROOT / "reports" / "determinism_runs.jsonl"

METRIC_KEYS = ["ac", "c", "i", "a", "gel", "grl"]


def cat_band(score: float) -> str:
    """Banda DISA CAT usada na calibração do prompt (CAT I/II/III)."""
    if score >= 7.0:
        return "CAT I"
    if score >= 4.0:
        return "CAT II"
    return "CAT III"


# ------------------------------------------------------------------ #
# run                                                                  #
# ------------------------------------------------------------------ #

def cmd_run(n_runs: int, out_path: Path, model: str, ollama_url: str) -> None:
    # Antes dos imports: build_llm.py chama basicConfig(INFO) ao ser importado
    # e o primeiro basicConfig é o que fica.
    logging.basicConfig(level=logging.WARNING)

    from config_assessment.build.llm_client import OllamaClient
    from config_assessment.plugins.apache_httpd.build_llm import ENTRIES
    from config_assessment.plugins.apache_httpd.llm_pipeline import LLMBuildPipeline

    benchmark_pdf = (ROOT / "config_assessment" / "plugins" / "apache_httpd"
                     / "CIS_Apache_HTTP_Server_2.4_Benchmark_V2.3.0.pdf")

    # Sem fallback para stub: se o Ollama cair a meio, queremos um erro claro,
    # não dados de stub a contaminar a experiência.
    llm = OllamaClient(model=model, base_url=ollama_url)
    if not llm.is_available():
        sys.exit(f"Ollama não está acessível em {ollama_url} — arranca com: ollama serve")

    pipeline = LLMBuildPipeline(benchmark_path=str(benchmark_pdf), llm=llm)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    done: set[tuple[int, str, str]] = set()
    if out_path.exists():
        for line in out_path.read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("kind") == "result":
                done.add((rec["run"], rec["directive"], rec["bad_value"]))
        if done:
            print(f"[resume] {len(done)} chamadas já feitas em {out_path} — a continuar")

    with out_path.open("a") as fh:
        if not done:
            fh.write(json.dumps({
                "kind": "meta", "model": model, "temperature": llm.temperature,
                "n_runs": n_runs, "n_entries": len(ENTRIES),
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }) + "\n")
            fh.flush()

        total = n_runs * len(ENTRIES)
        n_done = len(done)
        for run in range(1, n_runs + 1):
            for entry in ENTRIES:
                key = (run, entry.directive, entry.bad_value)
                if key in done:
                    continue
                t0 = time.time()
                mc = pipeline.process_entry(entry)
                elapsed = time.time() - t0
                # process_entry devolve Misconfiguration; o flag de fallback
                # (confidence) fica no LLMMetrics interno — reconstruímos a
                # deteção pelo texto da justificação de fallback.
                is_fallback = mc.justification.startswith("Fallback:") or \
                    mc.justification in {
                        "Module enabled unnecessarily.", "Privilege/ownership issue.",
                        "Access control misconfiguration.", "Feature/option enabled insecurely.",
                        "Logging misconfiguration.", "TLS/SSL misconfiguration.",
                        "Information leakage.", "DoS mitigation missing.",
                        "Request size limit missing.",
                    }
                rec = {
                    "kind": "result", "run": run,
                    "directive": entry.directive, "bad_value": entry.bad_value,
                    "cis_section": entry.cis_section,
                    "ac": mc.ac, "c": mc.c, "i": mc.i, "a": mc.a,
                    "gel": mc.gel, "grl": mc.grl,
                    "base_score": mc.base_score, "temporal_score": mc.temporal_score,
                    "fallback": is_fallback, "elapsed_s": round(elapsed, 2),
                }
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                n_done += 1
                print(f"[{n_done}/{total}] run {run} {entry.directive}={entry.bad_value!r} "
                      f"→ {mc.ac}/{mc.c}/{mc.i}/{mc.a} GEL:{mc.gel} GRL:{mc.grl} "
                      f"base={mc.base_score:.1f} ({elapsed:.1f}s)")

    print(f"\nConcluído: {n_done}/{total} chamadas em {out_path}")


# ------------------------------------------------------------------ #
# analyze                                                              #
# ------------------------------------------------------------------ #

def cmd_analyze(in_path: Path) -> None:
    if not in_path.exists():
        sys.exit(f"Ficheiro não encontrado: {in_path}")

    meta = None
    records = []
    for line in in_path.read_text().splitlines():
        rec = json.loads(line)
        if rec["kind"] == "meta":
            meta = rec
        else:
            records.append(rec)

    # Agrupar por entrada (directive, bad_value)
    by_entry: dict[tuple[str, str], list[dict]] = {}
    for rec in records:
        by_entry.setdefault((rec["directive"], rec["bad_value"]), []).append(rec)

    n_runs = max(r["run"] for r in records)
    print("=" * 78)
    print("EXPERIÊNCIA DE DETERMINISMO — Stage 1 (classificação CCSS via LLM)")
    if meta:
        print(f"Modelo: {meta['model']}  temperatura: {meta['temperature']}  "
              f"execuções: {n_runs}  entradas: {len(by_entry)}")
    print("=" * 78)

    unanimous = 0
    modal_fracs = []
    metric_agree: dict[str, list[float]] = {k: [] for k in METRIC_KEYS}
    base_ranges, temp_ranges, base_stds = [], [], []
    band_stable_base = 0
    n_fallback = sum(1 for r in records if r["fallback"])
    rows = []

    for (directive, bad_value), recs in sorted(by_entry.items(),
                                               key=lambda kv: kv[1][0]["cis_section"]):
        vectors = [tuple(r[k] for k in METRIC_KEYS) for r in recs]
        counts = Counter(vectors)
        modal_vec, modal_n = counts.most_common(1)[0]
        modal_frac = modal_n / len(recs)
        modal_fracs.append(modal_frac)
        if len(counts) == 1:
            unanimous += 1

        for k in METRIC_KEYS:
            vals = [r[k] for r in recs]
            mode_n = Counter(vals).most_common(1)[0][1]
            metric_agree[k].append(mode_n / len(vals))

        bases = [r["base_score"] for r in recs]
        temps = [r["temporal_score"] for r in recs]
        base_ranges.append(max(bases) - min(bases))
        temp_ranges.append(max(temps) - min(temps))
        base_stds.append(statistics.pstdev(bases))
        bands = {cat_band(b) for b in bases}
        if len(bands) == 1:
            band_stable_base += 1

        rows.append((recs[0]["cis_section"], directive, bad_value,
                     len(counts), modal_frac, max(bases) - min(bases),
                     "/".join(modal_vec), " ".join(sorted(bands))))

    n_entries = len(by_entry)
    print(f"\n{'CIS':>5}  {'directiva':<22} {'#vec':>4} {'modal':>6} {'Δbase':>6}  "
          f"{'vetor modal':<16} {'bandas'}")
    print("-" * 78)
    for cis, d, bv, nvec, mf, rng, vec, bands in rows:
        flag = "" if nvec == 1 else "  ←"
        print(f"{cis:>5}  {d:<22} {nvec:>4} {mf:>5.0%} {rng:>6.1f}  {vec:<16} {bands}{flag}")

    print("-" * 78)
    print("\nRESUMO GLOBAL")
    print(f"  Entradas com vetor CCSS unânime (N/{n_runs} iguais): "
          f"{unanimous}/{n_entries} ({unanimous / n_entries:.0%})")
    print(f"  Concordância modal média do vetor completo:          "
          f"{statistics.mean(modal_fracs):.1%}")
    print("  Concordância por métrica individual:")
    for k in METRIC_KEYS:
        print(f"    {k.upper():>3}: {statistics.mean(metric_agree[k]):.1%}")
    print(f"  Amplitude do base score  — média: {statistics.mean(base_ranges):.2f}  "
          f"máx: {max(base_ranges):.2f}")
    print(f"  Amplitude do temporal    — média: {statistics.mean(temp_ranges):.2f}  "
          f"máx: {max(temp_ranges):.2f}")
    print(f"  Desvio-padrão médio do base score: {statistics.mean(base_stds):.3f}")
    print(f"  Entradas com banda CAT estável (base score):         "
          f"{band_stable_base}/{n_entries} ({band_stable_base / n_entries:.0%})")
    print(f"  Chamadas em fallback conservador: {n_fallback}/{len(records)}")


# ------------------------------------------------------------------ #

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="executar a experiência")
    p_run.add_argument("--runs", type=int, default=5)
    p_run.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p_run.add_argument("--model", default="qwen2.5:14b")
    p_run.add_argument("--ollama-url", default="http://localhost:11434")

    p_an = sub.add_parser("analyze", help="analisar resultados")
    p_an.add_argument("--in", dest="in_path", type=Path, default=DEFAULT_OUT)

    args = ap.parse_args()
    if args.cmd == "run":
        cmd_run(args.runs, args.out, args.model, args.ollama_url)
    else:
        cmd_analyze(args.in_path)


if __name__ == "__main__":
    main()
