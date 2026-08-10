#!/usr/bin/env python3
"""
scripts/watch_demo.py
---------------------
Prepara (e opcionalmente conduz) uma demonstração do modo `watch` em que o
score MEXE de facto.

Porque existe
=============
Vigiar um `/etc/apache2/apache2.conf` de uma instalação normal e editá-lo à
mão quase nunca mostra nada: o score global é o **pior achado individual**, e
uma directiva acrescentada abaixo desse máximo é registada como problema novo
sem alterar o número. Um `Timeout 300`, por exemplo, nem sequer tem regra —
é uma das directivas sem cobertura, e mexer-lhe não muda rigorosamente nada.
Fica a impressão de que o watch está morto quando está apenas a dizer a
verdade sobre uma configuração cujo topo não se moveu.

Este script resolve isso com uma configuração de degraus: achados a 8.7, 7.9,
7.1 e 6.0. Remover o do topo faz o score cair para o degrau seguinte, e a
queda vê-se no painel a cada passo.

Uso
===
    python3 scripts/watch_demo.py --prepare       # cria a config de trabalho
    python3 scripts/watch_demo.py --step 1        # aplica um degrau
    python3 scripts/watch_demo.py --auto          # todos os degraus, com pausas
    python3 scripts/watch_demo.py --reset         # volta ao estado inicial

Fluxo típico: `--prepare`, arrancar o watch no painel sobre o caminho que o
script imprime, e depois `--auto` numa segunda consola.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "docker_fixtures" / "httpd-vulnerable.conf"
WORKDIR = ROOT / ".watch_demo"
CONFIG = WORKDIR / "httpd.conf"

# Cada degrau remedeia o achado que está no topo, deixando o seguinte a
# descoberto. Os scores são os medidos nesta fixture — ver --prepare, que os
# reimprime a partir de um scan real em vez de os assumir.
# `score` é o valor GLOBAL medido depois de aplicar o degrau (não o do achado
# removido). Verificado com um scan real nesta fixture — se a base de
# conhecimento mudar, reconfirma com `--verify`.
#
# Os dois últimos degraus não baixam o número: a partir dos 6.0 o topo passa a
# ser um achado `Header` que estes degraus não tocam. Ficam na demonstração
# de propósito, porque mostram o ponto que mais confunde — o score é o PIOR
# achado, portanto remediar um problema menor reduz a lista de problemas sem
# mexer no score. É uma propriedade do CCSS, não uma avaria do watch.
STEPS: list[tuple[str, str, str, str]] = [
    ("User root", "User www-data",
     "7.9", "processo deixa de correr como root"),
    ("Group root", "Group www-data",
     "7.1", "grupo do processo deixa de ser privilegiado"),
    ("ServerTokens Full", "ServerTokens Prod",
     "6.0", "deixa de revelar versão e módulos"),
    ("ServerSignature On", "ServerSignature Off",
     "6.0", "menos um problema; score preso no `Header` a 6.0"),
    ("TraceEnable On", "TraceEnable Off",
     "6.0", "fecha uma cadeia de ataque; cadeias não pontuam o global"),
]


def prepare() -> None:
    WORKDIR.mkdir(exist_ok=True)
    shutil.copy(FIXTURE, CONFIG)
    print(f"Configuração de trabalho: {CONFIG}")
    print("\nAponta o watch a este caminho (painel > Watch > modo 'path'),")
    print("ou pela CLI:")
    print(f"    caspar watch {CONFIG} --interval 2")
    print("\nDepois, noutra consola:")
    print("    python3 scripts/watch_demo.py --auto")
    print(f"\nDegraus previstos ({len(STEPS)}):")
    for i, (old, new, score, why) in enumerate(STEPS, 1):
        print(f"  {i}. {old:22} -> {new:22} (~{score:>4}) {why}")


def _require_config() -> str:
    if not CONFIG.exists():
        sys.exit("Config de trabalho não existe — corre primeiro --prepare.")
    return CONFIG.read_text()


def apply_step(n: int) -> None:
    if not 1 <= n <= len(STEPS):
        sys.exit(f"Degrau inválido: escolhe entre 1 e {len(STEPS)}.")
    text = _require_config()
    old, new, score, why = STEPS[n - 1]
    if old not in text:
        print(f"[{n}] '{old}' já não está na config — degrau saltado.")
        return
    CONFIG.write_text(text.replace(old, new))
    print(f"[{n}] {old} -> {new}")
    print(f"    {why} (o score deve sair de ~{score})")


def auto(pause: float) -> None:
    _require_config()
    print(f"A aplicar {len(STEPS)} degraus, {pause}s entre cada.")
    print("Deixa o painel aberto na sessão de watch.\n")
    for i in range(1, len(STEPS) + 1):
        apply_step(i)
        if i < len(STEPS):
            time.sleep(pause)
    print("\nTerminado. O score deve ter descido a cada passo.")


def verify(db_path: str) -> None:
    """Reaplica os degraus num scan real e compara com os valores da tabela.

    Os scores dependem da base de conhecimento instalada; sem isto, a tabela
    acima seria uma promessa por verificar.
    """
    import subprocess
    import re

    def score() -> str:
        out = subprocess.run(
            [sys.executable, "-m", "cli.main", "--db", db_path,
             "scan", str(CONFIG)],
            cwd=ROOT, capture_output=True, text=True).stdout
        m = re.search(r"Highest finding\s+([0-9.]+)", out)
        return m.group(1) if m else "?"

    shutil.copy(FIXTURE, CONFIG)
    print(f"inicial: {score()}")
    ok = True
    for i, (old, new, expected, _why) in enumerate(STEPS, 1):
        apply_step(i)
        got = score()
        mark = "ok" if got == expected else f"DIVERGE (tabela diz {expected})"
        if got != expected:
            ok = False
        print(f"  degrau {i}: {got}  {mark}")
    print("\nTabela confirmada." if ok else "\nA tabela precisa de actualização.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--prepare", action="store_true", help="cria a config de trabalho")
    g.add_argument("--step", type=int, metavar="N", help="aplica um degrau")
    g.add_argument("--auto", action="store_true", help="aplica todos os degraus")
    g.add_argument("--reset", action="store_true", help="repõe o estado inicial")
    g.add_argument("--verify", action="store_true",
                   help="confirma os scores da tabela com scans reais")
    ap.add_argument("--pause", type=float, default=8.0,
                    help="segundos entre degraus no modo --auto (omissão: 8)")
    ap.add_argument("--db", default="ccss.db", help="base de dados a usar")
    args = ap.parse_args()

    if args.verify:
        WORKDIR.mkdir(exist_ok=True)
        verify(args.db)
        return

    if args.prepare or args.reset:
        prepare() if args.prepare else (shutil.copy(FIXTURE, CONFIG),
                                        print(f"Reposto: {CONFIG}"))
    elif args.step:
        apply_step(args.step)
    else:
        auto(args.pause)


if __name__ == "__main__":
    main()
