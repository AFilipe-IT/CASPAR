"""
tests/test_chain_determinism.py
-------------------------------
O mesmo input tem de produzir exactamente o mesmo output — é a base da
reprodutibilidade que a metodologia CVM reclama, e o que permite comparar
scans ao longo do tempo ou entre investigadores.

Regressão concreta: `detect_chains` construía `triggered_by` com
`list(present)`, onde `present` é um `set`. A ordem de iteração de um set de
strings depende do PYTHONHASHSEED, que o CPython aleatoriza por processo.
Dois scans idênticos produziam relatórios JSON byte-diferentes — mesmo score,
directivas por ordem trocada. Só aparecia entre *processos* distintos, por
isso passava despercebido dentro de uma única sessão de testes.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

from config_assessment.core.engines.attack_chain import detect_chains
from config_assessment.core.models import AttackChain


def _chain() -> AttackChain:
    return AttackChain(
        chain_id="info-disclosure-chain",
        target_name="apache-httpd",
        description="Version disclosure amplified by signature confirmation",
        misconfig_directives=["ServerTokens", "ServerSignature"],
        amplification=1.25,
    )


def test_triggered_by_follows_the_declared_order():
    """A ordem é a da cadeia, não a do set — e é a ordem que se lê como a
    progressão do ataque (ServerTokens revela a versão, ServerSignature
    confirma-a)."""
    fired = detect_chains(
        active_directives={"ServerSignature", "ServerTokens"},
        misconfig_directives={"ServerTokens"},
        chains=[_chain()],
    )

    assert len(fired) == 1
    assert fired[0].triggered_by == ["ServerTokens", "ServerSignature"]


def test_order_does_not_depend_on_the_input_sets_construction():
    """Os sets são construídos por ordens diferentes; o resultado não muda."""
    a = detect_chains({"ServerTokens", "ServerSignature"}, {"ServerTokens"},
                      [_chain()])
    b = detect_chains({"ServerSignature", "ServerTokens"}, {"ServerSignature"},
                      [_chain()])

    assert a[0].triggered_by == b[0].triggered_by


def test_order_is_stable_across_processes():
    """O teste que apanha a regressão real.

    Dentro de um processo o PYTHONHASHSEED é fixo, por isso `list(set)` é
    estável e um teste in-process passaria mesmo com o bug. É preciso
    atravessar processos com seeds diferentes para o expor.
    """
    program = textwrap.dedent("""
        from config_assessment.core.engines.attack_chain import detect_chains
        from config_assessment.core.models import AttackChain

        chain = AttackChain(
            chain_id="info-disclosure-chain",
            target_name="apache-httpd",
            description="d",
            misconfig_directives=["ServerTokens", "ServerSignature"],
            amplification=1.25,
        )
        fired = detect_chains({"ServerTokens", "ServerSignature"},
                              {"ServerTokens"}, [chain])
        print(",".join(fired[0].triggered_by))
    """)

    seen = set()
    for seed in ("0", "1", "42", "1000", "12345"):
        out = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True, text=True, check=True,
            env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin",
                 "PYTHONPATH": "."},
        )
        seen.add(out.stdout.strip())

    assert seen == {"ServerTokens,ServerSignature"}, (
        f"triggered_by varia com o PYTHONHASHSEED: {seen}")
