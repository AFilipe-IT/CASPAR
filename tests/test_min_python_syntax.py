"""
tests/test_min_python_syntax.py
-------------------------------
Guarda a versão mínima de Python declarada no pyproject (3.10).

Porquê um teste só para isto: um `SyntaxError` num módulo importado à cabeça
não falha um teste — impede a *recolha* da suite inteira. Aconteceu mesmo, com
uma f-string multi-linha (PEP 701, só válida em 3.12+) em `cli/_output.py`: o
CI ficou vermelho durante 7 commits em `tests (3.10)` sem que ninguém ligasse,
porque o desenvolvimento local corre em 3.12 e lá a sintaxe é legal. O `caspar`
instalado em Ubuntu 22.04 (Python 3.10 de origem) não arrancava de todo.

`compile()` é usado em vez de `ast.parse(feature_version=...)` de propósito:
`feature_version` afeta a gramática mas não o lexer de f-strings, portanto
deixa passar exatamente a classe de erro que motivou este teste. Este teste
corre em qualquer versão e só é uma verificação *real* quando corre em 3.10 —
que é precisamente o que a matriz do CI garante.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGES = ("cli", "config_assessment")

# Lido do pyproject: requires-python = ">=3.10".
MIN_PYTHON = (3, 10)


def _source_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for pkg in PACKAGES:
        files.extend(sorted((REPO_ROOT / pkg).rglob("*.py")))
    return files


def test_source_files_were_found():
    """Sem isto, um erro de caminho tornaria os testes abaixo vacuamente verdes."""
    assert len(_source_files()) > 50


@pytest.mark.skipif(
    sys.version_info >= (3, 12),
    reason="a sintaxe só pode ser validada contra a versão mínima pelo próprio "
           "interpretador; em 3.12 construções PEP 701 compilam e o teste não "
           "provaria nada. A matriz do CI corre esta suite em 3.10.",
)
def test_all_sources_compile_on_minimum_python():
    """Cada módulo tem de compilar no interpretador mínimo suportado."""
    failures = []
    for path in _source_files():
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except SyntaxError as exc:
            rel = path.relative_to(REPO_ROOT)
            failures.append(f"{rel}:{exc.lineno}: {exc.msg}")

    assert not failures, (
        f"Sintaxe inválida em Python {'.'.join(map(str, MIN_PYTHON))}:\n  "
        + "\n  ".join(failures)
    )


def test_no_multiline_expressions_inside_fstrings():
    """Deteta quebras de linha dentro de `{...}` de f-strings em qualquer versão.

    A verificação acima só morde quando a suite corre em 3.10; esta corre
    sempre, para que um programador em 3.12 veja a falha antes do push em vez
    de a descobrir no CI. Faz uma leitura textual deliberadamente simples: uma
    f-string cujo `{` não fecha na mesma linha.
    """
    offenders = []
    for path in _source_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not (stripped.startswith(("f'", 'f"')) or ' f"' in stripped
                    or " f'" in stripped):
                continue
            # Chavetas por fechar + aspas ímpares = a expressão continua na
            # linha seguinte, o que só é legal a partir do 3.12.
            if stripped.count("{") > stripped.count("}") and (
                stripped.count('"') % 2 == 1 or stripped.count("'") % 2 == 1
            ):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {stripped}")

    assert not offenders, (
        "Expressão multi-linha dentro de f-string (PEP 701, requer Python "
        "3.12+; este projeto suporta 3.10). Extraia o valor para uma variável "
        "antes da f-string:\n  " + "\n  ".join(offenders)
    )
