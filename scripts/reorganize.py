#!/usr/bin/env python3
"""
scripts/reorganize.py — Reorganiza CASPAR para o layout config_assessment/.

Idempotente: se já estiver reorganizado, os passos de movimentação são no-ops.

Passos:
  1. Criar a estrutura de pastas nova (com __init__.py)
  2. Mover ficheiros (git mv quando possível, senão shutil.move)
  3. Actualizar imports em TODOS os .py (incluindo templates string no scaffolder)
  4. Actualizar pyproject.toml (packages, pythonpath)
  5. (reinstalação fica a cargo do operador: pip install -e .)

Corre a partir da raiz do repo:  python scripts/reorganize.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "config_assessment"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _run_git(*args) -> bool:
    try:
        subprocess.run(["git", *args], cwd=ROOT, check=True,
                       capture_output=True, text=True)
        return True
    except Exception:
        return False


def _is_git_tracked(p: Path) -> bool:
    res = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(p.relative_to(ROOT))],
        cwd=ROOT, capture_output=True, text=True,
    )
    return res.returncode == 0


def move(src: Path, dst: Path) -> None:
    """Move src→dst preservando histórico git quando possível. No-op se já movido."""
    if not src.exists():
        if dst.exists():
            print(f"  · já movido: {dst.relative_to(ROOT)}")
        else:
            print(f"  ! origem inexistente (ignorado): {src.relative_to(ROOT)}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if _is_git_tracked(src) and _run_git("mv", "-f",
                                         str(src.relative_to(ROOT)),
                                         str(dst.relative_to(ROOT))):
        print(f"  → git mv {src.relative_to(ROOT)} → {dst.relative_to(ROOT)}")
    else:
        shutil.move(str(src), str(dst))
        print(f"  → mv {src.relative_to(ROOT)} → {dst.relative_to(ROOT)}")


def ensure_pkg_dir(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    init = d / "__init__.py"
    if not init.exists():
        init.write_text('"""Auto-created package init."""\n', encoding="utf-8")
        print(f"  + {init.relative_to(ROOT)}")


# --------------------------------------------------------------------------- #
# Passo 1 — estrutura
# --------------------------------------------------------------------------- #

def step1_structure() -> None:
    print("\n[1] A criar estrutura de pastas…")
    for sub in ("core", "core/db", "build", "enrichment",
                "reports", "parsers", "plugins"):
        ensure_pkg_dir(PKG / sub)
    # __init__.py do pacote raiz
    root_init = PKG / "__init__.py"
    if not root_init.exists():
        root_init.write_text('"""CASPAR — Configuration Assessment package."""\n',
                             encoding="utf-8")
        print(f"  + {root_init.relative_to(ROOT)}")
    for d in ("scripts", "benchmarks", "data"):
        (ROOT / d).mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# Passo 2 — mover ficheiros
# --------------------------------------------------------------------------- #

# core/ → config_assessment/core/   (runtime determinístico)
CORE_KEEP = ["runtime.py", "models.py", "target.py", "ccss.py",
             "input_resolver.py"]
# core/db/ → config_assessment/core/db/
CORE_DB = ["__init__.py", "database.py", "schema.sql"]
# core/ → config_assessment/build/
TO_BUILD = ["llm_client.py", "rag.py", "benchmark_extractor.py",
            "generic_build.py", "plugin_scaffolder.py", "plugin_detector.py"]
# core/ → config_assessment/enrichment/
TO_ENRICH = ["cve_enricher.py", "exploit_enricher.py", "version_prefetch.py"]
# core/ → config_assessment/reports/
TO_REPORTS = ["report_html.py", "report_dashboard.py",
              "report_dashboard_online.py"]
# core/parsers/ → config_assessment/parsers/
PARSERS = ["__init__.py", "key_value.py"]


def step2_move() -> None:
    print("\n[2] A mover ficheiros…")
    old_core = ROOT / "core"

    # core runtime
    for f in CORE_KEEP:
        move(old_core / f, PKG / "core" / f)
    # core/__init__.py (manter como core package init)
    move(old_core / "__init__.py", PKG / "core" / "__init__.py")
    # core/db
    for f in CORE_DB:
        move(old_core / "db" / f, PKG / "core" / "db" / f)
    # core/parsers
    for f in PARSERS:
        move(old_core / "parsers" / f, PKG / "parsers" / f)
    # build
    for f in TO_BUILD:
        move(old_core / f, PKG / "build" / f)
    # build.py → build_utils.py (evita conflito com pasta build/)
    move(old_core / "build.py", PKG / "build" / "build_utils.py")
    # enrichment
    for f in TO_ENRICH:
        move(old_core / f, PKG / "enrichment" / f)
    # reports
    for f in TO_REPORTS:
        move(old_core / f, PKG / "reports" / f)

    # chain_pipeline: partilhado entre plugins/builds → config_assessment/build/
    move(ROOT / "plugins" / "apache_httpd" / "chain_pipeline.py",
         PKG / "build" / "chain_pipeline.py")

    # plugins/ → config_assessment/plugins/   (move directório inteiro)
    old_plugins = ROOT / "plugins"
    if old_plugins.exists():
        for entry in sorted(old_plugins.iterdir()):
            move(entry, PKG / "plugins" / entry.name)

    # limpar dirs antigos vazios
    for d in (old_core / "db", old_core / "parsers", old_core, old_plugins):
        if d.exists() and not any(d.iterdir()):
            d.rmdir()
            print(f"  - rmdir {d.relative_to(ROOT)}")

    # scripts históricos
    for pat in ("fix_*.py", "patch_*.py"):
        for f in sorted(ROOT.glob(pat)):
            move(f, ROOT / "scripts" / f.name)

    # benchmarks (CIS_*.pdf na raiz)
    for f in sorted(ROOT.glob("CIS_*.pdf")):
        move(f, ROOT / "benchmarks" / f.name)

    # data canónica
    move(ROOT / "ccss_canonical.sql", ROOT / "data" / "ccss_canonical.sql")


# --------------------------------------------------------------------------- #
# Passo 3 — actualizar imports
# --------------------------------------------------------------------------- #

# Ordem IMPORTA. As regras "específicas" (core.<modulo> → build/enrichment/…)
# têm de correr ANTES da regra genérica "core." → "config_assessment.core.".
# Por isso re-prefixamos directamente para o destino final.
REPLACEMENTS: list[tuple[str, str]] = [
    # Forma "from core import X" (sem ponto a seguir a core) — X moveu de pacote.
    ("from core import version_prefetch",
     "from config_assessment.enrichment import version_prefetch"),
    ("from core import runtime",
     "from config_assessment.core import runtime"),

    # chain_pipeline saiu de plugins/apache_httpd → build/
    ("plugins.apache_httpd.chain_pipeline",
     "config_assessment.build.chain_pipeline"),

    # core/ módulos que foram para build/
    ("core.llm_client",          "config_assessment.build.llm_client"),
    ("core.rag",                 "config_assessment.build.rag"),
    ("core.benchmark_extractor", "config_assessment.build.benchmark_extractor"),
    ("core.generic_build",       "config_assessment.build.generic_build"),
    ("core.plugin_scaffolder",   "config_assessment.build.plugin_scaffolder"),
    ("core.plugin_detector",     "config_assessment.build.plugin_detector"),
    # core/build.py → build/build_utils.py
    ("core.build",               "config_assessment.build.build_utils"),

    # core/ → enrichment/
    ("core.cve_enricher",        "config_assessment.enrichment.cve_enricher"),
    ("core.exploit_enricher",    "config_assessment.enrichment.exploit_enricher"),
    ("core.version_prefetch",    "config_assessment.enrichment.version_prefetch"),

    # core/ → reports/  (report_dashboard_online antes de report_dashboard
    #                    para evitar match parcial — usamos limites de palavra)
    ("core.report_dashboard_online",
     "config_assessment.reports.report_dashboard_online"),
    ("core.report_dashboard",    "config_assessment.reports.report_dashboard"),
    ("core.report_html",         "config_assessment.reports.report_html"),

    # core/parsers/ → parsers/
    ("core.parsers.",            "config_assessment.parsers."),

    # genérico: tudo o resto em core. continua dentro de config_assessment.core.
    ("core.",                    "config_assessment.core."),

    # plugins/ → config_assessment/plugins/
    ("plugins.",                 "config_assessment.plugins."),
]


def _rewrite_imports(text: str) -> str:
    """Reescreve imports/strings. Usa \\b à esquerda do token a substituir
    para não tocar em 'config_assessment.core.' já reescrito (idempotência)."""
    for old, new in REPLACEMENTS:
        # \b antes do token, e garantir que não está já prefixado por
        # 'config_assessment.' (evita dupla reescrita ao re-correr).
        pattern = re.compile(r"(?<![\w.])" + re.escape(old))
        text = pattern.sub(new, text)
    return text


def step3_imports() -> None:
    print("\n[3] A actualizar imports…")
    n = 0
    for py in sorted(PKG.rglob("*.py")) + \
            sorted((ROOT / "cli").rglob("*.py")) + \
            sorted((ROOT / "tests").rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        original = py.read_text(encoding="utf-8")
        updated = _rewrite_imports(original)
        if updated != original:
            py.write_text(updated, encoding="utf-8")
            print(f"  ✎ {py.relative_to(ROOT)}")
            n += 1
    print(f"  ({n} ficheiros alterados)")


# --------------------------------------------------------------------------- #
# Passo 3b — paths hardcoded em runtime
# --------------------------------------------------------------------------- #

def step3b_runtime_paths() -> None:
    """Corrige paths dinâmicos que apontavam para ./plugins e ./core."""
    print("\n[3b] A corrigir paths hardcoded de runtime…")

    # cli/main.py — descoberta de plugins (parent.parent / "plugins")
    main = ROOT / "cli" / "main.py"
    txt = main.read_text(encoding="utf-8")
    before = txt
    # _discover_plugins: parent.parent / "plugins"  → /"config_assessment"/"plugins"
    txt = txt.replace(
        'Path(__file__).parent.parent / "plugins"',
        'Path(__file__).parent.parent / "config_assessment" / "plugins"',
    )
    txt = txt.replace(
        '_Path(__file__).resolve().parent.parent / "plugins"',
        '_Path(__file__).resolve().parent.parent / "config_assessment" / "plugins"',
    )
    # módulo importado dinamicamente
    txt = txt.replace(
        'importlib.import_module(f"plugins.{plugin_dir.name}")',
        'importlib.import_module(f"config_assessment.plugins.{plugin_dir.name}")',
    )
    if txt != before:
        main.write_text(txt, encoding="utf-8")
        print("  ✎ cli/main.py (discovery + import dinâmico)")

    # generic_build.py — chains.json em ./plugins/<id>/chains.json
    gb = PKG / "build" / "generic_build.py"
    if gb.exists():
        t = gb.read_text(encoding="utf-8")
        b = t
        t = t.replace(
            'Path("plugins") / target_id / "chains.json"',
            'Path("config_assessment") / "plugins" / target_id / "chains.json"',
        )
        if t != b:
            gb.write_text(t, encoding="utf-8")
            print("  ✎ config_assessment/build/generic_build.py (chains.json path)")


# --------------------------------------------------------------------------- #
# Passo 4 — pyproject.toml
# --------------------------------------------------------------------------- #

def step4_pyproject() -> None:
    print("\n[4] A actualizar pyproject.toml…")
    pp = ROOT / "pyproject.toml"
    txt = pp.read_text(encoding="utf-8")
    before = txt

    # hatch wheel packages
    txt = txt.replace(
        'packages = ["core", "plugins", "cli"]',
        'packages = ["config_assessment", "cli"]',
    )
    # pytest pythonpath comment ok; "." continua a funcionar
    txt = txt.replace(
        'pythonpath = ["."]  # so \'from core.xxx import\' works without install',
        'pythonpath = ["."]  # so \'from config_assessment.xxx import\' works without install',
    )
    if txt != before:
        pp.write_text(txt, encoding="utf-8")
        print("  ✎ pyproject.toml")
    else:
        print("  · pyproject.toml já actualizado")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> int:
    if not (ROOT / "pyproject.toml").exists():
        print("ERRO: corre a partir da raiz do repo CASPAR.", file=sys.stderr)
        return 1
    step1_structure()
    step2_move()
    step3_imports()
    step3b_runtime_paths()
    step4_pyproject()
    print("\n✅ Reorganização concluída. Agora:")
    print("   pip install -e . --break-system-packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
