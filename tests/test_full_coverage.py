"""
tests/test_full_coverage.py
-----------------------------
Teste de cobertura completa: garante que o scanner deteta TODAS as
misconfigurations presentes no banco quando corre sobre o alvo worst-case
(test_target/httpd.conf), que contém todas elas.

Porquê este teste existe:
  Expôs (e protege contra) bugs como o do LoadModule, em que o parser
  guardava "dav_module modules/mod_dav.so" mas o lookup procurava
  "dav_module" exacto — fazendo com que 5 misconfigurations nunca
  disparassem em configs reais. Sem este teste, regressões assim passam
  despercebidas até alguém reparar manualmente.

Como funciona:
  1. Abre a ccss.db real (falha com mensagem clara se não existir).
  2. Descobre o(s) target(s) e o conjunto esperado de (directive, bad_value).
  3. Corre runtime.scan() sobre test_target/httpd.conf.
  4. Afirma que cada (directive, bad_value) esperado aparece nos issues.
  5. Se faltar algum, lista exactamente quais (diagnóstico acionável).

Requisitos de ambiente (decisão: FALHAR se faltarem, não dar skip):
  - ccss.db construída (ccss build + build_narratives)
  - test_target/httpd.conf presente (gerado nesta sessão)

O alvo worst-case isola valores mutuamente exclusivos (ServerTokens,
SSLProtocol, Options) em blocos <Directory> distintos, por isso todos são
parseados (princípio worst-case) e o conjunto completo é detetável num
único scan.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from core.db.database import Database
from core import runtime


# ── Localizar os artefactos do projeto (raiz = dois níveis acima deste ficheiro) ──
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DB_PATH = _PROJECT_ROOT / "ccss.db"
_TARGET_CONF = _PROJECT_ROOT / "test_target" / "httpd.conf"

# Mapeamento target_name → ficheiro worst-case (value-rules).
# Targets sem entrada são ignorados (ex.: dummy, sem misconfigs no banco).
_WORST_CASE: dict[str, Path] = {
    "apache-httpd": _PROJECT_ROOT / "test_target" / "httpd.conf",
    "nginx":        _PROJECT_ROOT / "test_target" / "nginx.conf",
}

# Mapeamento target_name → ficheiro worst-case para absence rules.
# Um config de ausência tem as condições de trigger (ssl_certificate)
# mas NÃO tem as directivas que deviam estar presentes.
_WORST_CASE_ABSENCE: dict[str, Path] = {
    "apache-httpd": _PROJECT_ROOT / "test_target" / "httpd_absence.conf",
    "nginx":        _PROJECT_ROOT / "test_target" / "nginx_absence.conf",
}


def _require(path: Path, what: str, how: str) -> None:
    """Fail loudly with an actionable message if a required artefact is missing."""
    if not path.exists():
        pytest.fail(
            f"{what} não encontrado em {path}.\n"
            f"  Para preparar o ambiente: {how}"
        )


def _distinct_targets(db: Database) -> list[str]:
    """Discover target names present in the DB (no hardcoding of 'apache_httpd')."""
    cur = db._conn.execute("SELECT DISTINCT target_name FROM misconfigurations")
    return [row[0] for row in cur.fetchall()]


@pytest.fixture(scope="module", autouse=True)
def _register_plugins():
    """
    Ensure the runtime plugin registry is populated before any scan.

    Plugins register themselves as a side-effect of being imported (the CLI
    does this via _discover_plugins, which simply imports each plugins.* module).
    When this test runs in isolation, nothing else imports the Apache plugin, so
    runtime.registered_plugins() is empty and _select_plugin() raises. Importing
    the plugin module here reproduces the CLI's discovery behaviour without
    depending on the CLI itself.
    """
    import importlib

    plugins_dir = _PROJECT_ROOT / "plugins"
    if plugins_dir.exists():
        for plugin_dir in sorted(plugins_dir.iterdir()):
            if plugin_dir.is_dir() and (plugin_dir / "__init__.py").exists():
                try:
                    importlib.import_module(f"plugins.{plugin_dir.name}")
                except Exception:
                    pass  # a broken optional plugin shouldn't break coverage testing

    # Fallback: if discovery didn't register anything, register Apache explicitly.
    if not runtime.registered_plugins():
        from plugins.apache_httpd import ApachePlugin
        runtime.register_plugin(ApachePlugin())

    assert runtime.registered_plugins(), (
        "Nenhum plugin registado após discovery — verifica que "
        "plugins/apache_httpd/__init__.py regista o ApachePlugin ao ser importado."
    )


@pytest.fixture(scope="module")
def db() -> Database:
    _require(
        _DB_PATH,
        "Banco ccss.db",
        "ccss build --benchmark <pdf> && python3 -m plugins.apache_httpd.build_narratives --db ccss.db",
    )
    with Database(str(_DB_PATH)) as database:
        yield database


@pytest.fixture(scope="module")
def scan_result(db):
    _require(
        _TARGET_CONF,
        "Alvo de teste test_target/httpd.conf",
        "gerar o worst-case config (test_target/httpd.conf) com todas as misconfigurations",
    )
    return runtime.scan(str(_TARGET_CONF), db)


# ──────────────────────────────────────────────────────────────────────
# Sanity checks on the environment
# ──────────────────────────────────────────────────────────────────────

def test_db_has_misconfigurations(db):
    """The DB must contain at least one target with misconfigurations."""
    targets = _distinct_targets(db)
    assert targets, "Nenhum target no banco — corre 'ccss build' primeiro."
    total = 0
    for t in targets:
        total += len(db.get_all_misconfigurations(t))
    assert total > 0, "O banco não tem misconfigurations — build incompleto."


def test_scan_produces_issues(scan_result):
    """The worst-case scan must produce issues (not a clean result)."""
    assert scan_result.issues, "O scan do alvo worst-case não produziu issues."


# ──────────────────────────────────────────────────────────────────────
# The core coverage assertion
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("target_name,worst_case", sorted(_WORST_CASE.items()))
def test_all_db_misconfigurations_are_detected(db, target_name, worst_case):
    """
    Every (directive, bad_value) stored in the DB for a given target must be
    detected when scanning that target's worst-case config. Parametrized per
    target so each plugin gets an independent pass/fail entry.
    """
    _require(
        worst_case,
        f"Alvo worst-case para {target_name!r}",
        f"criar {worst_case.relative_to(_PROJECT_ROOT)}",
    )
    scan = runtime.scan(str(worst_case), db)

    # Apenas value-rules: absence rules requerem o config oposto (directiva ausente)
    # e são testadas por test_all_absence_rules_are_detected.
    expected: set[tuple[str, str]] = {
        (m.directive, m.bad_value)
        for m in db.get_all_misconfigurations(target_name)
        if m.rule_type == "value"
    }
    assert expected, f"Banco não tem value-rule misconfigurations para {target_name!r}."

    detected: set[tuple[str, str]] = {
        (issue.directive, issue.bad_value)
        for issue in scan.issues
        if issue.rule_type == "value"
    }
    missing = expected - detected
    if missing:
        listing = "\n".join(f"  - {d} = {v}" for d, v in sorted(missing))
        pytest.fail(
            f"[{target_name}] {len(missing)}/{len(expected)} misconfigurations NÃO "
            f"foram detetadas no alvo worst-case:\n{listing}\n\n"
            "Causa provável: o parser e o lookup discordam sobre o 'value' desta "
            "directiva (ex.: LoadModule guardava o caminho .so). Verifica o parser "
            "e o bad_value no banco."
        )

    assert expected.issubset(detected), "Cobertura incompleta (ver acima)."


@pytest.mark.parametrize("target_name,absence_case", sorted(_WORST_CASE_ABSENCE.items()))
def test_all_absence_rules_are_detected(db, target_name, absence_case):
    """
    Every absence rule in the DB for a given target must fire when scanning a
    config that has the trigger condition met but lacks the required directives.
    Parametrized per target (currently only nginx has absence rules).
    """
    _require(
        absence_case,
        f"Alvo absence worst-case para {target_name!r}",
        f"criar {absence_case.relative_to(_PROJECT_ROOT)}",
    )
    scan = runtime.scan(str(absence_case), db)

    expected: set[tuple[str, str]] = {
        (m.directive, m.bad_value)
        for m in db.get_absence_rules(target_name)
    }
    if not expected:
        pytest.skip(f"Banco não tem absence rules para {target_name!r} — nada a verificar.")

    detected: set[tuple[str, str]] = {
        (issue.directive, issue.bad_value)
        for issue in scan.issues
        if issue.rule_type == "absence"
    }
    missing = expected - detected
    if missing:
        listing = "\n".join(f"  - {d!r} (bad_value={v!r})" for d, v in sorted(missing))
        pytest.fail(
            f"[{target_name}] {len(missing)}/{len(expected)} absence rules NÃO "
            f"dispararam no alvo absence worst-case:\n{listing}\n\n"
            "Verifica que o config de ausência tem as condições de trigger (ex.: "
            "ssl_certificate presente) mas não tem as directivas requeridas."
        )

    assert expected.issubset(detected), "Cobertura de ausências incompleta (ver acima)."


def test_loadmodule_specifically_detected(db, scan_result):
    """
    Regression guard for the LoadModule .so-path bug specifically.
    Every LoadModule entry in the DB must be detected by module name,
    even though the config lines include the full 'modules/mod_x.so' path.
    """
    expected_modules = {
        m.bad_value
        for t in _distinct_targets(db)
        for m in db.get_all_misconfigurations(t)
        if m.directive == "LoadModule"
    }
    if not expected_modules:
        pytest.skip("Banco não tem entradas LoadModule — nada a verificar.")

    detected_modules = {
        issue.bad_value
        for issue in scan_result.issues
        if issue.directive == "LoadModule"
    }

    missing = expected_modules - detected_modules
    assert not missing, (
        f"LoadModule não detetado para: {sorted(missing)}. "
        "O parser deve normalizar o value para o nome do módulo (1º token), "
        "não a linha completa com o caminho .so."
    )


@pytest.mark.parametrize("target_name,worst_case", sorted(_WORST_CASE.items()))
def test_no_unexpected_directives_detected(db, target_name, worst_case):
    """
    Sanity in the other direction: every detected issue must correspond to a
    real DB entry for that specific target (no phantom detections). Parametrized
    per target and filtered to the correct target's valid set — using a union of
    all targets would mask phantoms that coincidentally match another plugin's
    bad_values.
    """
    _require(
        worst_case,
        f"Alvo worst-case para {target_name!r}",
        f"criar {worst_case.relative_to(_PROJECT_ROOT)}",
    )
    scan = runtime.scan(str(worst_case), db)

    # valid inclui todos os tipos (value + absence) — qualquer issue detectado deve
    # corresponder a uma entrada real no banco, independentemente do tipo de regra.
    valid: set[tuple[str, str]] = {
        (m.directive, m.bad_value) for m in db.get_all_misconfigurations(target_name)
    }
    detected = {(i.directive, i.bad_value) for i in scan.issues}
    phantom = detected - valid
    assert not phantom, (
        f"[{target_name}] Issues detetados que não existem no banco: {sorted(phantom)}. "
        "Isto não devia acontecer — o lookup é por match exacto."
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
