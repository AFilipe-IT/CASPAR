"""
tests/test_live_service.py
--------------------------
Regression: `--live <service>` must route to the correct plugin and config
path. Before, resolve_live_service() always returned the Apache config
(via an unconditional apache2ctl -V probe), regardless of the service name.
"""

from __future__ import annotations

import pytest

import config_assessment.core.input_resolver as ir
from config_assessment.core.input_resolver import resolve_live_service


_ENTRY = {
    "nginx": ("nginx", "nginx.conf", "worker_processes 1;\n"),
    "ssh":   ("ssh", "sshd_config", "PermitRootLogin yes\nPort 22\n"),
    "mysql": ("mysql", "mysqld.cnf", "[mysqld]\nlocal_infile = ON\n"),
}


@pytest.mark.parametrize("service", ["nginx", "ssh", "mysql"])
def test_live_routes_to_correct_service(service, tmp_path, monkeypatch):
    plugin_id, fname, content = _ENTRY[service]
    (tmp_path / fname).write_text(content)

    # Point the service's mapped directory at our fixture dir.
    patched = dict(ir._LIVE_SERVICE_MAP)
    patched[service] = (plugin_id, str(tmp_path) + "/")
    monkeypatch.setattr(ir, "_LIVE_SERVICE_MAP", patched)

    resolved = resolve_live_service(service)
    assert resolved.mode == "live"
    assert resolved.metadata["service"] == plugin_id
    assert resolved.path.endswith(fname)          # the service's own entry file
    assert "apache2.conf" not in resolved.path     # NOT the Apache config


def test_mysql_ubuntu_layout_resolves_and_is_accepted(tmp_path, monkeypatch):
    # Ubuntu 22.04+/24.04: /etc/mysql/ has mysql.cnf (main) + my.cnf symlink.
    # resolve_directory must pick mysql.cnf, and the mysql plugin must accept it.
    import os
    from config_assessment.core.runtime import registered_plugins
    import config_assessment.plugins.mysql  # noqa: F401  (register)

    (tmp_path / "mysql.conf.d").mkdir()
    (tmp_path / "mysql.cnf").write_text("[mysqld]\nlocal_infile = ON\n")
    os.symlink(tmp_path / "mysql.cnf", tmp_path / "my.cnf")  # symlink, as on Ubuntu

    patched = dict(ir._LIVE_SERVICE_MAP)
    patched["mysql"] = ("mysql", str(tmp_path) + "/")
    monkeypatch.setattr(ir, "_LIVE_SERVICE_MAP", patched)

    resolved = resolve_live_service("mysql")
    assert resolved.metadata["entry_file"] == "mysql.cnf"   # not the my.cnf symlink
    assert resolved.path.endswith("mysql.cnf")

    mysql_plugin = [p for p in registered_plugins() if p.metadata().name == "mysql"][0]
    assert mysql_plugin.detect(resolved.path) is True        # was the failing point


def test_unknown_service_raises_clear_error():
    with pytest.raises(ValueError) as exc:
        resolve_live_service("unknown_service")
    assert "Unknown live service" in str(exc.value)
    assert "nginx" in str(exc.value)               # lists supported services


def test_service_map_covers_all_plugins():
    # Every routed plugin id should be a real registered target id.
    plugin_ids = {p for p, _ in ir._LIVE_SERVICE_MAP.values()}
    assert {"apache-httpd", "nginx", "ssh", "mysql"} <= plugin_ids


def test_aliases_route_to_same_plugin():
    assert ir._LIVE_SERVICE_MAP["sshd"][0] == ir._LIVE_SERVICE_MAP["ssh"][0]
    assert ir._LIVE_SERVICE_MAP["mariadb"][0] == ir._LIVE_SERVICE_MAP["mysql"][0]
    assert ir._LIVE_SERVICE_MAP["apache"][0] == ir._LIVE_SERVICE_MAP["apache2"][0]


# ------------------------------------------------------------------ #
# Estado do serviço (informativo, nunca condiciona o scan)             #
# ------------------------------------------------------------------ #

class TestServiceRunningState:
    """`--live` lê a configuração em disco e funciona com o serviço parado —
    é intencional. O que faltava era dizê-lo: um Apache em `failed` produzia
    um score normal (7.1, medido) sem uma palavra, e quem estava a degradar a
    configuração para ver o score mexer concluía que era o CASPAR que não
    reagia. Daí `metadata["running"]`, que a CLI usa para avisar.

    Os três valores têm significados distintos e a distinção interessa:
    True/False só quando há resposta do systemd, None quando a pergunta não se
    pode fazer — e None nunca deve gerar aviso.
    """

    def test_active_service_reports_true(self, monkeypatch):
        import subprocess as sp
        monkeypatch.setattr(ir.shutil, "which", lambda _: "/bin/systemctl",
                            raising=False)
        monkeypatch.setattr(
            ir.subprocess, "run",
            lambda *a, **k: sp.CompletedProcess(a[0], 0, "active\n", ""))
        assert ir._service_is_running("apache2") is True

    @pytest.mark.parametrize("state", ["inactive", "failed"])
    def test_stopped_service_reports_false(self, state, monkeypatch):
        """Uma unidade real parada dá exit code 3."""
        import subprocess as sp
        monkeypatch.setattr(ir.shutil, "which", lambda _: "/bin/systemctl",
                            raising=False)
        monkeypatch.setattr(
            ir.subprocess, "run",
            lambda *a, **k: sp.CompletedProcess(a[0], 3, f"{state}\n", ""))
        assert ir._service_is_running("apache2") is False

    def test_unknown_unit_reports_none_not_false(self, monkeypatch):
        """Uma unidade inexistente também diz "inactive", mas com exit code 4.

        Sem esta distinção, `--live mysql` numa máquina onde o MySQL não é uma
        unidade systemd dava o aviso "não está a correr" — enganador, porque o
        que não existe é a unidade.
        """
        import subprocess as sp
        monkeypatch.setattr(ir.shutil, "which", lambda _: "/bin/systemctl",
                            raising=False)
        monkeypatch.setattr(
            ir.subprocess, "run",
            lambda *a, **k: sp.CompletedProcess(a[0], 4, "inactive\n", ""))
        assert ir._service_is_running("mysql") is None

    def test_without_systemctl_reports_none(self, monkeypatch):
        """Dentro de um container não há systemd — a pergunta não se põe."""
        monkeypatch.setattr(ir.shutil, "which", lambda _: None, raising=False)
        assert ir._service_is_running("apache2") is None

    def test_resolution_carries_the_flag(self, tmp_path, monkeypatch):
        """O metadata tem de chegar a quem chama — é o que a CLI lê para avisar."""
        etc = tmp_path / "etc" / "nginx"
        etc.mkdir(parents=True)
        (etc / "nginx.conf").write_text("worker_processes 1;\n")
        monkeypatch.setitem(ir._LIVE_SERVICE_MAP, "nginx", ("nginx", str(etc)))
        monkeypatch.setattr(ir, "_service_is_running", lambda _: False)

        resolved = resolve_live_service("nginx")
        assert resolved.metadata["running"] is False
