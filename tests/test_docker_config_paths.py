"""
tests/test_docker_config_paths.py
----------------------------------
Regression: resolve_docker must search config paths for ALL registered
targets, not just Apache/Nginx. SSH (/etc/ssh/sshd_config) and MySQL
(/etc/mysql/mysql.conf.d/mysqld.cnf) configs were never found before.

Two layers are covered offline:
  1. CONFIG_PATHS_TO_TRY covers every target's config directory.
  2. resolve_directory() recognises sshd_config / mysqld.cnf as entry points
     (neither is a *.conf file, so they must be listed explicitly).
"""

from __future__ import annotations

from config_assessment.core.input_resolver import (
    CONFIG_PATHS_TO_TRY,
    resolve_directory,
)


class TestConfigPathsCoverage:
    def test_covers_apache_nginx(self):
        assert "/etc/apache2/" in CONFIG_PATHS_TO_TRY
        assert "/etc/nginx/" in CONFIG_PATHS_TO_TRY

    def test_covers_ssh(self):
        assert "/etc/ssh/" in CONFIG_PATHS_TO_TRY

    def test_covers_mysql(self):
        assert "/etc/mysql/mysql.conf.d/" in CONFIG_PATHS_TO_TRY
        assert "/etc/mysql/" in CONFIG_PATHS_TO_TRY


class TestEntryPointRecognition:
    """resolve_directory must locate non-.conf entry points once extracted."""

    def test_finds_sshd_config(self, tmp_path):
        (tmp_path / "sshd_config").write_text("PermitRootLogin yes\n")
        r = resolve_directory(str(tmp_path))
        assert r.metadata["entry_file"] == "sshd_config"

    def test_finds_mysqld_cnf(self, tmp_path):
        (tmp_path / "mysqld.cnf").write_text("[mysqld]\nlocal_infile = ON\n")
        r = resolve_directory(str(tmp_path))
        assert r.metadata["entry_file"] == "mysqld.cnf"
