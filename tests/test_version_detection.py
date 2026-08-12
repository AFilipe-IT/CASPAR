"""
tests/test_version_detection.py
--------------------------------
Best-effort, offline service-version detection used to drive the CVE/exploit
cross-reference (version_exploits). Covers the docker-tag parser and the
config-text fallback. The binary-on-PATH path is environment-dependent and is
not asserted here.
"""

from __future__ import annotations

from config_assessment.core.input_resolver import (
    version_from_docker_tag,
    detect_version,
    _clean_package_version,
    _version_from_config_text,
    _version_from_package_db,
)


class TestDockerTag:
    def test_simple_semver_tag(self):
        assert version_from_docker_tag("httpd:2.4.58") == "2.4.58"

    def test_two_component_tag(self):
        assert version_from_docker_tag("httpd:2.4") == "2.4"

    def test_v_prefixed_tag(self):
        assert version_from_docker_tag("nginx:v1.25.3") == "1.25.3"

    def test_registry_and_repo_ignored(self):
        assert version_from_docker_tag("docker.io/library/mysql:8.0.36") == "8.0.36"

    def test_no_tag_returns_none(self):
        assert version_from_docker_tag("httpd") is None

    def test_non_version_tag_returns_none(self):
        assert version_from_docker_tag("httpd:latest") is None


class TestConfigText:
    def test_apache_version_in_config(self, tmp_path):
        # Test the config-text extractor in isolation (detect_version may prefer
        # a binary on PATH, which is environment-dependent).
        cfg = tmp_path / "httpd.conf"
        cfg.write_text("# Server built: Apache/2.4.51 (Unix)\nListen 80\n")
        assert _version_from_config_text("apache-httpd", str(cfg)) == "2.4.51"

    def test_no_version_in_config_returns_none(self, tmp_path):
        cfg = tmp_path / "httpd.conf"
        cfg.write_text("Listen 80\nServerTokens Full\n")
        assert _version_from_config_text("apache-httpd", str(cfg)) is None

    def test_docker_tag_takes_precedence(self, tmp_path):
        cfg = tmp_path / "httpd.conf"
        cfg.write_text("Apache/2.4.10\n")
        # Explicit image hint wins over config text.
        assert detect_version("apache-httpd", str(cfg),
                              image="httpd:2.4.58") == "2.4.58"


class TestCleanPackageVersion:
    """A versão upstream a partir da versão de pacote da distribuição."""

    def test_strips_debian_revision(self):
        assert _clean_package_version("2.4.58-1ubuntu8.15") == "2.4.58"

    def test_strips_epoch_and_patch_suffix(self):
        # OpenSSH traz epoch (1:) e sufixo de patch (p1) — nenhum é upstream.
        assert _clean_package_version("1:9.6p1-3ubuntu13.18") == "9.6"

    def test_plain_version_untouched(self):
        assert _clean_package_version("1.25.3") == "1.25.3"

    def test_non_numeric_returns_none(self):
        assert _clean_package_version("nonsense") is None


class TestPackageDatabase:
    """Detecção pela base de dados de pacotes.

    É o que faz o servidor pontuar como a CLI: dentro do contentor o `/etc` do
    host está montado mas o binário do serviço não existe, e sem versão não há
    evidência de exploits — o mesmo ServerTokens caía de 7.1 para 6.0, que se
    lia como o watch a não reagir às alterações.
    """

    def _status(self, tmp_path, monkeypatch, content):
        import config_assessment.core.input_resolver as ir
        status = tmp_path / "status"
        status.write_text(content)
        monkeypatch.setattr(ir, "_DPKG_STATUS", str(status))

    def test_apache_version_from_dpkg(self, tmp_path, monkeypatch):
        self._status(tmp_path, monkeypatch,
                     "Package: apache2\n"
                     "Status: install ok installed\n"
                     "Version: 2.4.58-1ubuntu8.15\n\n")
        assert _version_from_package_db("apache-httpd") == "2.4.58"

    def test_removed_package_is_ignored(self, tmp_path, monkeypatch):
        # Um pacote removido-mas-não-purgado mantém a entrada e a versão.
        # Reportá-la daria a versão de algo que já não está instalado.
        self._status(tmp_path, monkeypatch,
                     "Package: apache2\n"
                     "Status: deinstall ok config-files\n"
                     "Version: 2.4.58-1ubuntu8.15\n\n")
        assert _version_from_package_db("apache-httpd") is None

    def test_preference_order_wins_over_file_order(self, tmp_path, monkeypatch):
        # nginx-core é preferido a nginx, mesmo aparecendo depois no ficheiro.
        self._status(tmp_path, monkeypatch,
                     "Package: nginx\n"
                     "Status: install ok installed\n"
                     "Version: 1.18.0-0ubuntu1\n\n"
                     "Package: nginx-core\n"
                     "Status: install ok installed\n"
                     "Version: 1.24.0-2ubuntu7\n\n")
        assert _version_from_package_db("nginx") == "1.24.0"

    def test_missing_database_returns_none(self, tmp_path, monkeypatch):
        import config_assessment.core.input_resolver as ir
        monkeypatch.setattr(ir, "_DPKG_STATUS", str(tmp_path / "nao-existe"))
        assert _version_from_package_db("apache-httpd") is None

    def test_unknown_target_returns_none(self, tmp_path, monkeypatch):
        self._status(tmp_path, monkeypatch,
                     "Package: apache2\n"
                     "Status: install ok installed\n"
                     "Version: 2.4.58-1ubuntu8.15\n\n")
        assert _version_from_package_db("produto-desconhecido") is None

    def test_detect_version_falls_back_to_package_db(self, tmp_path, monkeypatch):
        """A cadeia completa: sem tag, sem binário e sem versão na config,
        detect_version tem de chegar ao pacote em vez de devolver None."""
        import config_assessment.core.input_resolver as ir

        cfg = tmp_path / "apache2.conf"
        cfg.write_text("ServerTokens Full\n")      # sem versão no texto
        monkeypatch.setattr(ir, "_version_from_binary", lambda target_id: None)
        self._status(tmp_path, monkeypatch,
                     "Package: apache2\n"
                     "Status: install ok installed\n"
                     "Version: 2.4.58-1ubuntu8.15\n\n")

        assert ir.detect_version("apache-httpd", str(cfg)) == "2.4.58"

    def test_binary_takes_precedence_over_package(self, tmp_path, monkeypatch):
        # O binário é o que está mesmo a correr; o pacote é o que está instalado.
        import config_assessment.core.input_resolver as ir

        cfg = tmp_path / "apache2.conf"
        cfg.write_text("ServerTokens Full\n")
        monkeypatch.setattr(ir, "_version_from_binary", lambda target_id: "2.4.99")
        self._status(tmp_path, monkeypatch,
                     "Package: apache2\n"
                     "Status: install ok installed\n"
                     "Version: 2.4.58-1ubuntu8.15\n\n")

        assert ir.detect_version("apache-httpd", str(cfg)) == "2.4.99"


class TestResolveDockerVersionMetadata:
    """Regression: resolve_docker must store the tag version in metadata so the
    runtime can fire F1 amplification for docker:// scans (was always None)."""

    def test_tag_version_lands_in_metadata(self, tmp_path, monkeypatch):
        import config_assessment.core.input_resolver as ir

        cfg = tmp_path / "httpd.conf"
        cfg.write_text("ServerTokens Full\n")

        # Stub out the daemon-dependent steps so the test runs offline.
        monkeypatch.setattr(ir, "_docker_available", lambda: True)
        monkeypatch.setattr(ir, "_docker_image_exists", lambda image: True)
        monkeypatch.setattr(ir, "_extract_config_from_image",
                            lambda image, tmpdir: str(tmp_path))

        resolved = ir.resolve_docker("docker://httpd:2.4.49")
        try:
            assert resolved.metadata.get("version") == "2.4.49"
            assert resolved.metadata.get("image") == "httpd:2.4.49"
        finally:
            if resolved.cleanup:
                resolved.cleanup()

    def test_non_version_tag_leaves_metadata_unset(self, tmp_path, monkeypatch):
        import config_assessment.core.input_resolver as ir

        (tmp_path / "httpd.conf").write_text("Listen 80\n")
        monkeypatch.setattr(ir, "_docker_available", lambda: True)
        monkeypatch.setattr(ir, "_docker_image_exists", lambda image: True)
        monkeypatch.setattr(ir, "_extract_config_from_image",
                            lambda image, tmpdir: str(tmp_path))

        resolved = ir.resolve_docker("docker://httpd:latest")
        try:
            # "latest" is not a version → no version key, graceful.
            assert resolved.metadata.get("version") is None
        finally:
            if resolved.cleanup:
                resolved.cleanup()
