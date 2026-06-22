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
    _version_from_config_text,
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
