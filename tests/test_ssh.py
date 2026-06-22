"""
tests/test_ssh.py
-----------------
Tests for the SSH plugin (Peça 1: parser).
"""

from __future__ import annotations

from config_assessment.core.models import Directive
from config_assessment.plugins.ssh import SSHPlugin
from config_assessment.plugins.ssh.parser import parse_file, _canonical
from config_assessment.plugins.ssh.rules import infer_profile
from config_assessment.core.target import CONFIDENCE_EXACT_FILENAME, CONFIDENCE_SYNTAX_MARKER


def _dirs(*pairs):
    return [Directive(name=n, value=v) for n, v in pairs]


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


class TestCanonical:
    def test_keyword_case_insensitive(self):
        assert _canonical("permitrootlogin") == "PermitRootLogin"
        assert _canonical("PERMITROOTLOGIN") == "PermitRootLogin"
        assert _canonical("PermitRootLogin") == "PermitRootLogin"

    def test_unknown_keyword_kept_as_is(self):
        assert _canonical("SomeCustomThing") == "SomeCustomThing"


class TestParser:
    def test_simple_keyword_value(self, tmp_path):
        cfg = _write(tmp_path, "sshd_config", "PermitRootLogin no\nMaxAuthTries 4\n")
        ds = parse_file(str(cfg))
        by = {d.name: d for d in ds}
        assert by["PermitRootLogin"].value == "no"
        assert by["MaxAuthTries"].value == "4"

    def test_keyword_normalised_value_case_preserved(self, tmp_path):
        cfg = _write(tmp_path, "sshd_config", "ciphers AES256-CTR,ChaCha20-Poly1305\n")
        ds = parse_file(str(cfg))
        assert ds[0].name == "Ciphers"                 # keyword canonicalised
        assert ds[0].value == "AES256-CTR,ChaCha20-Poly1305"  # value untouched

    def test_comments_and_blank_lines_ignored(self, tmp_path):
        cfg = _write(tmp_path, "sshd_config",
                     "# a comment\n\n   \nPort 22\n# trailing\n")
        ds = parse_file(str(cfg))
        assert len(ds) == 1 and ds[0].name == "Port" and ds[0].value == "22"

    def test_value_with_multiple_spaces(self, tmp_path):
        cfg = _write(tmp_path, "sshd_config", "Banner    /etc/issue.net\n")
        ds = parse_file(str(cfg))
        assert ds[0].name == "Banner" and ds[0].value == "/etc/issue.net"

    def test_include_followed_recursively(self, tmp_path):
        (tmp_path / "sshd_config.d").mkdir()
        _write(tmp_path / "sshd_config.d", "50-hardening.conf",
               "PermitRootLogin no\n")
        cfg = _write(tmp_path, "sshd_config",
                     "Include sshd_config.d/*.conf\nMaxAuthTries 3\n")
        ds = parse_file(str(cfg))
        names = {d.name for d in ds}
        assert "PermitRootLogin" in names   # came from the included fragment
        assert "MaxAuthTries" in names

    def test_match_block_context_recorded_not_global(self, tmp_path):
        cfg = _write(tmp_path, "sshd_config",
                     "PermitRootLogin no\n"
                     "Match User admin\n"
                     "PermitRootLogin yes\n")
        ds = parse_file(str(cfg))
        # Two PermitRootLogin: one global, one inside Match.
        global_ones = [d for d in ds if d.name == "PermitRootLogin" and d.context == "global"]
        match_ones = [d for d in ds if d.name == "PermitRootLogin" and d.context != "global"]
        assert len(global_ones) == 1 and global_ones[0].value == "no"
        assert len(match_ones) == 1
        assert match_ones[0].context.startswith("Match(")
        assert "admin" in match_ones[0].context

    def test_include_inside_match_not_followed(self, tmp_path):
        # An Include appearing after a Match must not be globally expanded.
        _write(tmp_path, "extra.conf", "Port 2222\n")
        cfg = _write(tmp_path, "sshd_config",
                     "Match User bob\nInclude extra.conf\n")
        ds = parse_file(str(cfg))
        # extra.conf must NOT have been pulled in at global scope.
        assert all(d.source_file.endswith("sshd_config") for d in ds)

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_file(str(tmp_path / "nonexistent")) == []

    def test_include_cycle_guarded(self, tmp_path):
        cfg = _write(tmp_path, "sshd_config", "Include sshd_config\nPort 22\n")
        ds = parse_file(str(cfg))  # must not recurse forever
        assert any(d.name == "Port" for d in ds)


class TestProfile:
    def test_no_listenaddress_is_network(self):
        p = infer_profile(_dirs(("Port", "22"), ("PermitRootLogin", "no")))
        assert p.av == "N"
        assert "default" in p.rationale_av.lower()

    def test_only_loopback_is_local(self):
        p = infer_profile(_dirs(("ListenAddress", "127.0.0.1"),
                                ("ListenAddress", "::1")))
        assert p.av == "L"

    def test_loopback_with_port_is_local(self):
        p = infer_profile(_dirs(("ListenAddress", "127.0.0.1:2222"),
                                ("ListenAddress", "[::1]:22")))
        assert p.av == "L"

    def test_mixed_loopback_and_public_is_network(self):
        p = infer_profile(_dirs(("ListenAddress", "127.0.0.1"),
                                ("ListenAddress", "192.168.1.10")))
        assert p.av == "N"

    def test_single_public_is_network(self):
        p = infer_profile(_dirs(("ListenAddress", "0.0.0.0")))
        assert p.av == "N"

    def test_port_without_listenaddress_stays_network(self):
        # Port alone must NOT flip AV to local.
        p = infer_profile(_dirs(("Port", "2222")))
        assert p.av == "N"

    def test_au_always_none_regardless_of_content(self):
        for ds in (
            _dirs(("PermitRootLogin", "yes")),
            _dirs(("PasswordAuthentication", "yes"), ("PubkeyAuthentication", "yes")),
            _dirs(("ListenAddress", "127.0.0.1")),
            [],
        ):
            assert infer_profile(ds).au == "N"


class TestDetection:
    def _plugin(self):
        return SSHPlugin()

    def test_sshd_config_exact_filename(self, tmp_path):
        cfg = _write(tmp_path, "sshd_config", "PermitRootLogin no\n")
        plug = self._plugin()
        assert plug.detect(str(cfg)) is True
        assert plug.detection_confidence(str(cfg)) == CONFIDENCE_EXACT_FILENAME

    def test_content_marker_detected(self, tmp_path):
        # Arbitrary filename, but SSH markers in content.
        cfg = _write(tmp_path, "myhost.conf",
                     "PermitRootLogin no\nKexAlgorithms curve25519-sha256\n")
        plug = self._plugin()
        assert plug.detect(str(cfg)) is True
        assert plug.detection_confidence(str(cfg)) == CONFIDENCE_SYNTAX_MARKER

    def test_fragment_in_sshd_config_d(self, tmp_path):
        d = tmp_path / "sshd_config.d"
        d.mkdir()
        frag = d / "50-hardening.conf"
        frag.write_text("PermitRootLogin no\n", encoding="utf-8")
        assert self._plugin().detect(str(frag)) is True

    def test_apache_file_rejected(self, tmp_path):
        cfg = _write(tmp_path, "httpd.conf",
                     "ServerTokens Full\nLoadModule foo modules/mod_foo.so\n")
        assert self._plugin().detect(str(cfg)) is False

    def test_nginx_file_rejected(self, tmp_path):
        cfg = _write(tmp_path, "nginx.conf",
                     "worker_processes 1;\nserver {\n  listen 80;\n}\n")
        assert self._plugin().detect(str(cfg)) is False

    def test_metadata_fields(self):
        meta = self._plugin().metadata()
        assert meta.name == "ssh"
        assert meta.version_exposing_directives == ("Banner",)
        assert "5.1" in meta.benchmark_source

    def test_parse_config_directory_entry_point(self, tmp_path):
        _write(tmp_path, "sshd_config", "PermitRootLogin no\nMaxAuthTries 3\n")
        ds = self._plugin().parse_config(str(tmp_path))
        assert {d.name for d in ds} == {"PermitRootLogin", "MaxAuthTries"}
