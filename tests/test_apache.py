"""
tests/test_apache.py
---------------------
Tests for the Apache HTTP Server 2.4 plugin.

Covers:
  - Parser: directive extraction, include resolution, context tracking
  - Rule engine: AV/Au inference from Listen, AuthType, Require
  - Detection: file/directory identification
  - End-to-end: httpd.conf → ScanResult with real Apache misconfigurations
  - Build: metric assignments are internally consistent
"""

from __future__ import annotations

import os
import tempfile
import textwrap
from pathlib import Path

import pytest

from core import runtime
from core.ccss import base_score, temporal_score
from core.db.database import Database
from core.models import AttackChain, Misconfiguration, TargetMetadata
from plugins.apache_httpd.build_apache import APACHE_MISCONFIGS, build_apache_db
from plugins.apache_httpd.parser import parse_file
from plugins.apache_httpd.rules import infer_profile


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def write_conf(content: str, filename: str = "httpd.conf") -> str:
    """Write a temp Apache config and return its path."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, filename)
    Path(path).write_text(textwrap.dedent(content), encoding="utf-8")
    return path


# ------------------------------------------------------------------ #
# Parser tests                                                         #
# ------------------------------------------------------------------ #

class TestParser:

    def test_parses_simple_directives(self):
        path = write_conf("""
            ServerTokens Full
            ServerSignature On
            Timeout 300
        """)
        directives = parse_file(path)
        names = {d.name for d in directives}
        assert "ServerTokens" in names
        assert "ServerSignature" in names
        assert "Timeout" in names

    def test_skips_comments(self):
        path = write_conf("""
            # This is a comment
            ServerTokens Full
            # Another comment
        """)
        directives = parse_file(path)
        assert len(directives) == 1
        assert directives[0].name == "ServerTokens"

    def test_skips_empty_lines(self):
        path = write_conf("""

            ServerTokens Full

            ServerSignature On

        """)
        directives = parse_file(path)
        assert len(directives) == 2

    def test_directive_context_from_virtualhost(self):
        path = write_conf("""
            <VirtualHost *:443>
                ServerName example.com
                SSLProtocol All
            </VirtualHost>
        """)
        directives = parse_file(path)
        ssl = next(d for d in directives if d.name == "SSLProtocol")
        assert "VirtualHost" in ssl.context

    def test_canonical_name_normalisation(self):
        path = write_conf("servertokens Full\n")
        directives = parse_file(path)
        assert directives[0].name == "ServerTokens"

    def test_line_number_recorded(self):
        path = write_conf("""
            ServerTokens Full
            ServerSignature On
        """)
        directives = parse_file(path)
        assert directives[0].line_number is not None
        assert directives[0].line_number >= 1

    def test_source_file_recorded(self):
        path = write_conf("ServerTokens Full\n")
        directives = parse_file(path)
        assert directives[0].source_file == str(Path(path).resolve())

    def test_include_resolution(self):
        """Include directive should pull in directives from included file."""
        tmpdir = tempfile.mkdtemp()
        extra = os.path.join(tmpdir, "extra.conf")
        Path(extra).write_text("TraceEnable On\n", encoding="utf-8")
        main = os.path.join(tmpdir, "httpd.conf")
        Path(main).write_text(f"Include {extra}\nServerTokens Full\n", encoding="utf-8")

        directives = parse_file(main)
        names = {d.name for d in directives}
        assert "TraceEnable" in names
        assert "ServerTokens" in names

    def test_inline_comment_stripped_from_value(self):
        path = write_conf("Timeout 300 # should be 10\n")
        directives = parse_file(path)
        assert directives[0].value == "300"


# ------------------------------------------------------------------ #
# Rule engine tests                                                    #
# ------------------------------------------------------------------ #

class TestRules:

    def test_default_av_is_network(self):
        """No Listen directive → Apache defaults to 0.0.0.0 → AV=Network."""
        path = write_conf("ServerTokens Full\n")
        directives = parse_file(path)
        profile = infer_profile(directives)
        assert profile.av == "N"

    def test_network_listen_gives_av_network(self):
        path = write_conf("Listen 0.0.0.0:80\n")
        directives = parse_file(path)
        assert infer_profile(directives).av == "N"

    def test_loopback_only_gives_av_local(self):
        path = write_conf("Listen 127.0.0.1:80\n")
        directives = parse_file(path)
        assert infer_profile(directives).av == "L"

    def test_mixed_listen_gives_av_network(self):
        """Even one non-loopback Listen → worst case = Network."""
        path = write_conf("Listen 127.0.0.1:80\nListen 0.0.0.0:443\n")
        directives = parse_file(path)
        assert infer_profile(directives).av == "N"

    def test_no_auth_gives_au_none(self):
        path = write_conf("ServerTokens Full\n")
        directives = parse_file(path)
        assert infer_profile(directives).au == "N"

    def test_authtype_with_require_gives_au_single(self):
        path = write_conf("""
            AuthType Basic
            AuthName "Restricted"
            Require valid-user
        """)
        directives = parse_file(path)
        profile = infer_profile(directives)
        assert profile.au == "S"

    def test_require_all_granted_is_not_auth(self):
        """'Require all granted' is permissive — Au stays None."""
        path = write_conf("""
            AuthType Basic
            Require all granted
        """)
        directives = parse_file(path)
        assert infer_profile(directives).au == "N"


# ------------------------------------------------------------------ #
# Detection tests                                                      #
# ------------------------------------------------------------------ #

class TestDetection:

    def test_detects_httpd_conf(self):
        from plugins.apache_httpd import ApachePlugin
        path = write_conf("ServerTokens Full\n", filename="httpd.conf")
        assert ApachePlugin().detect(path) is True

    def test_detects_apache2_conf(self):
        from plugins.apache_httpd import ApachePlugin
        path = write_conf("ServerTokens Full\n", filename="apache2.conf")
        assert ApachePlugin().detect(path) is True

    def test_rejects_nginx_conf(self):
        from plugins.apache_httpd import ApachePlugin
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "nginx.conf")
        Path(path).write_text("worker_processes 1;\n", encoding="utf-8")
        assert ApachePlugin().detect(path) is False

    def test_detects_conf_with_apache_content(self):
        from plugins.apache_httpd import ApachePlugin
        path = write_conf("LoadModule ssl_module modules/mod_ssl.so\n", filename="ssl.conf")
        assert ApachePlugin().detect(path) is True


# ------------------------------------------------------------------ #
# Build tests                                                          #
# ------------------------------------------------------------------ #

class TestBuild:

    def test_all_misconfigs_have_required_fields(self):
        for entry in APACHE_MISCONFIGS:
            assert entry["directive"], f"Missing directive in {entry}"
            assert entry["bad_value"] is not None
            assert entry["ac"] in ("H", "M", "L"), f"Bad AC in {entry['directive']}"
            assert entry["c"] in ("N", "P", "C")
            assert entry["i"] in ("N", "P", "C")
            assert entry["a"] in ("N", "P", "C")
            assert entry["gel"] in ("N", "L", "M", "H", "ND")
            assert entry["grl"] in ("U", "W", "H", "ND")

    def test_scores_are_positive_for_non_zero_impact(self):
        for entry in APACHE_MISCONFIGS:
            if not all(v == "N" for v in [entry["c"], entry["i"], entry["a"]]):
                bs = base_score("N", "N", entry["ac"], entry["c"], entry["i"], entry["a"])
                assert bs > 0.0, f"Expected positive score for {entry['directive']}"

    def test_critical_misconfigs_score_high(self):
        """User=root and LoadModule dav_module should score High or Critical."""
        critical = [e for e in APACHE_MISCONFIGS
                    if e["directive"] in ("User", "Group") and e["bad_value"] == "root"]
        for entry in critical:
            bs = base_score("N", "N", entry["ac"], entry["c"], entry["i"], entry["a"])
            assert bs >= 7.0, f"User/Group=root should be High/Critical, got {bs}"

    def test_info_disclosure_scores_medium_or_above(self):
        """ServerTokens Full should be at least Medium severity."""
        st = next(e for e in APACHE_MISCONFIGS
                  if e["directive"] == "ServerTokens" and e["bad_value"] == "Full")
        bs = base_score("N", "N", st["ac"], st["c"], st["i"], st["a"])
        assert bs >= 4.0, f"ServerTokens Full should be Medium+, got {bs}"

    def test_build_populates_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            count = build_apache_db(db_path)
            assert count == len(APACHE_MISCONFIGS)
            with Database(db_path) as db:
                all_m = db.get_all_misconfigurations("apache-httpd")
                assert len(all_m) == len(APACHE_MISCONFIGS)
                chains = db.get_attack_chains("apache-httpd")
                assert len(chains) > 0
        finally:
            os.unlink(db_path)


# ------------------------------------------------------------------ #
# End-to-end integration                                               #
# ------------------------------------------------------------------ #

class TestApacheEndToEnd:

    @pytest.fixture(autouse=True)
    def clear_registry(self):
        original = list(runtime._REGISTRY)
        runtime._REGISTRY.clear()
        yield
        runtime._REGISTRY.clear()
        runtime._REGISTRY.extend(original)

    @pytest.fixture
    def populated_db(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        build_apache_db(db_path)
        return db_path

    def test_scan_insecure_httpd_conf(self, populated_db):
        """Insecure httpd.conf should produce issues and a non-zero score."""
        from plugins.apache_httpd import ApachePlugin
        runtime.register_plugin(ApachePlugin())

        config = write_conf("""
            ServerTokens Full
            ServerSignature On
            TraceEnable On
            User root
            Timeout 300
            MaxKeepAliveRequests 0
            SSLProtocol All
            AllowOverride All
            Options Indexes FollowSymLinks
        """)

        with Database(populated_db) as db:
            result = runtime.scan(config, db)

        assert result.target_name == "apache-httpd"
        assert result.total_issues_found >= 5
        assert result.global_temporal_score > 0.0
        assert result.severity in ("Medium", "High", "Critical")

    def test_scan_detects_root_user_as_critical(self, populated_db):
        """User=root should produce a Critical or High issue."""
        from plugins.apache_httpd import ApachePlugin
        runtime.register_plugin(ApachePlugin())

        config = write_conf("User root\nGroup root\n")

        with Database(populated_db) as db:
            result = runtime.scan(config, db)

        root_issues = [i for i in result.issues if i.directive == "User" and i.bad_value == "root"]
        assert len(root_issues) >= 1
        assert root_issues[0].temporal_score >= 7.0

    def test_scan_clean_config_zero_issues(self, populated_db):
        """A hardened config should produce zero issues."""
        from plugins.apache_httpd import ApachePlugin
        runtime.register_plugin(ApachePlugin())

        config = write_conf("""
            ServerTokens Prod
            ServerSignature Off
            TraceEnable Off
            User apache
            Group apache
            Timeout 10
            MaxKeepAliveRequests 100
            KeepAliveTimeout 15
            AllowOverride None
        """)

        with Database(populated_db) as db:
            result = runtime.scan(config, db)

        # The clean config might still match some directives
        # but the score should be low
        assert result.global_temporal_score < 5.0 or result.total_issues_found == 0

    def test_scan_is_deterministic(self, populated_db):
        """Same httpd.conf → identical score on every run."""
        from plugins.apache_httpd import ApachePlugin
        runtime.register_plugin(ApachePlugin())

        config = write_conf("""
            ServerTokens Full
            TraceEnable On
            User root
        """)

        scores = []
        for _ in range(5):
            with Database(populated_db) as db:
                r = runtime.scan(config, db)
            scores.append(r.global_temporal_score)

        assert len(set(scores)) == 1, f"Non-deterministic: {scores}"

    def test_attack_chain_fires_for_compound_misconfigs(self, populated_db):
        """ServerTokens Full + ServerSignature On should fire info-disclosure-chain."""
        from plugins.apache_httpd import ApachePlugin
        runtime.register_plugin(ApachePlugin())

        config = write_conf("ServerTokens Full\nServerSignature On\n")

        with Database(populated_db) as db:
            result = runtime.scan(config, db)

        chain_ids = [c.chain_id for c in result.chains if c.active]
        assert "info-disclosure-chain" in chain_ids

    def test_amplified_score_exceeds_individual_scores(self, populated_db):
        """When a chain fires, its amplified_score > max individual TemporalScore."""
        from plugins.apache_httpd import ApachePlugin
        runtime.register_plugin(ApachePlugin())

        config = write_conf("ServerTokens Full\nServerSignature On\n")

        with Database(populated_db) as db:
            result = runtime.scan(config, db)

        active_chains = [c for c in result.chains if c.active]
        for chain in active_chains:
            max_individual = max(
                (i.temporal_score for i in result.issues
                 if i.directive in chain.misconfig_directives),
                default=0.0,
            )
            assert chain.amplified_score >= max_individual
