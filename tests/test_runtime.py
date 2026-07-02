"""
tests/test_runtime.py
---------------------
Integration tests: dummy plugin → runtime engine → ScanResult.

This file is the Phase 1 completion criterion test.
A passing test suite here means the core works end-to-end with a
minimal plugin — without touching a single line of the core modules.
"""

import os
import tempfile
from unittest.mock import patch
import pytest

from config_assessment.enrichment.cve_enricher import VersionExploitInfo
from config_assessment.core.db.database import Database
from config_assessment.core.models import (
    AttackChain,
    Directive,
    Misconfiguration,
    ScanResult,
    SystemProfile,
    TargetMetadata,
)
from config_assessment.core import runtime
from config_assessment.core.ccss import base_score, temporal_score


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

@pytest.fixture(autouse=True)
def clear_registry():
    """Ensure the plugin registry is clean before each test."""
    original = list(runtime._REGISTRY)
    runtime._REGISTRY.clear()
    yield
    runtime._REGISTRY.clear()
    runtime._REGISTRY.extend(original)


@pytest.fixture
def db():
    """In-memory database, pre-loaded with dummy target data."""
    database = Database(":memory:")

    # Register target
    meta = TargetMetadata(
        name="dummy",
        display_name="Dummy Test Target",
        version="1.0",
        benchmark_source="CCSS-Scan Phase 1 test fixture",
    )
    database.upsert_target(meta)

    # Add one misconfiguration
    bs = base_score("N", "N", "L", "P", "P", "P")
    ts = temporal_score(bs, "M", "H")
    m = Misconfiguration(
        target_name="dummy",
        directive="DangerousOption",
        bad_value="on",
        good_value="off",
        av="N",
        au="N",
        ac="L",
        c="P",
        i="P",
        a="P",
        base_score=bs,
        temporal_score=ts,
        gel="M",
        grl="H",
        cves=["CVE-2023-00001"],
        cce_id="CCE-TEST-001",
        cis_section="1.1",
        justification="DangerousOption=on exposes the system.",
        recommendation="Set DangerousOption=off in the config.",
    )
    database.upsert_misconfiguration(m)

    # Add one attack chain
    chain = AttackChain(
        chain_id="test-chain",
        target_name="dummy",
        misconfig_directives=["DangerousOption", "Listen"],
        amplification=1.5,
        justification="Combined attack path.",
    )
    database.upsert_attack_chain(chain)

    yield database
    database.close()


@pytest.fixture
def dummy_config_file():
    """Write a temporary .dummy config file and return its path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".dummy", delete=False
    ) as f:
        f.write("# Dummy config\n")
        f.write("Listen=0.0.0.0:80\n")
        f.write("DangerousOption=on\n")
        f.write("LogLevel=warn\n")
        path = f.name
    yield path
    os.unlink(path)


@pytest.fixture
def safe_config_file():
    """Config with no misconfigurations."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".dummy", delete=False
    ) as f:
        f.write("Listen=127.0.0.1:80\n")
        f.write("DangerousOption=off\n")
        f.write("AuthRequired=on\n")
        path = f.name
    yield path
    os.unlink(path)


# ------------------------------------------------------------------ #
# Model tests                                                          #
# ------------------------------------------------------------------ #

class TestModels:

    def test_directive_strips_whitespace(self):
        d = Directive(name="  ServerTokens  ", value="  Full  ")
        assert d.name == "ServerTokens"
        assert d.value == "Full"

    def test_directive_defaults(self):
        d = Directive(name="Test", value="val")
        assert d.context == "global"
        assert d.source_file == ""
        assert d.line_number is None

    def test_system_profile_fields(self):
        sp = SystemProfile(av="N", au="N")
        assert sp.av == "N"
        assert sp.au == "N"

    def test_misconfiguration_defaults(self):
        m = Misconfiguration(
            target_name="test",
            directive="TestDir",
            bad_value="bad",
            ac="L",
            c="P",
            i="P",
            a="P",
        )
        assert m.gel == "ND"
        assert m.grl == "ND"
        assert m.cves == []
        assert m.detected_in_scan is False

    def test_scan_result_has_uuid(self):
        r = ScanResult(
            target_name="test",
            input_path="/tmp/test.conf",
            input_hash="abc123",
            profile=SystemProfile(av="N", au="N"),
        )
        assert len(r.scan_id) == 36  # UUID format

    def test_target_metadata(self):
        meta = TargetMetadata(
            name="apache-httpd",
            display_name="Apache HTTP Server",
            version="2.4",
            benchmark_source="CIS Apache 2.4 v2.3",
        )
        assert meta.priority == 100  # default


# ------------------------------------------------------------------ #
# Plugin registry tests                                                #
# ------------------------------------------------------------------ #

class TestPluginRegistry:

    def test_register_and_retrieve(self):
        from config_assessment.plugins.dummy import DummyPlugin
        plugin = DummyPlugin()
        runtime.register_plugin(plugin)
        assert plugin in runtime.registered_plugins()

    def test_no_matching_plugin_raises(self, db):
        with pytest.raises(RuntimeError, match="No registered plugin"):
            runtime.scan("/tmp/unknown.xyz", db)

    def test_select_plugin_by_extension(self, dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())
        # Should not raise
        result = runtime.scan(dummy_config_file, db)
        assert result.target_name == "dummy"


# ------------------------------------------------------------------ #
# Database tests                                                       #
# ------------------------------------------------------------------ #

class TestDatabase:

    def test_upsert_and_retrieve_misconfiguration(self, db):
        rows = db.get_misconfigurations("dummy", "DangerousOption", "on")
        assert len(rows) == 1
        assert rows[0].directive == "DangerousOption"
        assert rows[0].target_name == "dummy"
        assert "CVE-2023-00001" in rows[0].cves

    def test_no_match_returns_empty_list(self, db):
        rows = db.get_misconfigurations("dummy", "NonExistent", "value")
        assert rows == []

    def test_upsert_idempotent(self, db):
        # Calling upsert twice with same data should not raise and should
        # not duplicate the row
        rows_before = db.get_all_misconfigurations("dummy")
        count_before = len(rows_before)

        bs = base_score("N", "N", "L", "P", "P", "P")
        ts = temporal_score(bs, "M", "H")
        m = Misconfiguration(
            target_name="dummy",
            directive="DangerousOption",
            bad_value="on",
            good_value="off",
            av="N",
            au="N",
            ac="L",
            c="P",
            i="P",
            a="P",
            base_score=bs,
            temporal_score=ts,
            gel="M",
            grl="H",
        )
        db.upsert_misconfiguration(m)
        rows_after = db.get_all_misconfigurations("dummy")
        assert len(rows_after) == count_before

    def test_get_attack_chains(self, db):
        chains = db.get_attack_chains("dummy")
        assert len(chains) == 1
        assert chains[0].chain_id == "test-chain"
        assert chains[0].amplification == 1.5

    def test_save_and_retrieve_scan_result(self, db):
        result = ScanResult(
            target_name="dummy",
            input_path="/tmp/test.dummy",
            input_hash="deadbeef",
            profile=SystemProfile(av="N", au="N"),
            global_base_score=7.5,
            global_temporal_score=7.5,
            severity="High",
        )
        db.save_scan_result(result)
        retrieved = db.get_scan_result(result.scan_id)
        assert retrieved is not None
        assert retrieved.global_temporal_score == 7.5

    def test_scan_history_counts_limit_and_filter(self, db):
        for i, score in enumerate([5.0, 6.0, 7.0]):
            db.save_scan_result(ScanResult(
                target_name="dummy", input_path="/tmp/a.conf",
                input_hash=f"h{i}", profile=SystemProfile(av="N", au="N"),
                global_temporal_score=score, severity="Medium"))
        db.save_scan_result(ScanResult(
            target_name="dummy", input_path="/tmp/other.conf",
            input_hash="z", profile=SystemProfile(av="N", au="N"),
            global_temporal_score=9.0, severity="High"))

        # All scans, and the limit is honoured.
        assert len(db.get_scan_history(limit=10)) == 4
        assert len(db.get_scan_history(limit=2)) == 2
        # Filtering to one input_path returns only its scans.
        only_a = db.get_scan_history(input_path="/tmp/a.conf")
        assert len(only_a) == 3
        assert all(r["input_path"] == "/tmp/a.conf" for r in only_a)
        # Rows carry the fields the CLI renders.
        assert {"timestamp", "input_path", "global_temporal_score",
                "severity"} <= set(only_a[0])


# ------------------------------------------------------------------ #
# End-to-end integration test  (Phase 1 completion criterion)          #
# ------------------------------------------------------------------ #

class TestEndToEnd:
    """
    The Phase 1 completion criterion:
    "A plugin of ~20 lines implements the Target interface and passes
     through the runtime engine from start to finish without modifying
     a single line of the config_assessment.core."
    """

    def test_full_pipeline_with_misconfiguration(self, dummy_config_file, db):
        """input → parse → profile → scan → scoring → chain detection → ScanResult"""
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        result = runtime.scan(dummy_config_file, db)

        # ScanResult is returned
        assert isinstance(result, ScanResult)

        # Target identified correctly
        assert result.target_name == "dummy"

        # At least one issue found (DangerousOption=on)
        assert result.total_issues_found >= 1
        issue = next(i for i in result.issues if i.directive == "DangerousOption")
        assert issue.bad_value == "on"
        assert issue.detected_in_scan is True

        # AV/Au adjusted by profile (Listen present → AV=Network)
        assert result.profile.av == "N"

        # Scores computed
        assert issue.base_score > 0.0
        assert issue.temporal_score > 0.0
        assert result.global_temporal_score > 0.0

        # Severity assigned
        assert result.severity != "None"

        # Chain detected (DangerousOption + Listen both present)
        assert result.total_chains_detected >= 1
        chain = result.chains[0]
        assert chain.active is True
        assert chain.amplified_score > issue.temporal_score

        # Input hash present
        assert len(result.input_hash) == 64

    def test_full_pipeline_clean_config(self, safe_config_file, db):
        """Clean config → zero issues, zero score."""
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        result = runtime.scan(safe_config_file, db)

        assert result.total_issues_found == 0
        assert result.total_chains_detected == 0
        assert result.global_temporal_score == 0.0
        assert result.severity == "None"

    def test_scan_is_deterministic(self, dummy_config_file, db):
        """Same input → identical score every time (zero variance in runtime)."""
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        scores = [
            runtime.scan(dummy_config_file, db).global_temporal_score
            for _ in range(10)
        ]
        assert len(set(scores)) == 1, f"Non-deterministic scores: {scores}"

    def test_hash_differs_for_different_inputs(
        self, dummy_config_file, safe_config_file, db
    ):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        r1 = runtime.scan(dummy_config_file, db)
        r2 = runtime.scan(safe_config_file, db)
        assert r1.input_hash != r2.input_hash


class TestVersionPropagation:
    """F1 Peça 1: detected version flows into the ScanResult."""

    def test_version_propagates_to_scan_result(self, dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        result = runtime.scan(dummy_config_file, db, version="2.4.51")
        assert result.detected_version == "2.4.51"

    def test_version_defaults_to_none(self, dummy_config_file, db):
        """Existing callers that omit version see None — unchanged behaviour."""
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        result = runtime.scan(dummy_config_file, db)
        assert result.detected_version is None

    def test_version_serialised_in_json(self, dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        result = runtime.scan(dummy_config_file, db, version="1.27.0")
        assert '"detected_version": "1.27.0"' in result.model_dump_json()


class TestVersionAmplificationE2E:
    """F1 Peça 3: version-exposing misconfig amplified end-to-end via scan().

    The dummy plugin declares DangerousOption as version-exposing. We mock the
    NVD lookup so no network is touched.
    """

    def _exposing_issue(self, result):
        return next(m for m in result.issues if m.directive == "DangerousOption")

    def _base_temporal(self, dummy_config_file, db):
        """Temporal score with no version (no amplification) — the baseline."""
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())
        result = runtime.scan(dummy_config_file, db)
        return self._exposing_issue(result).temporal_score

    @patch("config_assessment.enrichment.cve_enricher.get_version_exploit_info")
    def test_kev_active_amplifies_temporal(self, mock_info, dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())
        base = self._base_temporal(dummy_config_file, db)

        # KEV active → factor 1.5
        mock_info.return_value = VersionExploitInfo(
            "dummy", "2.4.49", cve_count=8, kev_count=2, max_cvss=9.8
        )
        result = runtime.scan(dummy_config_file, db, version="2.4.49")
        issue = self._exposing_issue(result)

        assert issue.version_amplification == 1.5
        assert issue.temporal_score == min(round(base * 1.5, 1), 10.0)
        assert issue.temporal_score > base

    @patch("config_assessment.enrichment.cve_enricher.get_version_exploit_info")
    def test_no_cves_no_amplification(self, mock_info, dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())
        base = self._base_temporal(dummy_config_file, db)

        mock_info.return_value = VersionExploitInfo("dummy", "2.4.99", cve_count=0)
        result = runtime.scan(dummy_config_file, db, version="2.4.99")
        issue = self._exposing_issue(result)

        assert issue.version_amplification == 1.0
        assert issue.temporal_score == base

    def test_version_none_no_amplification(self, dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())
        base = self._base_temporal(dummy_config_file, db)

        # version=None → enricher never consulted, score unchanged.
        result = runtime.scan(dummy_config_file, db, version=None)
        issue = self._exposing_issue(result)
        assert issue.version_amplification == 1.0
        assert issue.temporal_score == base

    @patch("config_assessment.enrichment.cve_enricher.get_version_exploit_info")
    def test_only_exposing_directive_amplified(self, mock_info, dummy_config_file, db):
        """Other misconfigs must NOT be touched — only DangerousOption."""
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        mock_info.return_value = VersionExploitInfo(
            "dummy", "2.4.49", cve_count=8, kev_count=2
        )
        result = runtime.scan(dummy_config_file, db, version="2.4.49")
        for m in result.issues:
            if m.directive != "DangerousOption":
                assert m.version_amplification == 1.0


class TestVersionExploitsE2E:
    """F1 exploit extension: ScanResult.version_exploits populated via scan()."""

    @patch("config_assessment.enrichment.exploit_enricher.search_exploits_for_cves")
    @patch("config_assessment.enrichment.cve_enricher.get_version_exploit_info")
    def test_exploits_attached_to_result(self, mock_info, mock_exploits,
                                         dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        from config_assessment.enrichment.exploit_enricher import ExploitRecord
        runtime.register_plugin(DummyPlugin())

        mock_info.return_value = VersionExploitInfo(
            "dummy", "2.4.49", cve_count=1, kev_count=0,
            cve_ids=["CVE-2021-41773"],
        )
        mock_exploits.return_value = [
            ExploitRecord(edb_id="50383", title="Apache RCE", verified=True,
                          cve="CVE-2021-41773", path="/x/50383.py"),
        ]
        result = runtime.scan(dummy_config_file, db, version="2.4.49")

        assert len(result.version_exploits) == 1
        assert result.version_exploits[0]["edb_id"] == "50383"
        # searchsploit was called with the CVE ids from the version lookup.
        mock_exploits.assert_called_once_with(["CVE-2021-41773"])

    @patch("config_assessment.enrichment.exploit_enricher.search_exploits_for_cves", return_value=[])
    @patch("config_assessment.enrichment.cve_enricher.get_version_exploit_info")
    def test_no_exploits_empty_list(self, mock_info, _mx, dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())
        mock_info.return_value = VersionExploitInfo(
            "dummy", "2.4.99", cve_count=0, cve_ids=[],
        )
        result = runtime.scan(dummy_config_file, db, version="2.4.99")
        assert result.version_exploits == []

    def test_no_version_no_exploits(self, dummy_config_file, db):
        from config_assessment.plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())
        result = runtime.scan(dummy_config_file, db)  # no version
        assert result.version_exploits == []

    @patch("config_assessment.enrichment.exploit_enricher.search_exploits_for_cves")
    @patch("config_assessment.enrichment.cve_enricher.get_version_exploit_info")
    def test_exploits_listed_even_without_amplification(
        self, mock_info, mock_exploits, dummy_config_file, db
    ):
        """Public exploits are shown even when there is no KEV/CVE amplification."""
        from config_assessment.plugins.dummy import DummyPlugin
        from config_assessment.enrichment.exploit_enricher import ExploitRecord
        runtime.register_plugin(DummyPlugin())

        # cve_count=0 → version_amplification == 1.0 (no score change) ...
        mock_info.return_value = VersionExploitInfo(
            "dummy", "2.4.49", cve_count=0, kev_count=0, cve_ids=["CVE-2021-41773"],
        )
        # ... but an exploit still exists for that CVE.
        mock_exploits.return_value = [
            ExploitRecord(edb_id="50383", title="Apache RCE", cve="CVE-2021-41773"),
        ]
        result = runtime.scan(dummy_config_file, db, version="2.4.49")

        issue = next(m for m in result.issues if m.directive == "DangerousOption")
        assert issue.version_amplification == 1.0       # no amplification
        assert len(result.version_exploits) == 1        # but exploit listed
