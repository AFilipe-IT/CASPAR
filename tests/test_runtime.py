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
import pytest

from core.db.database import Database
from core.models import (
    AttackChain,
    Directive,
    Misconfiguration,
    ScanResult,
    SystemProfile,
    TargetMetadata,
)
from core import runtime
from core.ccss import base_score, temporal_score


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
        from plugins.dummy import DummyPlugin
        plugin = DummyPlugin()
        runtime.register_plugin(plugin)
        assert plugin in runtime.registered_plugins()

    def test_no_matching_plugin_raises(self, db):
        with pytest.raises(RuntimeError, match="No registered plugin"):
            runtime.scan("/tmp/unknown.xyz", db)

    def test_select_plugin_by_extension(self, dummy_config_file, db):
        from plugins.dummy import DummyPlugin
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


# ------------------------------------------------------------------ #
# End-to-end integration test  (Phase 1 completion criterion)          #
# ------------------------------------------------------------------ #

class TestEndToEnd:
    """
    The Phase 1 completion criterion:
    "A plugin of ~20 lines implements the Target interface and passes
     through the runtime engine from start to finish without modifying
     a single line of the core."
    """

    def test_full_pipeline_with_misconfiguration(self, dummy_config_file, db):
        """input → parse → profile → scan → scoring → chain detection → ScanResult"""
        from plugins.dummy import DummyPlugin
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
        from plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        result = runtime.scan(safe_config_file, db)

        assert result.total_issues_found == 0
        assert result.total_chains_detected == 0
        assert result.global_temporal_score == 0.0
        assert result.severity == "None"

    def test_scan_is_deterministic(self, dummy_config_file, db):
        """Same input → identical score every time (zero variance in runtime)."""
        from plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        scores = [
            runtime.scan(dummy_config_file, db).global_temporal_score
            for _ in range(10)
        ]
        assert len(set(scores)) == 1, f"Non-deterministic scores: {scores}"

    def test_hash_differs_for_different_inputs(
        self, dummy_config_file, safe_config_file, db
    ):
        from plugins.dummy import DummyPlugin
        runtime.register_plugin(DummyPlugin())

        r1 = runtime.scan(dummy_config_file, db)
        r2 = runtime.scan(safe_config_file, db)
        assert r1.input_hash != r2.input_hash
