"""
tests/test_scan_cmds.py
-------------------------
`caspar scan --host <label>` — tags a scan as belonging to an Operating
System instance (host_id FK on scan_results). Untagged scans get no host.

Uses the ubuntu plugin's deterministic curated build (same pattern as
test_ubuntu_plugin.py) rather than the dummy plugin, since `caspar scan`
runs real plugin discovery and a fixture with no DB-side misconfigurations
would still need a registered target either way.
"""

from __future__ import annotations

from click.testing import CliRunner

import cli.main as m  # noqa: F401 — discovers/registers plugins like the CLI
from config_assessment.core.db.database import Database
from config_assessment.plugins.ubuntu.build_ubuntu import run_build

m._discover_plugins()

_SYSCTL_BAD = """\
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.tcp_syncookies = 0
kernel.randomize_va_space = 0
"""


def _seed(tmp_path):
    db = tmp_path / "kb.db"
    out = run_build(str(db))
    assert out["misconfigs"] >= 15
    return db


class TestScanHostTagging:
    def test_scan_with_host_persists_host_id(self, tmp_path):
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)

        res = CliRunner().invoke(
            m.cli, ["--db", str(db_path), "scan", str(f), "--host", "web01"],
        )
        assert res.exit_code == 0, res.output

        with Database(str(db_path)) as db:
            host_id = db.get_host_id("web01")
            assert host_id is not None
            scans = db.get_scans_for_host(host_id)
            assert len(scans) == 1

    def test_scan_without_host_registers_no_host(self, tmp_path):
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)

        res = CliRunner().invoke(m.cli, ["--db", str(db_path), "scan", str(f)])
        assert res.exit_code == 0, res.output

        with Database(str(db_path)) as db:
            assert db.list_hosts() == []

    def test_repeated_host_label_reuses_same_host(self, tmp_path):
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)

        CliRunner().invoke(m.cli, ["--db", str(db_path), "scan", str(f), "--host", "web01"])
        CliRunner().invoke(m.cli, ["--db", str(db_path), "scan", str(f), "--host", "web01"])

        with Database(str(db_path)) as db:
            assert len(db.list_hosts()) == 1
            host_id = db.get_host_id("web01")
            assert len(db.get_scans_for_host(host_id)) == 2


class TestScanOutputVerbosity:
    """Default `scan` is an operational summary; detail is opt-in.

    The default output kept growing until a real service configuration pushed
    the score and the recommendation off the top of the screen, so the per-
    finding and per-chain sections now sit behind flags.
    """

    def _scan(self, tmp_path, *extra):
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)
        res = CliRunner().invoke(
            m.cli, ["--db", str(db_path), "scan", str(f), *extra])
        assert res.exit_code == 0, res.output
        return res.output

    def test_default_output_omits_detail_sections(self, tmp_path):
        out = self._scan(tmp_path)
        assert "ALL FINDINGS" not in out
        assert "ATTACK CHAINS (detail)" not in out
        # …but the summary the operator came for is still there.
        assert "CONFIGURATION VULNERABILITY SCORE" in out
        assert "RECOMMENDATION" in out
        assert "COVERAGE" in out

    def test_default_output_advertises_the_flags_it_hid(self, tmp_path):
        out = self._scan(tmp_path)
        assert "--verbose" in out and "--show-uncovered" in out

    def test_verbose_restores_per_finding_detail(self, tmp_path):
        out = self._scan(tmp_path, "--verbose")
        assert "ALL FINDINGS" in out
        # Having shown everything, it must not then advertise --verbose.
        assert "# every finding in full detail" not in out

    def test_show_chains_adds_chains_without_per_finding_detail(self, tmp_path):
        out = self._scan(tmp_path, "--show-chains")
        assert "ALL FINDINGS" not in out


class TestChainsAreReportedButNotScored:
    """Chains inform; they do not move the number.

    The scan output must still make the composition visible — that is the
    CVM's contribution — while the headline score stays traceable to one
    fixable directive.
    """

    def test_output_states_that_chains_are_not_scored(self, tmp_path):
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)
        res = CliRunner().invoke(m.cli, ["--db", str(db_path), "scan", str(f)])
        assert res.exit_code == 0, res.output
        assert "chains not scored" in res.output

    # The score-vs-chain assertion itself lives in test_apache.py, next to the
    # fixture that actually fires chains (sysctl fires none).


class TestAbout:
    # A box-drawing run alone is not enough to identify the wordmark — the
    # score meter is drawn with the same block character.
    WORDMARK_GLYPH = "╚██████╗"

    def test_about_carries_the_wordmark_and_version(self):
        res = CliRunner().invoke(m.cli, ["about"])
        assert res.exit_code == 0, res.output
        assert self.WORDMARK_GLYPH in res.output
        assert "Configuration Vulnerability Meter" in res.output

    def test_scan_does_not_print_the_wordmark(self, tmp_path):
        """The logo belongs to `about`; `scan` is run many times a day."""
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)
        res = CliRunner().invoke(m.cli, ["--db", str(db_path), "scan", str(f)])
        assert self.WORDMARK_GLYPH not in res.output


class TestReportOutputDirErrors:
    """An unwritable -o reports an error, never a traceback.

    The assessment has already run and printed its result by the time the
    report directory is created, so a raw OSError buries a completed scan
    under a stack trace. This was reached in practice through the Docker
    wrapper, which mounted the working directory read-only.
    """

    def test_unwritable_output_dir_is_a_clean_error(self, tmp_path):
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)

        ro = tmp_path / "ro"
        ro.mkdir()
        ro.chmod(0o500)  # r-x: cannot create children
        try:
            res = CliRunner().invoke(
                m.cli,
                ["--db", str(db_path), "scan", str(f),
                 "--report", "-f", "json", "-o", str(ro / "out")],
            )
            assert res.exit_code != 0
            assert res.exception is None or isinstance(res.exception, SystemExit)
            assert "cannot create report directory" in res.output
            assert "Traceback" not in res.output
        finally:
            ro.chmod(0o700)  # so tmp_path cleanup can remove it

    def test_container_path_outside_the_mounts_is_flagged(self, tmp_path, monkeypatch):
        """Writing outside the bound dirs succeeds, then vanishes with --rm."""
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)

        # Stand in for the image: CASPAR_REPORTS_DIR is set only there.
        reports = tmp_path / "reports"
        monkeypatch.setenv("CASPAR_REPORTS_DIR", str(reports))
        stray = tmp_path / "stray"

        res = CliRunner().invoke(
            m.cli,
            ["--db", str(db_path), "scan", str(f),
             "--report", "-f", "json", "-o", str(stray)],
        )
        assert res.exit_code == 0, res.output
        assert "is inside the container" in res.output
        assert list(stray.glob("*.json")), "report should still be written"

    def test_no_container_warning_on_a_native_install(self, tmp_path, monkeypatch):
        """Without CASPAR_REPORTS_DIR there is no container to warn about."""
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)
        monkeypatch.delenv("CASPAR_REPORTS_DIR", raising=False)

        res = CliRunner().invoke(
            m.cli,
            ["--db", str(db_path), "scan", str(f),
             "--report", "-f", "json", "-o", str(tmp_path / "out")],
        )
        assert res.exit_code == 0, res.output
        assert "is inside the container" not in res.output

    def test_writable_output_dir_still_works(self, tmp_path):
        db_path = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)

        out = tmp_path / "nested" / "reports"
        res = CliRunner().invoke(
            m.cli,
            ["--db", str(db_path), "scan", str(f),
             "--report", "-f", "json", "-o", str(out)],
        )
        assert res.exit_code == 0, res.output
        assert list(out.glob("*.json")), "report was not written"
