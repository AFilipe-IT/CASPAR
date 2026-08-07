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
