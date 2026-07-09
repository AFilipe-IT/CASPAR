"""
tests/test_ubuntu_plugin.py
---------------------------
Ubuntu OS-hardening plugin (config-based subset of CIS Ubuntu 22.04 L1):
detection of sysctl.conf / login.defs, deterministic curated build, and
end-to-end scans of insecure fixtures. Offline, no LLM.
"""

from __future__ import annotations

import cli.main as m  # noqa: F401 — discovers/registers plugins like the CLI
from config_assessment.core import runtime
from config_assessment.core.db.database import Database
from config_assessment.plugins.ubuntu.build_ubuntu import run_build

m._discover_plugins()

_SYSCTL_BAD = """\
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.tcp_syncookies = 0
kernel.randomize_va_space = 0
"""

_LOGINDEFS_BAD = """\
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
ENCRYPT_METHOD  MD5
"""


def _seed(tmp_path):
    db = tmp_path / "kb.db"
    out = run_build(str(db))
    assert out["misconfigs"] >= 15
    return db


class TestDetection:

    def test_sysctl_conf_routes_to_ubuntu(self, tmp_path):
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)
        assert runtime._select_plugin(str(f)).metadata().name == "ubuntu"

    def test_login_defs_routes_to_ubuntu(self, tmp_path):
        f = tmp_path / "login.defs"
        f.write_text(_LOGINDEFS_BAD)
        assert runtime._select_plugin(str(f)).metadata().name == "ubuntu"

    def test_sysctl_d_fragment_detected(self, tmp_path):
        d = tmp_path / "sysctl.d"
        d.mkdir()
        f = d / "99-hardening.conf"
        f.write_text("net.ipv4.ip_forward = 1\n")
        from config_assessment.plugins.ubuntu import UbuntuPlugin
        assert UbuntuPlugin().detect(str(f))

    def test_unrelated_conf_not_claimed(self, tmp_path):
        f = tmp_path / "nginx.conf"
        f.write_text("worker_processes 4;\n")
        from config_assessment.plugins.ubuntu import UbuntuPlugin
        assert not UbuntuPlugin().detect(str(f))


class TestBuild:

    def test_build_deterministic_idempotent(self, tmp_path):
        db = tmp_path / "kb.db"
        n1 = run_build(str(db))["misconfigs"]
        n2 = run_build(str(db))["misconfigs"]          # re-run: upsert
        assert n1 == n2
        with Database(str(db)) as d:
            assert len(d.get_all_misconfigurations("ubuntu")) == n1


class TestScan:

    def test_sysctl_misconfigs_detected(self, tmp_path):
        db = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text(_SYSCTL_BAD)
        with Database(str(db)) as d:
            result = runtime.scan(str(f), d)
        found = {i.directive for i in result.issues}
        assert {"net.ipv4.conf.all.accept_redirects",
                "net.ipv4.conf.all.rp_filter",
                "net.ipv4.tcp_syncookies",
                "kernel.randomize_va_space"} <= found

    def test_login_defs_misconfigs_detected(self, tmp_path):
        db = _seed(tmp_path)
        f = tmp_path / "login.defs"
        f.write_text(_LOGINDEFS_BAD)
        with Database(str(db)) as d:
            result = runtime.scan(str(f), d)
        found = {i.directive for i in result.issues}
        # parser lowercases keys (canonical key_value form)
        assert {"pass_max_days", "encrypt_method"} <= found

    def test_secure_sysctl_is_clean(self, tmp_path):
        """A hardened sysctl.conf (CIS values) must produce no issues."""
        db = _seed(tmp_path)
        f = tmp_path / "sysctl.conf"
        f.write_text("net.ipv4.conf.all.accept_redirects = 0\n"
                     "net.ipv4.tcp_syncookies = 1\n"
                     "kernel.randomize_va_space = 2\n")
        with Database(str(db)) as d:
            result = runtime.scan(str(f), d)
        assert not result.issues
