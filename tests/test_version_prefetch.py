"""
tests/test_version_prefetch.py
-------------------------------
F1 pre-fetch: fetch_version stores NVD CVEs + Exploit-DB exploits in the local
DB. Both NVD and searchsploit are mocked — no network, no subprocess.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.db.database import Database
from core.cve_enricher import VersionExploitInfo
from core.exploit_enricher import ExploitRecord
from core import version_prefetch


@pytest.fixture
def db():
    database = Database(":memory:")
    yield database
    database.close()


class _StubClient:
    """Stub NVDClient returning a fixed VersionExploitInfo."""
    def __init__(self, info):
        self._info = info
    def get_cves_for_version(self, product, version, kev_ids=None):
        return self._info


def test_fetch_stores_cves_and_exploits(db):
    info = VersionExploitInfo(
        "apache-httpd", "2.4.49", cve_count=2, kev_count=1, max_cvss=9.8,
        cve_ids=["CVE-2021-41773", "CVE-2021-42013"],
    )
    exploits = [ExploitRecord(edb_id="50383", title="RCE", verified=True,
                              cve="CVE-2021-41773", path="/x.py")]
    with patch("core.version_prefetch.search_exploits_for_cves", return_value=exploits), \
         patch("core.version_prefetch._load_kev", return_value=set()):
        r = version_prefetch.fetch_version(db, "apache-httpd", "2.4.49",
                                           client=_StubClient(info))
    assert r["ok"] and r["cve_count"] == 2 and r["exploit_count"] == 1

    stored = db.get_version_exploits("apache-httpd", "2.4.49")
    assert stored["cve_count"] == 2
    assert stored["cve_ids"] == ["CVE-2021-41773", "CVE-2021-42013"]
    assert stored["exploits"][0]["edb_id"] == "50383"


def test_clean_version_stored_with_no_exploits(db):
    info = VersionExploitInfo("apache-httpd", "2.4.58", cve_count=48, kev_count=0,
                              cve_ids=["CVE-2023-25690"])
    with patch("core.version_prefetch.search_exploits_for_cves", return_value=[]), \
         patch("core.version_prefetch._load_kev", return_value=set()):
        r = version_prefetch.fetch_version(db, "apache-httpd", "2.4.58",
                                           client=_StubClient(info))
    assert r["ok"] and r["cve_count"] == 48 and r["exploit_count"] == 0
    stored = db.get_version_exploits("apache-httpd", "2.4.58")
    assert stored["cve_count"] == 48 and stored["exploits"] == []


def test_failed_lookup_not_stored(db):
    info = VersionExploitInfo("apache-httpd", "2.4.49", lookup_failed=True)
    with patch("core.version_prefetch.search_exploits_for_cves", return_value=[]), \
         patch("core.version_prefetch._load_kev", return_value=set()):
        r = version_prefetch.fetch_version(db, "apache-httpd", "2.4.49",
                                           client=_StubClient(info))
    assert r["ok"] is False
    assert db.get_version_exploits("apache-httpd", "2.4.49") is None  # nothing stored


def test_fetch_versions_multiple(db):
    infos = {
        "2.4.49": VersionExploitInfo("apache-httpd", "2.4.49", cve_count=2,
                                     cve_ids=["CVE-2021-41773"]),
        "2.4.58": VersionExploitInfo("apache-httpd", "2.4.58", cve_count=48,
                                     cve_ids=["CVE-2023-25690"]),
    }

    class _MultiStub:
        def get_cves_for_version(self, product, version, kev_ids=None):
            return infos[version]

    with patch("core.version_prefetch.search_exploits_for_cves", return_value=[]), \
         patch("core.version_prefetch._load_kev", return_value=set()):
        results = version_prefetch.fetch_versions(
            db, "apache-httpd", ["2.4.49", "2.4.58"], client=_MultiStub())
    assert len(results) == 2
    assert db.get_version_exploits("apache-httpd", "2.4.49") is not None
    assert db.get_version_exploits("apache-httpd", "2.4.58") is not None
