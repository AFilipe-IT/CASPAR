"""
tests/test_cve_enricher.py
---------------------------
Testes do CVE enrichment, alinhados com a API actual:

  - NVDClient.get_cve(cve_id) — lookup directo por CVE ID (não keyword search)
  - enrich_misconfiguration(directive, bad_value, existing_cves, nvd, kev_ids)
  - _compute_gel(records, kev_ids) — lógica KEV→H, CVSS≥7→M, resto→L

Todos os testes são offline: NVDClient.get_cve é mockado, nunca se toca na
rede real.

Nota importante sobre o comportamento real da função:
  - enrich_misconfiguration marca record.in_kev quando o CVE está em kev_ids
    (faz `record.in_kev = cve_id in kev_ids` durante o lookup).
  - _compute_gel decide KEV→H usando `r.cve_id in kev_ids` (recebe o set).
  - A ordenação dos cve_ids no resultado usa `r.in_kev` (o atributo).
  - grl é sempre "H".
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from core.cve_enricher import (
    CVERecord,
    EnrichmentResult,
    NVDClient,
    VersionExploitInfo,
    _compute_gel,
    enrich_misconfiguration,
    get_version_exploit_info,
    version_amplification,
)


# ════════════════════════════════════════════════════════════════════
# Dataclasses
# ════════════════════════════════════════════════════════════════════

class TestDataclasses:
    def test_cve_record_defaults(self):
        r = CVERecord(cve_id="CVE-2021-1", description="x", cvss_score=7.5, severity="HIGH")
        assert r.in_kev is False
        assert r.published == ""

    def test_enrichment_result_defaults(self):
        e = EnrichmentResult(directive="ServerTokens", bad_value="Full")
        assert e.cve_ids == []
        assert e.cve_records == []
        assert e.gel == "ND"
        assert e.grl == "H"


# ════════════════════════════════════════════════════════════════════
# NVDClient.get_cve — direct lookup, mocked network
# ════════════════════════════════════════════════════════════════════

def _fake_nvd_response(cve_id="CVE-2021-1234", score=7.5, severity="HIGH",
                       metric_key="cvssMetricV31"):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2021-01-15T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "A test vulnerability description."},
                        {"lang": "es", "value": "ignored"},
                    ],
                    "metrics": {
                        metric_key: [
                            {"cvssData": {"baseScore": score, "baseSeverity": severity}}
                        ]
                    },
                }
            }
        ]
    }


class _FakeHTTPResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")
    def read(self):
        return self._payload
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class TestNVDClientGetCVE:
    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_get_cve_returns_record(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(
            _fake_nvd_response("CVE-2021-1234", 7.5, "HIGH")
        )
        rec = NVDClient().get_cve("CVE-2021-1234")
        assert rec is not None
        assert rec.cve_id == "CVE-2021-1234"
        assert rec.cvss_score == 7.5
        assert rec.severity == "HIGH"
        assert "test vulnerability" in rec.description

    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_get_cve_picks_english_description(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(_fake_nvd_response())
        rec = NVDClient().get_cve("CVE-2021-1234")
        assert rec.description != "ignored"
        assert rec.description.startswith("A test")

    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_get_cve_empty_vulns_returns_none(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse({"vulnerabilities": []})
        assert NVDClient().get_cve("CVE-0000-0000") is None

    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_get_cve_falls_back_to_v30(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(
            _fake_nvd_response(score=5.0, severity="MEDIUM", metric_key="cvssMetricV30")
        )
        rec = NVDClient().get_cve("CVE-2021-1234")
        assert rec.cvss_score == 5.0
        assert rec.severity == "MEDIUM"

    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_get_cve_no_metrics_returns_unknown(self, mock_urlopen):
        payload = _fake_nvd_response()
        payload["vulnerabilities"][0]["cve"]["metrics"] = {}
        mock_urlopen.return_value = _FakeHTTPResponse(payload)
        rec = NVDClient().get_cve("CVE-2021-1234")
        assert rec.cvss_score is None
        assert rec.severity == "UNKNOWN"

    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_get_cve_network_error_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = OSError("network down")
        assert NVDClient().get_cve("CVE-2021-1234") is None

    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_api_key_included_in_request(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(_fake_nvd_response())
        NVDClient(api_key="test-key-123").get_cve("CVE-2021-1234")
        called_url = mock_urlopen.call_args[0][0].full_url
        assert "apiKey=test-key-123" in called_url

    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_no_api_key_omits_param(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(_fake_nvd_response())
        NVDClient().get_cve("CVE-2021-1234")
        called_url = mock_urlopen.call_args[0][0].full_url
        assert "apiKey" not in called_url


# ════════════════════════════════════════════════════════════════════
# _compute_gel  (takes the kev_ids SET and checks r.cve_id in kev_ids)
# ════════════════════════════════════════════════════════════════════

class TestComputeGEL:
    def test_no_records_returns_low(self):
        gel, note = _compute_gel([], set())
        assert gel == "L"
        assert "configuration risk" in note.lower()

    def test_kev_match_returns_high(self):
        rec = CVERecord(cve_id="CVE-2021-1", description="x", cvss_score=5.0, severity="MEDIUM")
        gel, note = _compute_gel([rec], {"CVE-2021-1"})
        assert gel == "H"
        assert "KEV" in note

    def test_high_cvss_no_kev_returns_medium(self):
        rec = CVERecord(cve_id="CVE-2021-2", description="x", cvss_score=8.1, severity="HIGH")
        gel, note = _compute_gel([rec], set())
        assert gel == "M"

    def test_low_cvss_returns_low(self):
        rec = CVERecord(cve_id="CVE-2021-3", description="x", cvss_score=3.1, severity="LOW")
        gel, note = _compute_gel([rec], set())
        assert gel == "L"

    def test_kev_takes_priority_over_low_cvss(self):
        rec = CVERecord(cve_id="CVE-2021-4", description="x", cvss_score=2.0, severity="LOW")
        gel, note = _compute_gel([rec], {"CVE-2021-4"})
        assert gel == "H"

    def test_cvss_exactly_7_is_medium(self):
        rec = CVERecord(cve_id="CVE-2021-5", description="x", cvss_score=7.0, severity="HIGH")
        gel, note = _compute_gel([rec], set())
        assert gel == "M"

    def test_none_cvss_score_handled(self):
        rec = CVERecord(cve_id="CVE-2021-6", description="x", cvss_score=None, severity="UNKNOWN")
        gel, note = _compute_gel([rec], set())
        assert gel == "L"


# ════════════════════════════════════════════════════════════════════
# enrich_misconfiguration
# signature: (directive, bad_value, existing_cves, nvd, kev_ids)
# ════════════════════════════════════════════════════════════════════

class TestEnrichMisconfiguration:
    def test_no_cves_sets_gel_low_without_nvd_call(self):
        nvd = MagicMock(spec=NVDClient)
        result = enrich_misconfiguration("AllowOverride", "All", [], nvd, set())
        assert isinstance(result, EnrichmentResult)
        assert result.gel == "L"
        nvd.get_cve.assert_not_called()

    def test_known_cve_triggers_lookup(self):
        nvd = MagicMock(spec=NVDClient)
        nvd.get_cve.return_value = CVERecord(
            cve_id="CVE-2011-3389", description="BEAST", cvss_score=4.3, severity="MEDIUM",
        )
        result = enrich_misconfiguration("SSLProtocol", "All", ["CVE-2011-3389"], nvd, set())
        nvd.get_cve.assert_called_once_with("CVE-2011-3389")
        assert "CVE-2011-3389" in result.cve_ids

    def test_kev_cve_sets_gel_high(self):
        nvd = MagicMock(spec=NVDClient)
        nvd.get_cve.return_value = CVERecord(
            cve_id="CVE-2017-5638", description="Struts", cvss_score=10.0, severity="CRITICAL",
        )
        result = enrich_misconfiguration(
            "SomeDir", "bad", ["CVE-2017-5638"], nvd, {"CVE-2017-5638"},
        )
        assert result.gel == "H"

    def test_high_cvss_no_kev_sets_gel_medium(self):
        nvd = MagicMock(spec=NVDClient)
        nvd.get_cve.return_value = CVERecord(
            cve_id="CVE-2021-9", description="x", cvss_score=8.8, severity="HIGH",
        )
        result = enrich_misconfiguration("Dir", "bad", ["CVE-2021-9"], nvd, set())
        assert result.gel == "M"

    def test_cve_not_found_in_nvd_still_recorded(self):
        nvd = MagicMock(spec=NVDClient)
        nvd.get_cve.return_value = None
        result = enrich_misconfiguration("Dir", "bad", ["CVE-9999-9999"], nvd, set())
        assert "CVE-9999-9999" in result.cve_ids

    def test_cve_not_found_but_in_kev_sets_high(self):
        nvd = MagicMock(spec=NVDClient)
        nvd.get_cve.return_value = None
        result = enrich_misconfiguration(
            "Dir", "bad", ["CVE-9999-9999"], nvd, {"CVE-9999-9999"},
        )
        assert result.gel == "H"

    def test_result_carries_directive_and_value(self):
        nvd = MagicMock(spec=NVDClient)
        result = enrich_misconfiguration("ServerTokens", "Full", [], nvd, set())
        assert result.directive == "ServerTokens"
        assert result.bad_value == "Full"

    def test_grl_is_always_h(self):
        nvd = MagicMock(spec=NVDClient)
        result = enrich_misconfiguration("ServerTokens", "Full", [], nvd, set())
        assert result.grl == "H"

    def test_multiple_cves_all_looked_up(self):
        nvd = MagicMock(spec=NVDClient)
        nvd.get_cve.side_effect = [
            CVERecord(cve_id="CVE-A", description="a", cvss_score=5.0, severity="MEDIUM"),
            CVERecord(cve_id="CVE-B", description="b", cvss_score=6.0, severity="MEDIUM"),
        ]
        result = enrich_misconfiguration("Dir", "bad", ["CVE-A", "CVE-B"], nvd, set())
        assert nvd.get_cve.call_count == 2
        assert "CVE-A" in result.cve_ids
        assert "CVE-B" in result.cve_ids

    def test_kev_cve_ordered_first(self):
        """KEV CVEs should be ordered before non-KEV in the result list."""
        nvd = MagicMock(spec=NVDClient)
        nvd.get_cve.side_effect = [
            CVERecord(cve_id="CVE-LOW", description="low", cvss_score=3.0, severity="LOW"),
            CVERecord(cve_id="CVE-KEV", description="kev", cvss_score=4.0, severity="MEDIUM"),
        ]
        result = enrich_misconfiguration(
            "Dir", "bad", ["CVE-LOW", "CVE-KEV"], nvd, {"CVE-KEV"},
        )
        # KEV one comes first regardless of input order
        assert result.cve_ids[0] == "CVE-KEV"

    def test_cve_ids_capped_at_10(self):
        nvd = MagicMock(spec=NVDClient)
        many = [f"CVE-2021-{i:04d}" for i in range(15)]
        nvd.get_cve.side_effect = [
            CVERecord(cve_id=c, description="x", cvss_score=5.0, severity="MEDIUM")
            for c in many
        ]
        result = enrich_misconfiguration("Dir", "bad", many, nvd, set())
        assert len(result.cve_ids) <= 10


# ════════════════════════════════════════════════════════════════════
# F1 — version exploitability lookup + amplification (mocked network)
# ════════════════════════════════════════════════════════════════════

def _fake_cpe_response(n_cves=0, kev_ids=(), scores=()):
    """Build an NVD CPE-match response with n_cves vulnerabilities."""
    vulns = []
    for idx in range(n_cves):
        cid = f"CVE-2021-{1000 + idx}"
        score = scores[idx] if idx < len(scores) else 5.0
        vulns.append({
            "cve": {
                "id": cid,
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": "MEDIUM"}}]
                },
            }
        })
    return {"vulnerabilities": vulns}


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    """Point the version cache at a temp file so tests never touch the real one."""
    cache_dir = tmp_path / ".ccss_cache"
    monkeypatch.setattr("core.cve_enricher.VERSION_CACHE_DIR", cache_dir)
    monkeypatch.setattr("core.cve_enricher.VERSION_CACHE_FILE", cache_dir / "version_exploits.json")
    return cache_dir / "version_exploits.json"


class TestVersionAmplification:
    """Pure mapping — no I/O."""

    def test_none_returns_one(self):
        assert version_amplification(None) == 1.0

    def test_kev_returns_1_5(self):
        info = VersionExploitInfo("apache-httpd", "2.4.49", cve_count=10, kev_count=2, max_cvss=9.8)
        assert version_amplification(info) == 1.5

    def test_cve_count_5_no_kev_returns_1_3(self):
        info = VersionExploitInfo("apache-httpd", "2.4.51", cve_count=5, kev_count=0)
        assert version_amplification(info) == 1.3

    def test_cve_count_1_returns_1_15(self):
        info = VersionExploitInfo("nginx", "1.27.0", cve_count=1, kev_count=0)
        assert version_amplification(info) == 1.15

    def test_no_cves_returns_one(self):
        info = VersionExploitInfo("nginx", "1.27.4", cve_count=0, kev_count=0)
        assert version_amplification(info) == 1.0


class TestGetCVEsForVersion:
    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_counts_cves_and_max_cvss(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(
            _fake_cpe_response(n_cves=3, scores=(7.5, 9.1, 4.2))
        )
        info = NVDClient().get_cves_for_version("apache-httpd", "2.4.51", kev_ids=set())
        assert info.cve_count == 3
        assert info.max_cvss == 9.1
        assert info.kev_count == 0
        assert info.cached is False

    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_counts_kev(self, mock_urlopen):
        mock_urlopen.return_value = _FakeHTTPResponse(_fake_cpe_response(n_cves=3))
        info = NVDClient().get_cves_for_version(
            "apache-httpd", "2.4.49", kev_ids={"CVE-2021-1001"}
        )
        assert info.kev_count == 1

    def test_unknown_product_no_network(self):
        # Product not in CPE_TEMPLATES → empty info, never hits the network.
        info = NVDClient().get_cves_for_version("mystery-svc", "1.0")
        assert info.cve_count == 0 and info.kev_count == 0


class TestVersionCacheFlow:
    @patch("core.cve_enricher._load_kev", return_value=set())
    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_live_lookup_returns_fresh(self, mock_urlopen, _kev, isolated_cache):
        mock_urlopen.return_value = _FakeHTTPResponse(_fake_cpe_response(n_cves=1))
        info = get_version_exploit_info("apache-httpd", "2.4.49", client=NVDClient())
        assert info.cve_count == 1
        assert info.cached is False

    @patch("core.cve_enricher._load_kev", return_value={"CVE-2021-1000"})
    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_kev_active_amplifies_1_5(self, mock_urlopen, _kev, isolated_cache):
        mock_urlopen.return_value = _FakeHTTPResponse(_fake_cpe_response(n_cves=1))
        info = get_version_exploit_info("apache-httpd", "2.4.49", client=NVDClient())
        assert info.kev_count == 1
        assert version_amplification(info) == 1.5

    @patch("core.cve_enricher._load_kev", return_value=set())
    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_cache_hit_skips_network(self, mock_urlopen, _kev, isolated_cache):
        mock_urlopen.return_value = _FakeHTTPResponse(_fake_cpe_response(n_cves=5))
        # First call populates the cache (1 CPE network call; KEV is mocked).
        get_version_exploit_info("apache-httpd", "2.4.51", client=NVDClient())
        assert mock_urlopen.call_count == 1
        # Second call within TTL must NOT hit the network.
        info2 = get_version_exploit_info("apache-httpd", "2.4.51", client=NVDClient())
        assert mock_urlopen.call_count == 1
        assert info2.cached is True
        assert info2.cve_count == 5

    @patch("core.cve_enricher._load_kev", return_value=set())
    @patch("core.cve_enricher.urllib.request.urlopen")
    def test_expired_ttl_refetches(self, mock_urlopen, _kev, isolated_cache):
        import json as _json, time as _time
        mock_urlopen.return_value = _FakeHTTPResponse(_fake_cpe_response(n_cves=2))
        # Seed an expired cache entry (fetched 25h ago).
        isolated_cache.parent.mkdir(parents=True, exist_ok=True)
        isolated_cache.write_text(_json.dumps({
            "apache-httpd:2.4.51": {
                "cve_count": 99, "kev_count": 0, "max_cvss": 1.0,
                "fetched_at": _time.time() - 25 * 3600,
            }
        }))
        info = get_version_exploit_info("apache-httpd", "2.4.51", client=NVDClient())
        assert mock_urlopen.call_count == 1   # refetched
        assert info.cve_count == 2            # fresh value, not the stale 99
        assert info.cached is False

    def test_no_version_returns_none(self, isolated_cache):
        assert get_version_exploit_info("apache-httpd", None) is None

    def test_unknown_product_returns_none(self, isolated_cache):
        assert get_version_exploit_info("mystery-svc", "1.0") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
