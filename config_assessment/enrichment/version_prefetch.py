"""
core/version_prefetch.py
-------------------------
Build-time pre-fetch of version exploitability (F1).

For each curated version of a target, this queries the NVD once (for the CVEs
affecting that version) and Exploit-DB (for public exploits of those CVEs), then
stores the resolved result in the `version_exploits` table. The runtime then
reads it locally — no network, no searchsploit — keeping the scan path offline
and deterministic.

This is the "few requests, stored locally" path: the heavy/unreliable NVD work
happens here, once, instead of on every scan.
"""

from __future__ import annotations

import logging

from config_assessment.enrichment.cve_enricher import NVDClient, get_nvd_api_key, _load_kev
from config_assessment.enrichment.exploit_enricher import search_exploits_for_cves

logger = logging.getLogger(__name__)


def fetch_version(
    db,
    product: str,
    version: str,
    client: "NVDClient | None" = None,
    kev_ids: set | None = None,
) -> dict:
    """Fetch and store exploitability for one (product, version).

    Returns a status dict: {version, cve_count, exploit_count, ok}. ok=False when
    the NVD lookup failed (nothing is stored, so it can be retried later).
    """
    client = client or NVDClient(api_key=get_nvd_api_key())
    if kev_ids is None:
        kev_ids = _load_kev()

    info = client.get_cves_for_version(product, version, kev_ids=kev_ids)
    if info.lookup_failed:
        logger.warning("NVD lookup failed for %s %s — not stored", product, version)
        return {"version": version, "cve_count": 0, "exploit_count": 0,
                "ok": False, "empty": False}

    # The NVD intermittently returns an empty array on a 200 OK for a busy
    # product (or the CPE is wrong). Treat 0 CVEs as inconclusive and do not
    # store it — same rule as the JSON cache — so a false negative is not pinned.
    if info.cve_count == 0:
        logger.warning("NVD returned 0 CVEs for %s %s — inconclusive, not stored",
                       product, version)
        return {"version": version, "cve_count": 0, "exploit_count": 0,
                "ok": False, "empty": True}

    exploits = search_exploits_for_cves(info.cve_ids) if info.cve_ids else []
    exploit_dicts = [vars(e) for e in exploits]

    db.upsert_version_exploits(
        product, version,
        cve_count=info.cve_count,
        kev_count=info.kev_count,
        max_cvss=info.max_cvss,
        cve_ids=info.cve_ids,
        exploits=exploit_dicts,
    )
    logger.info(
        "Stored %s %s: %d CVEs, %d public exploits",
        product, version, info.cve_count, len(exploit_dicts),
    )
    return {
        "version": version,
        "cve_count": info.cve_count,
        "exploit_count": len(exploit_dicts),
        "ok": True,
    }


def fetch_versions(
    db,
    product: str,
    versions: list[str],
    client: "NVDClient | None" = None,
) -> list[dict]:
    """Fetch exploitability for several versions of a product.

    Shares one NVDClient (and one KEV load) across all versions so the rate
    limiter is respected. Failed versions are reported but not stored.
    """
    client = client or NVDClient(api_key=get_nvd_api_key())
    kev_ids = _load_kev()
    results = []
    for version in versions:
        results.append(fetch_version(db, product, version, client=client, kev_ids=kev_ids))
    return results
