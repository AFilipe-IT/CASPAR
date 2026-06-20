"""
core/cve_enricher.py
---------------------
CVE enrichment via NVD API v2 + CISA KEV.

Estratégia (corrigida):
  A NVD não indexa CVEs por directiva Apache — não existe CVE para
  "ServerTokens=Full". As CVEs Apache são indexadas por versão e tipo
  de vulnerabilidade.

  Por isso a abordagem é:
  1. Para CVEs JÁ CONHECIDOS (identificados pelo LLM): lookup directo
     por CVE ID → obter CVSS score real + verificar KEV.
  2. Para misconfigs SEM CVEs: GEL=L (correcto — são configurações más
     mas sem exploit code automatizado associado).

  Lógica de GEL:
    - Qualquer CVE conhecido na CISA KEV → GEL = High
    - CVE conhecido com CVSS >= 7.0 → GEL = Medium
    - CVEs conhecidos mas todos Low/Medium CVSS → GEL = Low
    - Sem CVEs → GEL = Low

  GRL = H sempre (remediação documentada no CIS Benchmark).

API key em .env:
  NVD_API_KEY=<key>
  Obter em: https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CPE 2.3 templates per target, for version-level CVE lookup (F1). The {version}
# placeholder is substituted with the detected service version. Extensible to
# new targets (SSH, Ubuntu, ...) without touching the lookup logic.
CPE_TEMPLATES: dict[str, str] = {
    "apache-httpd": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
    "nginx":        "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
}

# Persistent cache of version→exploitability lookups (F1, online-first).
VERSION_CACHE_DIR = Path(".ccss_cache")
VERSION_CACHE_FILE = VERSION_CACHE_DIR / "version_exploits.json"
VERSION_CACHE_TTL = 24 * 60 * 60  # seconds

# The CPE/version query (resultsPerPage=2000) is heavy and the NVD is often slow
# to answer it — measured ~24s for a busy product. 20s timed out every time;
# 60s gives the NVD room to respond.
NVD_CPE_TIMEOUT = 60  # seconds


# ------------------------------------------------------------------ #
# .env loader                                                          #
# ------------------------------------------------------------------ #

def load_env(env_path: str | None = None) -> dict[str, str]:
    """Ler variáveis de um ficheiro .env."""
    candidates = []
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path.cwd() / ".env")
    candidates.append(Path(__file__).parent.parent / ".env")

    for p in candidates:
        if p.exists():
            env: dict[str, str] = {}
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    env[key.strip()] = value.strip()
            logger.debug("Loaded .env from %s", p)
            return env
    return {}


def get_nvd_api_key(env_path: str | None = None) -> str:
    """
    Obter NVD API key.
    Precedência: env var NVD_API_KEY > .env file > string vazia.
    """
    key = os.environ.get("NVD_API_KEY", "")
    if key:
        return key
    return load_env(env_path).get("NVD_API_KEY", "")


# ------------------------------------------------------------------ #
# Result types                                                         #
# ------------------------------------------------------------------ #

@dataclass
class CVERecord:
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    in_kev: bool = False
    published: str = ""


@dataclass
class EnrichmentResult:
    directive: str
    bad_value: str
    cve_ids: list[str] = field(default_factory=list)
    cve_records: list[CVERecord] = field(default_factory=list)
    gel: str = "ND"
    grl: str = "H"
    notes: str = ""


@dataclass
class VersionExploitInfo:
    """Exploitability summary for a detected service version (F1).

    cached=True means the data came from the local cache (within TTL) rather
    than a live NVD lookup — surfaced so the dashboard can show provenance.
    """
    product: str
    version: str
    cve_count: int = 0
    kev_count: int = 0
    max_cvss: float = 0.0
    cached: bool = False
    cve_ids: list[str] = field(default_factory=list)  # CVEs affecting this version (for exploit lookup)
    lookup_failed: bool = False  # True when the NVD query errored (timeout etc.) — distinct from "no CVEs"


# ------------------------------------------------------------------ #
# CISA KEV                                                             #
# ------------------------------------------------------------------ #

_KEV_CACHE: set[str] | None = None


def _load_kev(timeout: int = 30) -> set[str]:
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE
    try:
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"User-Agent": "CCSS-Scan/0.1 (security research)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            _KEV_CACHE = {v["cveID"] for v in data.get("vulnerabilities", [])}
            logger.info("CISA KEV loaded: %d entries", len(_KEV_CACHE))
            return _KEV_CACHE
    except Exception as e:
        logger.warning("Could not load CISA KEV: %s", e)
        _KEV_CACHE = set()
        return _KEV_CACHE


# ------------------------------------------------------------------ #
# NVD client — lookup por CVE ID                                       #
# ------------------------------------------------------------------ #

class NVDClient:
    """
    Cliente NVD API v2.
    Faz lookup por CVE ID individual — mais preciso que keyword search.
    """

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key
        # Com API key: 50 req/30s → 0.6s entre requests + 20% margem
        # Sem API key: 5 req/30s → 6s entre requests + 20% margem
        self._delay = 0.72 if api_key else 7.2
        self._last_request = 0.0

    def _wait(self) -> None:
        elapsed = time.monotonic() - self._last_request
        wait = self._delay - elapsed
        if wait > 0:
            time.sleep(wait)

    def get_cve(self, cve_id: str) -> CVERecord | None:
        """
        Obter metadados de um CVE específico por ID.
        Retorna None se não encontrado ou em caso de erro.
        """
        params: dict[str, str] = {"cveId": cve_id}
        if self.api_key:
            params["apiKey"] = self.api_key

        self._wait()
        url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
        logger.debug("NVD lookup: %s", cve_id)

        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "CCSS-Scan/0.1 (security research)"},
            )
            with urllib.request.urlopen(req, timeout=NVD_CPE_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("NVD rate limited (429) — waiting 35s")
                time.sleep(35)
                try:
                    with urllib.request.urlopen(
                        urllib.request.Request(url, headers={"User-Agent": "CCSS-Scan/0.1"}),
                        timeout=NVD_CPE_TIMEOUT,
                    ) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                except Exception as e2:
                    logger.warning("NVD retry failed: %s", e2)
                    return None
            else:
                logger.debug("NVD %d for %s", e.code, cve_id)
                return None
        except Exception as e:
            logger.warning("NVD error for %s: %s", cve_id, e)
            return None
        finally:
            self._last_request = time.monotonic()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve = vulns[0].get("cve", {})
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "",
        )
        score, severity = None, "UNKNOWN"
        for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = cve.get("metrics", {}).get(mk, [])
            if entries:
                d = entries[0].get("cvssData", {})
                score = d.get("baseScore")
                severity = d.get("baseSeverity", "UNKNOWN")
                break

        return CVERecord(
            cve_id=cve_id,
            description=desc[:200],
            cvss_score=score,
            severity=severity,
            published=cve.get("published", "")[:10],
        )

    def get_cves_for_version(
        self, product: str, version: str, kev_ids: set[str] | None = None,
    ) -> VersionExploitInfo:
        """Count CVEs affecting *product* at *version* via NVD CPE match (F1).

        Queries the NVD by CPE (virtualMatchString) — a parallel path to the
        per-CVE-ID get_cve(). Returns a VersionExploitInfo (cached=False, this is
        a live lookup); on any error returns an empty info so scoring degrades to
        amplification ×1.0 rather than failing the scan.
        """
        cpe = CPE_TEMPLATES.get(product)
        if not cpe or not version:
            return VersionExploitInfo(product=product, version=version or "")
        if kev_ids is None:
            kev_ids = _load_kev()

        params: dict[str, str] = {
            "virtualMatchString": cpe.format(version=version),
            "resultsPerPage": "2000",
        }
        if self.api_key:
            params["apiKey"] = self.api_key

        self._wait()
        url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
        logger.debug("NVD CPE lookup: %s @ %s", product, version)

        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "CCSS-Scan/0.1 (security research)"},
            )
            with urllib.request.urlopen(req, timeout=NVD_CPE_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("NVD rate limited (429) — waiting 35s")
                time.sleep(35)
                try:
                    with urllib.request.urlopen(
                        urllib.request.Request(url, headers={"User-Agent": "CCSS-Scan/0.1"}),
                        timeout=NVD_CPE_TIMEOUT,
                    ) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                except Exception as e2:
                    logger.warning("NVD CPE retry failed: %s", e2)
                    return VersionExploitInfo(product=product, version=version, lookup_failed=True)
            else:
                logger.debug("NVD %d for %s @ %s", e.code, product, version)
                return VersionExploitInfo(product=product, version=version, lookup_failed=True)
        except Exception as e:
            logger.warning("NVD CPE error for %s @ %s: %s", product, version, e)
            return VersionExploitInfo(product=product, version=version, lookup_failed=True)
        finally:
            self._last_request = time.monotonic()

        vulns = data.get("vulnerabilities", [])
        cve_count = len(vulns)
        kev_count = 0
        max_cvss = 0.0
        cve_ids: list[str] = []
        for v in vulns:
            cve = v.get("cve", {})
            cid = cve.get("id")
            if cid:
                cve_ids.append(cid)
            if cid in kev_ids:
                kev_count += 1
            for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = cve.get("metrics", {}).get(mk, [])
                if entries:
                    score = entries[0].get("cvssData", {}).get("baseScore")
                    if score is not None:
                        max_cvss = max(max_cvss, float(score))
                    break

        return VersionExploitInfo(
            product=product, version=version,
            cve_count=cve_count, kev_count=kev_count,
            max_cvss=round(max_cvss, 1), cached=False,
            cve_ids=cve_ids,
        )


# ------------------------------------------------------------------ #
# Version exploitability — cache + amplification (F1)                  #
# ------------------------------------------------------------------ #

def _load_version_cache() -> dict:
    try:
        return json.loads(VERSION_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_version_cache(cache: dict) -> None:
    try:
        VERSION_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        VERSION_CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning("Could not write version cache: %s", e)


def get_version_exploit_info(
    product: str,
    version: str | None,
    client: "NVDClient | None" = None,
    use_cache: bool = True,
) -> VersionExploitInfo | None:
    """Resolve version→exploitability, online-first with a 24h persistent cache.

    Returns None when there is nothing to look up (no version, or product not in
    CPE_TEMPLATES) — callers treat None as amplification ×1.0. A fresh NVD lookup
    is persisted; a cache hit within TTL skips the network entirely.
    """
    if not version or product not in CPE_TEMPLATES:
        return None

    key = f"{product}:{version}"
    cache = _load_version_cache()
    entry = cache.get(key)
    if use_cache and entry and (time.time() - entry.get("fetched_at", 0)) < VERSION_CACHE_TTL:
        return VersionExploitInfo(
            product=product, version=version,
            cve_count=entry.get("cve_count", 0),
            kev_count=entry.get("kev_count", 0),
            max_cvss=entry.get("max_cvss", 0.0),
            cached=True,
            cve_ids=entry.get("cve_ids", []),
        )

    client = client or NVDClient(api_key=get_nvd_api_key())
    info = client.get_cves_for_version(product, version, kev_ids=_load_kev())

    # Do not cache inconclusive results — a failed lookup (timeout) OR an empty
    # CVE set. The NVD intermittently returns an empty "vulnerabilities" array
    # for a busy product even on a 200 OK; caching that 0 would pin a false
    # negative for the whole TTL and hide the real CVEs. Only a non-empty,
    # successful result is persisted.
    if not info.lookup_failed and info.cve_count > 0:
        cache[key] = {
            "cve_count": info.cve_count,
            "kev_count": info.kev_count,
            "max_cvss": info.max_cvss,
            "cve_ids": info.cve_ids,
            "fetched_at": time.time(),
        }
        _save_version_cache(cache)
    return info


def version_amplification(info: VersionExploitInfo | None) -> float:
    """Pure mapping exploitability → score amplification factor (F1).

    No I/O. None / unknown version → ×1.0 (graceful no-op).
        kev_count > 0   → ×1.5   (actively exploited version)
        cve_count >= 5  → ×1.3
        cve_count >= 1  → ×1.15
        otherwise       → ×1.0
    """
    if info is None:
        return 1.0
    if info.kev_count > 0:
        return 1.5
    if info.cve_count >= 5:
        return 1.3
    if info.cve_count >= 1:
        return 1.15
    return 1.0


# ------------------------------------------------------------------ #
# GEL logic                                                            #
# ------------------------------------------------------------------ #

def _compute_gel(records: list[CVERecord], kev_ids: set[str]) -> tuple[str, str]:
    """
    Determinar GEL baseado nos CVE records obtidos da NVD.

    Sem CVEs: GEL=L — a misconfiguration é um risco de configuração
    mas não tem exploit code automatizado conhecido.
    """
    if not records:
        return "L", "No CVEs associated — configuration risk without known exploit code."

    kev = [r for r in records if r.cve_id in kev_ids]
    if kev:
        return "H", f"In CISA KEV (actively exploited): {', '.join(r.cve_id for r in kev[:3])}"

    high = [r for r in records if r.cvss_score and r.cvss_score >= 7.0]
    if high:
        return "M", f"{len(high)} High/Critical CVE(s) — top: {high[0].cve_id} CVSS={high[0].cvss_score}"

    return "L", f"{len(records)} CVE(s), all Low/Medium severity."


# ------------------------------------------------------------------ #
# Enrich one misconfiguration                                          #
# ------------------------------------------------------------------ #

def enrich_misconfiguration(
    directive: str,
    bad_value: str,
    existing_cves: list[str],
    nvd: NVDClient,
    kev_ids: set[str],
) -> EnrichmentResult:
    """
    Enriquecer uma misconfiguration.

    Estratégia:
    - Se tem CVEs conhecidos (do LLM): fazer lookup individual na NVD
      para obter CVSS score real e verificar KEV.
    - Se não tem CVEs: GEL=L directamente (sem query NVD desnecessária).
    """
    records: list[CVERecord] = []

    if existing_cves:
        logger.info("  Looking up %d known CVE(s): %s", len(existing_cves), existing_cves)
        for cve_id in existing_cves:
            record = nvd.get_cve(cve_id)
            if record:
                record.in_kev = cve_id in kev_ids
                records.append(record)
                logger.info("  %s: CVSS=%s SEV=%s KEV=%s",
                           cve_id, record.cvss_score, record.severity, record.in_kev)
            else:
                # CVE não encontrado na NVD — incluir como stub
                in_kev = cve_id in kev_ids
                records.append(CVERecord(
                    cve_id=cve_id,
                    description="(CVE details unavailable from NVD)",
                    cvss_score=None,
                    severity="UNKNOWN",
                    in_kev=in_kev,
                ))
                logger.info("  %s: not found in NVD (KEV=%s)", cve_id, in_kev)
    else:
        logger.info("  No known CVEs — GEL=L (configuration risk)")

    gel, notes = _compute_gel(records, kev_ids)

    # Ordenar CVE IDs: KEV first, depois por CVSS
    kev_ids_local = [r.cve_id for r in records if r.in_kev]
    high_ids = [r.cve_id for r in records if not r.in_kev and r.cvss_score and r.cvss_score >= 7.0]
    other_ids = [r.cve_id for r in records if r.cve_id not in kev_ids_local + high_ids]
    final_ids = (kev_ids_local + high_ids + other_ids)[:10]

    return EnrichmentResult(
        directive=directive,
        bad_value=bad_value,
        cve_ids=final_ids,
        cve_records=records,
        gel=gel,
        grl="H",
        notes=notes,
    )


# ------------------------------------------------------------------ #
# Batch enrichment                                                     #
# ------------------------------------------------------------------ #

def enrich_all(
    misconfigs: list,
    api_key: str = "",
    dry_run: bool = False,
) -> dict[tuple[str, str], EnrichmentResult]:
    """
    Enriquecer todas as misconfigurations.

    Só faz chamadas NVD para misconfigs que têm CVEs conhecidos.
    Misconfigs sem CVEs recebem GEL=L directamente (correcto).
    """
    if dry_run:
        logger.info("CVE enrichment dry-run — no NVD calls")
        return {
            (m.directive, m.bad_value): EnrichmentResult(
                directive=m.directive, bad_value=m.bad_value,
                cve_ids=list(getattr(m, "cves", [])),
                gel="ND", grl="H", notes="dry-run",
            )
            for m in misconfigs
        }

    if not api_key:
        api_key = get_nvd_api_key()

    # Contar quantas têm CVEs (só essas precisam de chamadas NVD)
    with_cves = [m for m in misconfigs if getattr(m, "cves", [])]
    without_cves = [m for m in misconfigs if not getattr(m, "cves", [])]

    if api_key:
        nvd = NVDClient(api_key=api_key)
        logger.info("NVD: authenticated — %d CVE lookups needed", len(with_cves))
    else:
        nvd = NVDClient()
        if with_cves:
            est = max(1, len(with_cves) * 8 // 60)
            logger.info("NVD: unauthenticated — %d lookups, estimated %d min", len(with_cves), est)
            logger.info("  Tip: add NVD_API_KEY=<key> to .env")

    # Carregar KEV (mesmo sem CVEs conhecidos, verificamos por precaução)
    kev_ids = _load_kev()

    results: dict[tuple[str, str], EnrichmentResult] = {}

    for idx, m in enumerate(misconfigs, start=1):
        cves = list(getattr(m, "cves", []))
        logger.info("[%d/%d] %s=%s  (%d CVEs)", idx, len(misconfigs), m.directive, m.bad_value, len(cves))
        try:
            result = enrich_misconfiguration(
                directive=m.directive,
                bad_value=m.bad_value,
                existing_cves=cves,
                nvd=nvd,
                kev_ids=kev_ids,
            )
            results[(m.directive, m.bad_value)] = result
            logger.info("  → GEL=%s  CVEs=%d  %s", result.gel, len(result.cve_ids), result.notes[:80])
        except Exception as e:
            logger.error("  Error: %s", e)
            results[(m.directive, m.bad_value)] = EnrichmentResult(
                directive=m.directive, bad_value=m.bad_value,
                cve_ids=cves, gel="ND", grl="H", notes=f"Error: {e}",
            )

    # Summary
    gel_counts = {}
    for r in results.values():
        gel_counts[r.gel] = gel_counts.get(r.gel, 0) + 1
    kev_count = gel_counts.get("H", 0)
    logger.info("Enrichment done: %d enriched, %d KEV (GEL=High), %d no-CVE (GEL=L)",
                len(results), kev_count, len(without_cves))
    return results
