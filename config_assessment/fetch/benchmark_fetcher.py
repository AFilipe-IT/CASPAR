"""
config_assessment/fetch/benchmark_fetcher.py
--------------------------------------------
Automatic discovery and download of security benchmarks for a CASPAR service.

`caspar plugin add --source benchmark.pdf` already installs a plugin from a local
CIS PDF or DISA STIG XCCDF file. This module supplies the *fetch* half: given a
service name (e.g. "nginx"), find the right public benchmark and download it,
producing a file that `plugin add` can consume unchanged.

Investigation (2026-07-01) established the only reliable per-service source is
stigviewer.com, which exposes structured STIG JSON at

    https://www.stigviewer.com/stigs/<slug>/export/json

ComplianceAsCode/content (GitHub) only ships OS-level content (RHEL, Ubuntu, …),
and public.cyber.mil is a JS-rendered SPA with no static links — neither works
for individual services. See config_assessment/fetch/catalog.json for the
service→slug map.

The fetcher converts the JSON to a DISA-style XCCDF 1.1 XML file. That file goes
straight through the existing XCCDF branch of `plugin add`
(config_assessment.build.benchmark_extractor.XCCDFExtractor), so no new parser is
needed. Network access uses only the stdlib (urllib) — no third-party deps, in
keeping with the rest of CASPAR.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape

# XCCDF 1.1 — the namespace XCCDFExtractor defaults to and DISA STIGs use.
_XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"
_STIGVIEWER_EXPORT = "https://www.stigviewer.com/stigs/{slug}/export/json"
_USER_AGENT = "caspar/0.1 (+benchmark-fetch)"
_TIMEOUT = 30


class FetchError(RuntimeError):
    """A benchmark could not be discovered or downloaded."""


class BenchmarkFetcher:
    """Discover and download public benchmarks for CASPAR services.

    Parameters
    ----------
    catalog_path:
        Path to catalog.json. Defaults to the one shipped beside this module.
    """

    def __init__(self, catalog_path: str | Path | None = None) -> None:
        self.catalog_path = Path(catalog_path) if catalog_path else (
            Path(__file__).with_name("catalog.json"))
        self._catalog = self._load_catalog(self.catalog_path)

    # ── public API ────────────────────────────────────────────────────
    def list_available(self) -> list[dict]:
        """Return the catalogued services with their sources, sorted by name."""
        out: list[dict] = []
        for service, entry in sorted(self._catalog.items()):
            out.append({
                "service": service,
                "service_name": entry.get("service_name", service),
                "sources": [
                    {"type": s.get("type"), "title": s.get("title", ""),
                     "format": s.get("format", "")}
                    for s in entry.get("sources", [])
                ],
            })
        return out

    def fetch(self, service: str, dest_dir: str | Path) -> str:
        """Download the benchmark for `service` into `dest_dir`.

        Returns the path to the written file (XCCDF XML). Tries each catalogued
        source in order; raises FetchError if the service is unknown or every
        source fails.
        """
        entry = self._catalog.get(service.lower())
        if entry is None:
            known = ", ".join(sorted(self._catalog)) or "(none)"
            raise FetchError(
                f"Unknown service '{service}'. Available: {known}")

        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        errors: list[str] = []
        for source in entry.get("sources", []):
            stype = source.get("type")
            try:
                if stype == "stigviewer":
                    return self._fetch_stigviewer(source, dest, service.lower())
                if stype == "github_release":
                    return self._fetch_github_release(source, dest)
                if stype == "disa_stig":
                    return self._fetch_disa_stig(source, dest)
                errors.append(f"{stype}: unsupported source type")
            except FetchError as exc:
                errors.append(f"{stype}: {exc}")

        raise FetchError(
            f"All sources failed for '{service}': " + " | ".join(errors))

    # ── source implementations ────────────────────────────────────────
    def _fetch_stigviewer(self, source: dict, dest_dir: Path, service: str) -> str:
        """Download the stigviewer STIG JSON and write it as XCCDF XML.

        `service` is the canonical CASPAR service key; it is prepended to the
        XCCDF <title> so plugin_add's extract_service_name() names the plugin
        after the service (e.g. "nginx") rather than the vendor in the STIG
        title (e.g. "F5 NGINX ..." → "f5").
        """
        slug = source.get("slug")
        if not slug:
            raise FetchError("stigviewer source has no 'slug'")

        url = _STIGVIEWER_EXPORT.format(slug=slug)
        raw = _http_get(url)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise FetchError(f"stigviewer returned non-JSON for '{slug}': {exc}")

        stig = data.get("stig", data)
        groups = stig.get("groups") or []
        if not groups:
            raise FetchError(f"stigviewer STIG '{slug}' has no rules")

        stig_title = stig.get("title") or source.get("title") or slug
        # Lead the title with the canonical service so target_id derivation is
        # correct, but keep the real STIG title for readability/reporting.
        title = (stig_title if stig_title.lower().startswith(service.lower())
                 else f"{service} {stig_title}")
        version = _clean_version_label(stig.get("version") or "")
        xml = _stig_json_to_xccdf(title, version, groups)

        # Name the file so plugin_add's V<n>R<n> regex and service detection fire.
        safe = re.sub(r"[^A-Za-z0-9]+", "_", slug).strip("_")
        vpart = f"_{version}" if version else ""
        out = dest_dir / f"U_{safe}{vpart}_STIG.xml"
        out.write_text(xml, encoding="utf-8")
        return str(out)

    def _fetch_github_release(self, source: dict, dest_dir: Path) -> str:
        """Download a matching asset from a GitHub release.

        Kept for catalog extensibility (e.g. ComplianceAsCode). No CASPAR
        service currently uses it — investigation found only OS-level content
        there — so it is exercised only when a catalog entry opts in.
        """
        repo = source.get("repo")
        pattern = source.get("asset_pattern")
        if not repo or not pattern:
            raise FetchError("github_release source needs 'repo' and 'asset_pattern'")

        tag = source.get("tag", "latest")
        api = (f"https://api.github.com/repos/{repo}/releases/latest"
               if tag == "latest"
               else f"https://api.github.com/repos/{repo}/releases/tags/{tag}")
        rel = json.loads(_http_get(api))
        rx = re.compile(pattern, re.IGNORECASE)
        for asset in rel.get("assets", []):
            if rx.search(asset.get("name", "")):
                blob = _http_get(asset["browser_download_url"], binary=True)
                out = dest_dir / asset["name"]
                out.write_bytes(blob)
                return str(out)
        raise FetchError(
            f"no asset matching /{pattern}/ in {repo}@{tag}")

    def _fetch_disa_stig(self, source: dict, dest_dir: Path) -> str:
        """Download a STIG zip from a direct DoD URL declared in the catalog.

        DISA has no confirmed JSON API and its filenames are unpredictable, so
        this only works when the catalog carries a verified direct 'url'.
        """
        url = source.get("url")
        if not url:
            raise FetchError(
                "disa_stig source needs a verified direct 'url' "
                "(no public DISA API exists)")
        blob = _http_get(url, binary=True)
        out = dest_dir / (source.get("filename") or url.rsplit("/", 1)[-1])
        out.write_bytes(blob)
        return str(out)

    # ── internals ─────────────────────────────────────────────────────
    @staticmethod
    def _load_catalog(path: Path) -> dict:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise FetchError(f"catalog not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise FetchError(f"catalog is not valid JSON: {exc}") from exc
        # Drop documentation keys (leading underscore).
        return {k: v for k, v in data.items() if not k.startswith("_")}


# ── module-level helpers ──────────────────────────────────────────────

def _http_get(url: str, binary: bool = False) -> bytes | str:
    """GET a URL with the stdlib. Returns text (utf-8) or bytes."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ctx) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} for {url}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"network error for {url}: {exc.reason}") from exc
    return body if binary else body.decode("utf-8", "replace")


def _clean_version_label(version: str) -> str:
    """Normalise a stigviewer version like 'V2R2' → 'V2R2' (strip spaces)."""
    m = re.search(r"V\s*(\d+)\s*R\s*(\d+)", version, re.IGNORECASE)
    return f"V{m.group(1)}R{m.group(2)}" if m else re.sub(r"\s+", "", version)


def _stig_json_to_xccdf(title: str, version: str, groups: list[dict]) -> str:
    """Convert stigviewer 'groups' into a minimal XCCDF 1.1 document.

    Emits exactly the elements XCCDFExtractor reads: a top-level <title>, and one
    <Rule severity=...> per group carrying <title>, <fixtext> and a nested
    <check>/<check-content>. Text is XML-escaped; the rest of the STIG metadata
    is intentionally omitted (the extractor does not use it).
    """
    parts: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<Benchmark xmlns="{_XCCDF_NS}" id="CASPAR_fetch">',
        f"  <title>{escape(title)}</title>",
    ]
    if version:
        parts.append(f"  <version>{escape(version)}</version>")

    for g in groups:
        rule_id = g.get("ruleId") or g.get("ruleVersion") or g.get("groupId") or ""
        severity = (g.get("ruleSeverity") or "medium").lower()
        rtitle = g.get("ruleTitle") or g.get("title") or ""
        fixtext = g.get("ruleFixText") or ""
        check = g.get("ruleCheckContent") or ""
        parts.append(
            f'  <Rule id="{escape(rule_id, {chr(34): "&quot;"})}" '
            f'severity="{escape(severity)}">')
        parts.append(f"    <title>{escape(rtitle)}</title>")
        parts.append(f"    <fixtext>{escape(fixtext)}</fixtext>")
        parts.append("    <check system=\"C-STIG\">")
        parts.append(f"      <check-content>{escape(check)}</check-content>")
        parts.append("    </check>")
        parts.append("  </Rule>")

    parts.append("</Benchmark>")
    xml = "\n".join(parts)

    # Fail loudly here rather than deep inside plugin_add if escaping missed a
    # control character; the extractor parses with ElementTree too.
    ET.fromstring(xml)
    return xml
