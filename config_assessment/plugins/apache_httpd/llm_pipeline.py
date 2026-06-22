"""
plugins/apache_httpd/llm_pipeline.py
--------------------------------------
LLM pipeline para atribuição de métricas CCSS ao CIS Apache Benchmark.

Substitui as métricas hard-coded de build_apache.py por métricas geradas
pelo LLM com base no texto real do CIS Benchmark (RAG).

Fluxo por misconfiguration:
  1. RAG: recuperar secções CIS relevantes para a directiva
  2. LLM: dada a secção, atribuir AC/C/I/A + justificação em JSON
  3. Validação: verificar que o JSON é válido e os valores são legais
  4. Fallback: se o LLM falhar 3x, usar regras conservadoras (AC=L, C=P, I=N, A=N)
  5. Persist: escrever no banco via database.py

Prompt design:
  - System prompt: especialista CCSS, output apenas JSON, sem texto extra
  - User prompt: secção CIS completa (description + rationale + remediation)
    + definições CCSS das métricas + exemplos few-shot
  - Temperature: 0.1 (baixa, para JSON consistente)
  - Modelo recomendado: qwen2.5:14b (melhor raciocínio estruturado local)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

from config_assessment.core.ccss import base_score, temporal_score
from config_assessment.build.llm_client import LLMClient, make_client
from config_assessment.core.models import ACValue, CIAValue, GELValue, GRLValue, Misconfiguration
from config_assessment.build.rag import BenchmarkIndex, Section

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Output schema esperado do LLM                                        #
# ------------------------------------------------------------------ #

@dataclass
class LLMMetrics:
    ac: ACValue
    c: CIAValue
    i: CIAValue
    a: CIAValue
    gel: GELValue
    grl: GRLValue
    justification: str
    recommendation: str
    cve_ids: list[str]

    # Confidence score (0.0-1.0) — preenchido pelo validador, não pelo LLM
    confidence: float = 1.0


# ------------------------------------------------------------------ #
# System prompt (fixo, carregado uma vez)                              #
# ------------------------------------------------------------------ #

_SYSTEM_PROMPT = """\
You are a security configuration expert specialising in CCSS (Common Configuration Scoring System, NISTIR 7502).

Your task: given a CIS Benchmark recommendation for Apache HTTP Server 2.4, assign CCSS metrics for the MISCONFIGURED state (i.e. when the recommendation is NOT followed).

CCSS metrics you must assign:

AC (Access Complexity): How difficult is it to exploit this misconfiguration?
  H = High   - requires specialised conditions, insider access, or precise timing
  M = Medium - requires specific preconditions BEYOND just sending HTTP requests:
               write access to webroot/filesystem, local file access, or a specific
               network position (e.g. MITM between client and server).
  L = Low    - any remote unauthenticated attacker can trigger this with a single
               standard HTTP request. No preconditions needed.

  CRITICAL: use M (not L) when exploitation requires ANY of:
    - Write access to filesystem or web root (FollowSymLinks, AllowOverride)
    - Network position between client and server (TLS downgrade attacks)
    - Local access or prior authentication
    - A chain of multiple prerequisite steps
  Use L only for: version disclosure, dangerous HTTP methods, DoS via connections,
  missing headers — things ANY remote attacker can exploit immediately.

C (Confidentiality Impact): What information could be disclosed?
  N = None    - no information disclosure
  P = Partial - SOME information leaked (version numbers, config snippets, directory
                listings, partial file content). This is correct for most web server
                misconfigs. Default to P unless you have strong reason for C.
  C = Complete - attacker reads ALL system data without further exploitation needed.
                Only use when the misconfiguration DIRECTLY exposes the full filesystem.

I (Integrity Impact): Can data or configuration be modified?
  N = None    - no modification possible
  P = Partial - limited scope: files within web root, specific config sections.
                Use P for .htaccess overrides, partial write access.
  C = Complete - arbitrary write to ANY system file. Only when misconfiguration
                DIRECTLY allows writing outside webroot or executing code as root.

A (Availability Impact): Can the service be disrupted?
  N = None    - no availability impact
  P = Partial - degraded performance, slow responses, gradual resource exhaustion.
                Use P for connection limit issues, slow-loris style attacks.
  C = Complete - immediate total service shutdown. Only if the misconfiguration
                allows instantly crashing the process or exhausting all resources.

GEL (General Exploit Level): How often is this actively exploited in the wild?
  N  = None   - no known exploitation
  L  = Low    - rarely exploited, months between incidents
  M  = Medium - occasionally exploited, days to weeks between incidents
  H  = High   - frequently exploited (active CVE in CISA KEV)
  ND = Not Defined

GRL (General Remediation Level): How well-documented is the fix?
  U  = Unavailable - no official fix
  W  = Workaround  - workaround exists
  H  = High        - official CIS Benchmark remediation documented
  ND = Not Defined

DISA STIG CALIBRATION - use this to anchor your scores:
  CAT I  (Critical) = CCSS 7.0-10.0: direct RCE, root compromise, full system access
  CAT II (Medium)   = CCSS 4.0-6.9:  information disclosure, partial access, gradual DoS
  CAT III (Low)     = CCSS 0.1-3.9:  minor hardening, defence-in-depth
  Most Apache CIS recommendations are CAT II (Medium) - target CCSS 4.0-6.9.

RULES:
- Output ONLY valid JSON. No markdown, no preamble, no explanation outside JSON.
- Do NOT default CIA to Complete - Partial is correct for most Apache misconfigs.
- Do NOT default AC to Low if write access or network position is required.
- justification: 1-2 sentences on what an attacker can concretely do.
- recommendation: specific directive and value to set.
- cve_ids: list of CVE IDs (empty list [] if none).
"""


# ------------------------------------------------------------------ #
# Few-shot examples (parte do user prompt)                             #
# ------------------------------------------------------------------ #

_FEW_SHOT = """
EXAMPLES (calibration — study these carefully before answering):

Example 1 — ServerTokens=Full (remote, no preconditions → AC=L, info only → C=P):
{
  "ac": "L",
  "c": "P",
  "i": "N",
  "a": "N",
  "gel": "M",
  "grl": "H",
  "justification": "ServerTokens Full exposes Apache version and OS in every HTTP response header, enabling attackers to precisely target known CVEs for the disclosed version.",
  "recommendation": "Set 'ServerTokens Prod' to expose only the product name.",
  "cve_ids": []
}

Example 2 — User=root (any exploit → full system → AC=L, C/I/A=Complete, CAT I):
{
  "ac": "L",
  "c": "C",
  "i": "C",
  "a": "C",
  "gel": "M",
  "grl": "H",
  "justification": "Apache running as root means any web vulnerability grants full root access. This is CAT I — direct full system compromise without further steps.",
  "recommendation": "Set 'User apache' to run as a dedicated unprivileged account.",
  "cve_ids": []
}

Example 3 — AllowOverride=All (requires write access to webroot → AC=M, partial scope → I=P, CAT II):
{
  "ac": "M",
  "c": "P",
  "i": "P",
  "a": "N",
  "gel": "L",
  "grl": "H",
  "justification": "AllowOverride All lets .htaccess files override server config, but only attackers who already have write access to the web root can exploit this — AC is Medium. Scope is limited to the web application, not the full system.",
  "recommendation": "Set 'AllowOverride None' globally; enable selectively only where required.",
  "cve_ids": []
}

Example 4 — Options=FollowSymLinks (requires local write access → AC=M, limited scope → C=P I=P, CAT II):
{
  "ac": "M",
  "c": "P",
  "i": "P",
  "a": "N",
  "gel": "L",
  "grl": "H",
  "justification": "FollowSymLinks allows directory traversal via symlinks, but exploitation requires an attacker who already has write access to create the symlink — AC is Medium, not Low.",
  "recommendation": "Use 'Options SymLinksIfOwnerMatch' instead of 'Options FollowSymLinks'.",
  "cve_ids": []
}

Example 5 — LimitRequestLine=0 (remote DoS but gradual → AC=L, A=Partial not Complete, CAT II):
{
  "ac": "L",
  "c": "N",
  "i": "N",
  "a": "P",
  "gel": "M",
  "grl": "H",
  "justification": "No limit on request line size allows oversized requests that can exhaust memory and degrade performance, but this causes gradual degradation rather than immediate crash — A is Partial.",
  "recommendation": "Set 'LimitRequestLine 8190'.",
  "cve_ids": []
}

Example 6 — TraceEnable=On (requires browser victim → AC=M, limited theft → C=P I=P, CAT II):
{
  "ac": "M",
  "c": "P",
  "i": "P",
  "a": "N",
  "gel": "M",
  "grl": "H",
  "justification": "HTTP TRACE enables Cross-Site Tracing (XST) to steal cookies, but requires a victim to visit a malicious page — AC is Medium. Impact is partial credential theft, not full system access.",
  "recommendation": "Set 'TraceEnable Off' in httpd.conf.",
  "cve_ids": ["CVE-2004-2320", "CVE-2007-3008"]
}
"""


# ------------------------------------------------------------------ #
# Construção do prompt por secção                                       #
# ------------------------------------------------------------------ #

def build_prompt(section: Section, directive: str, bad_value: str) -> str:
    """
    Build the user prompt for one misconfiguration.

    Includes the full CIS section text + the specific bad_value context.
    """
    return f"""{_FEW_SHOT}

---
NOW ANALYSE THIS MISCONFIGURATION:

CIS Benchmark Section: {section.section_id}
Title: {section.title}
Level: {section.level}
Directive: {directive}
Misconfigured value: {bad_value!r}

DESCRIPTION:
{section.description}

RATIONALE (why this matters):
{section.rationale}

REMEDIATION (what the correct value is):
{section.remediation}

DEFAULT VALUE:
{section.default_value}

Assign CCSS metrics for the misconfigured state (when {directive}={bad_value!r}).
Return ONLY a JSON object with keys: ac, c, i, a, gel, grl, justification, recommendation, cve_ids.
"""


# ------------------------------------------------------------------ #
# JSON extraction e validação                                          #
# ------------------------------------------------------------------ #

_VALID_AC: set = {"H", "M", "L"}
_VALID_CIA: set = {"N", "P", "C"}
_VALID_GEL: set = {"N", "L", "M", "H", "ND"}
_VALID_GRL: set = {"U", "W", "H", "ND"}


def _extract_json(text: str) -> dict | None:
    """Extract and parse JSON from LLM response (handles markdown fences)."""
    # Strip markdown code fences (``` or ```json)
    clean = re.sub(r'^\s*```(?:json)?\s*', '', text, flags=re.MULTILINE)
    clean = re.sub(r'\s*```\s*$', '', clean, flags=re.MULTILINE).strip()

    # Try direct parse of cleaned text
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        pass

    # Try original text direct parse
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    # Find first JSON object in text (handles preamble/postamble from verbose models)
    m = re.search(r'\{.*?\}', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass

    return None


def validate_metrics(raw: dict) -> LLMMetrics | None:
    """
    Validate and coerce LLM output into LLMMetrics.
    Returns None if the output is not salvageable.
    """
    try:
        ac = raw.get("ac", "").upper()
        c  = raw.get("c",  "").upper()
        i  = raw.get("i",  "").upper()
        a  = raw.get("a",  "").upper()
        gel = raw.get("gel", "ND").upper()
        grl = raw.get("grl", "H").upper()

        if ac not in _VALID_AC or c not in _VALID_CIA:
            return None
        if i not in _VALID_CIA or a not in _VALID_CIA:
            return None
        if gel not in _VALID_GEL or grl not in _VALID_GRL:
            return None

        justification = str(raw.get("justification", ""))[:500]
        recommendation = str(raw.get("recommendation", ""))[:300]
        cve_ids = [str(v) for v in raw.get("cve_ids", []) if re.match(r'CVE-\d{4}-\d+', str(v))]

        return LLMMetrics(
            ac=ac, c=c, i=i, a=a,
            gel=gel, grl=grl,
            justification=justification,
            recommendation=recommendation,
            cve_ids=cve_ids,
        )
    except Exception:
        return None


# ------------------------------------------------------------------ #
# Conservative fallback (quando o LLM falha)                           #
# ------------------------------------------------------------------ #

_FALLBACK_BY_SECTION_PREFIX = {
    "2": LLMMetrics("L", "P", "N", "N", "L", "H", "Module enabled unnecessarily.", "Disable this module.", []),
    "3": LLMMetrics("L", "C", "C", "C", "M", "H", "Privilege/ownership issue.", "Configure correct ownership.", []),
    "4": LLMMetrics("L", "P", "P", "N", "L", "H", "Access control misconfiguration.", "Apply deny-by-default.", []),
    "5": LLMMetrics("L", "P", "N", "N", "M", "H", "Feature/option enabled insecurely.", "Disable or restrict this feature.", []),
    "6": LLMMetrics("L", "N", "N", "P", "L", "H", "Logging misconfiguration.", "Configure appropriate log level.", []),
    "7": LLMMetrics("H", "P", "P", "N", "M", "H", "TLS/SSL misconfiguration.", "Enable only secure protocols.", []),
    "8": LLMMetrics("L", "P", "N", "N", "M", "H", "Information leakage.", "Minimise server information disclosure.", []),
    "9": LLMMetrics("L", "N", "N", "P", "M", "H", "DoS mitigation missing.", "Apply connection limits.", []),
    "10": LLMMetrics("L", "N", "N", "P", "M", "H", "Request size limit missing.", "Set appropriate request limits.", []),
}


def _conservative_fallback(section_id: str) -> LLMMetrics:
    """Return conservative fallback metrics based on CIS section prefix."""
    prefix = section_id.split(".")[0]
    return _FALLBACK_BY_SECTION_PREFIX.get(
        prefix,
        LLMMetrics("L", "P", "N", "N", "M", "H",
                   "Fallback: LLM unavailable.", "Follow CIS recommendation.", []),
    )


# ------------------------------------------------------------------ #
# Main pipeline class                                                   #
# ------------------------------------------------------------------ #

@dataclass
class MisconfigEntry:
    """Input to the LLM pipeline for one misconfiguration."""
    directive: str
    bad_value: str
    good_value: str
    cis_section: str
    cce_id: str
    target_name: str = "apache-httpd"


class LLMBuildPipeline:
    """
    Populates the database with LLM-generated CCSS metrics.

    Usage:
        pipeline = LLMBuildPipeline(
            benchmark_path="CIS_Apache.pdf",
            llm=make_client(model="qwen2.5:14b"),
        )
        results = pipeline.run(entries, db)
    """

    def __init__(
        self,
        benchmark_path: str,
        llm: LLMClient,
        max_retries: int = 3,
    ) -> None:
        logger.info("Loading CIS Benchmark index from: %s", benchmark_path)
        self.index = BenchmarkIndex(benchmark_path)
        logger.info("Indexed %d sections", len(self.index.sections))
        self.llm = llm
        self.max_retries = max_retries

    def _get_section(self, entry: MisconfigEntry) -> Section | None:
        """
        Get the most relevant CIS section for this misconfiguration.
        Priority: exact section ID > directive search > TF-IDF query.
        """
        if entry.cis_section:
            sec = self.index.get_by_section_id(entry.cis_section)
            if sec:
                return sec

        # Search by directive
        by_directive = self.index.get_by_directive(entry.directive)
        if by_directive:
            return by_directive[0]

        # TF-IDF fallback
        results = self.index.query(f"{entry.directive} {entry.bad_value}", top_k=1)
        return results[0] if results else None

    def _call_llm(self, section: Section, entry: MisconfigEntry) -> LLMMetrics:
        """Call LLM with retries. Falls back to conservative defaults on failure."""
        prompt = build_prompt(section, entry.directive, entry.bad_value)

        for attempt in range(self.max_retries):
            try:
                raw_text = self.llm.complete(prompt, system=_SYSTEM_PROMPT)
                raw_json = _extract_json(raw_text)
                if raw_json is None:
                    raise ValueError(f"Could not extract JSON from: {raw_text[:200]}")

                metrics = validate_metrics(raw_json)
                if metrics is None:
                    raise ValueError(f"Invalid metric values in: {raw_json}")

                logger.debug(
                    "LLM assigned %s=%s → AC:%s C:%s I:%s A:%s GEL:%s GRL:%s",
                    entry.directive, entry.bad_value,
                    metrics.ac, metrics.c, metrics.i, metrics.a,
                    metrics.gel, metrics.grl,
                )
                return metrics

            except Exception as e:
                logger.warning(
                    "LLM attempt %d/%d failed for %s=%s: %s",
                    attempt + 1, self.max_retries,
                    entry.directive, entry.bad_value, e,
                )

        # All retries exhausted — use conservative fallback
        logger.error(
            "All LLM attempts failed for %s=%s — using conservative fallback",
            entry.directive, entry.bad_value,
        )
        metrics = _conservative_fallback(entry.cis_section)
        metrics.confidence = 0.0
        return metrics

    def process_entry(self, entry: MisconfigEntry) -> Misconfiguration:
        """
        Process one misconfiguration entry: RAG → LLM → Misconfiguration model.
        """
        section = self._get_section(entry)

        if section is None:
            logger.warning("No CIS section found for %s (section=%s)", entry.directive, entry.cis_section)
            metrics = _conservative_fallback(entry.cis_section)
        else:
            metrics = self._call_llm(section, entry)

        bs = base_score("N", "N", metrics.ac, metrics.c, metrics.i, metrics.a)
        ts = temporal_score(bs, metrics.gel, metrics.grl)

        return Misconfiguration(
            target_name=entry.target_name,
            directive=entry.directive,
            bad_value=entry.bad_value,
            good_value=entry.good_value,
            av="N",
            au="N",
            ac=metrics.ac,
            c=metrics.c,
            i=metrics.i,
            a=metrics.a,
            base_score=bs,
            temporal_score=ts,
            gel=metrics.gel,
            grl=metrics.grl,
            cves=metrics.cve_ids,
            cce_id=entry.cce_id,
            cis_section=entry.cis_section,
            justification=metrics.justification,
            recommendation=metrics.recommendation,
        )

    def run(
        self,
        entries: list[MisconfigEntry],
        db,
        dry_run: bool = False,
    ) -> list[Misconfiguration]:
        """
        Run the full pipeline over all entries.

        Args:
            entries:  list of MisconfigEntry (directive + context)
            db:       open Database handle
            dry_run:  if True, don't write to DB

        Returns:
            list of Misconfiguration with LLM-assigned metrics
        """
        results = []
        total = len(entries)

        for idx, entry in enumerate(entries, start=1):
            logger.info(
                "[%d/%d] Processing %s=%s (CIS %s)",
                idx, total, entry.directive, entry.bad_value, entry.cis_section,
            )
            misconfig = self.process_entry(entry)
            results.append(misconfig)

            if not dry_run:
                db.upsert_misconfiguration(misconfig)
                logger.info(
                    "  → BaseScore=%.1f TemporalScore=%.1f AC=%s C=%s I=%s A=%s",
                    misconfig.base_score, misconfig.temporal_score,
                    misconfig.ac, misconfig.c, misconfig.i, misconfig.a,
                )

        logger.info("Pipeline complete: %d/%d entries processed", len(results), total)
        return results
