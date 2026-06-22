"""
plugins/apache_httpd/narrative_pipeline.py
-------------------------------------------
Stage 3 do build pipeline: geração de narrativas detalhadas por misconfiguration.

v2 — adiciona enforcement de coerência entre o VALOR da métrica AC e o TEXTO
da justificação. O bug original: o LLM por vezes escrevia "AC=L because
discovering a vulnerability is not trivial" — texto descreve alta
complexidade mas o valor diz Low. Correcção em duas camadas:

  1. Prompt: instrução explícita "the justification text MUST match the
     metric value direction" + exemplos correctos/incorrectos.
  2. Validação pós-LLM: heurística que deteta palavras-chave contraditórias
     (ex: "not trivial", "requires expertise" associadas a AC=L) e
     substitui por um fallback determinístico e coerente.
"""

from __future__ import annotations

import json
import logging
import re

from config_assessment.build.llm_client import LLMClient
from config_assessment.core.models import Misconfiguration

logger = logging.getLogger(__name__)


def _system_prompt(service_name: str = "Apache HTTP Server") -> str:
    return f"""\
You are a senior {service_name} security expert writing a detailed security report.

For each {service_name} misconfiguration you receive, write a structured technical narrative
that will be shown to a security engineer in a professional audit report.

Be SPECIFIC to the directive and value given. Do NOT write generic text.

CRITICAL CONSISTENCY RULE:
The justification text for each metric MUST match the direction of the metric value.
Do NOT write a justification that contradicts the value you were given.

Examples of CORRECT alignment:
  AC=L + "any unauthenticated attacker can trigger this with a standard HTTP request" (consistent: Low = easy)
  AC=M + "requires write access to the web root, an additional precondition" (consistent: Medium = some barrier)
  AC=H + "requires a complex multi-step chain of prerequisites" (consistent: High = hard)

Examples of INCORRECT alignment (NEVER write like this):
  AC=L + "discovering a specific vulnerability is not trivial" -- CONTRADICTION
  AC=L + "requires significant expertise and reconnaissance" -- CONTRADICTION
  AC=H + "trivially exploitable by any script kiddie" -- CONTRADICTION

Before writing the ac justification, check: does the text describe the SAME
difficulty level as the value? If AC=L, describe something EASY.

Output ONLY valid JSON. No markdown, no preamble.
"""


def _build_prompt(m: Misconfiguration, service_name: str = "Apache HTTP Server") -> str:
    scores_context = (
        f"CCSS BaseScore: {m.base_score:.1f} | TemporalScore: {m.temporal_score:.1f} | "
        f"AC={m.ac} C={m.c} I={m.i} A={m.a} GEL={m.gel} GRL={m.grl}"
    )
    cve_context = f"Associated CVEs: {', '.join(m.cves)}" if m.cves else "No CVEs directly associated."
    cis_context = f"CIS Benchmark section: {m.cis_section}" if m.cis_section else ""

    ac_hint = {
        "L": "AC=L (Low): your ac justification must describe an EASY exploit -- no special preconditions beyond sending a request.",
        "M": "AC=M (Medium): your ac justification must describe a genuine but moderate barrier (write access needed, network position, etc).",
        "H": "AC=H (High): your ac justification must describe a hard, multi-step, or rare precondition.",
    }.get(m.ac, "")

    return f"""Generate a detailed security narrative for this {service_name} misconfiguration:

Directive:    {m.directive}
Bad value:    {m.bad_value}
Good value:   {m.good_value}
{cis_context}
{cve_context}
{scores_context}
LLM justification: {m.justification}
Recommendation: {m.recommendation}

REMINDER -- {ac_hint}

Return a JSON object with EXACTLY this structure:
{{
  "description": "2-3 sentences explaining what this directive does and why this specific value ({m.bad_value}) is dangerous.",
  "potential_impact": ["Specific impact 1", "Specific impact 2", "Specific impact 3 (if applicable)"],
  "exploitation_scenario": {{
    "prerequisites": ["Prerequisite 1", "Prerequisite 2 (if any)"],
    "example": "Concrete example: config snippet, HTTP request, or command. Plain text, no markdown fences, no code tags.",
    "result": "What happens as a result of the exploitation."
  }},
  "metric_justifications": {{
    "ac": "Why AC={m.ac}: explain the specific conditions for {m.directive}={m.bad_value}. MUST match AC={m.ac} difficulty -- see reminder.",
    "c": "Why C={m.c}: what information is disclosed or readable.",
    "i": "Why I={m.i}: what data or configuration can be modified.",
    "a": "Why A={m.a}: how availability is or is not affected.",
    "gel": "Why GEL={m.gel}: exploitation frequency for this type of misconfiguration.",
    "grl": "Why GRL={m.grl}: remediation documentation availability."
  }}
}}

Rules:
- All text in English. Be specific: mention {m.directive}, {m.bad_value}, actual attack techniques.
- The ac justification difficulty MUST match AC={m.ac} (checked automatically).
- potential_impact: 2-4 items, each starting with a verb.
- example: plain text only, no markdown fences, no code/pre tags.
- Return ONLY the JSON object.
"""


def _extract_narrative(text: str) -> dict | None:
    clean = re.sub(r'^\s*```(?:json)?\s*', '', text, flags=re.MULTILINE)
    clean = re.sub(r'\s*```\s*$', '', clean, flags=re.MULTILINE).strip()
    for candidate in [clean, text.strip()]:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group())
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    return None


_HARD_SIGNALS = [
    "not trivial", "non-trivial", "requires significant", "requires expertise",
    "requires deep knowledge", "difficult to exploit", "complex chain",
    "advanced skills", "specialized knowledge", "highly skilled",
    "requires extensive", "sophisticated attacker",
]
_EASY_SIGNALS = [
    "trivially", "trivial to exploit", "any attacker can", "no special skills",
    "script kiddie", "single http request", "with no prerequisites",
    "requires no special",
]


def _ac_text_contradicts_value(ac: str, text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    if ac == "L":
        return any(sig in lower for sig in _HARD_SIGNALS)
    if ac == "H":
        return any(sig in lower for sig in _EASY_SIGNALS)
    return False


def _fix_ac_justification(m: Misconfiguration) -> str:
    return {
        "L": f"AC=L (Low complexity): {m.directive}={m.bad_value} can be exploited directly via a standard HTTP request, with no additional preconditions beyond network reachability.",
        "M": f"AC=M (Medium complexity): exploiting {m.directive}={m.bad_value} requires an additional precondition beyond a normal request -- such as write access to the web root or a specific network position.",
        "H": f"AC=H (High complexity): exploiting {m.directive}={m.bad_value} requires a rare or multi-step precondition, such as a chain of prior compromises or precise timing.",
    }.get(m.ac, f"AC={m.ac}: complexity level assigned at build time.")


def _validate_narrative(raw: dict, m: Misconfiguration) -> dict:
    desc = str(raw.get("description", "")).strip() or (
        f"{m.directive}={m.bad_value} is a security misconfiguration. {m.justification}"
    )

    impact = raw.get("potential_impact", [])
    if not isinstance(impact, list) or not impact:
        impact = [m.justification or f"Security risk from {m.directive}={m.bad_value}"]

    scenario = raw.get("exploitation_scenario", {})
    if not isinstance(scenario, dict):
        scenario = {}

    prereqs = scenario.get("prerequisites", [])
    if not isinstance(prereqs, list):
        prereqs = []

    example = str(scenario.get("example", "")).strip() or f"# Configuration\n{m.directive} {m.bad_value}"
    result = str(scenario.get("result", "")).strip() or "Security risk introduced by this configuration."

    mjust = raw.get("metric_justifications", {})
    if not isinstance(mjust, dict):
        mjust = {}

    _CIA_FALLBACK = {
        "N": "None: this metric is not impacted by this misconfiguration.",
        "P": "Partial: limited impact within the scope of the web application.",
        "C": "Complete: full impact -- attacker gains unrestricted access.",
    }
    _GEL_FALLBACK = {
        "N": "No known exploitation in the wild.",
        "L": "Low exploitation rate -- theoretical risk without active automated exploitation.",
        "M": "Medium exploitation rate -- exploit code exists and is occasionally used.",
        "H": "High exploitation rate -- actively exploited, present in CISA KEV.",
        "ND": "Exploitation level not defined.",
    }
    _GRL_FALLBACK = {
        "U": "No official remediation documented.",
        "W": "Workaround available but no official fix.",
        "H": f"CIS Benchmark section {m.cis_section} documents the official remediation.",
        "ND": "Remediation level not defined.",
    }

    ac_text = str(mjust.get("ac", "")).strip()
    if not ac_text or _ac_text_contradicts_value(m.ac, ac_text):
        if ac_text:
            logger.warning(
                "AC consistency violation for %s=%s: AC=%s but text says '%s' -- using deterministic fallback",
                m.directive, m.bad_value, m.ac, ac_text[:80],
            )
        ac_text = _fix_ac_justification(m)

    return {
        "description": desc,
        "potential_impact": [str(i) for i in impact[:5]],
        "exploitation_scenario": {
            "prerequisites": [str(p) for p in prereqs[:5]],
            "example": example,
            "result": result,
        },
        "metric_justifications": {
            "ac":  ac_text,
            "c":   str(mjust.get("c",   _CIA_FALLBACK.get(m.c, ""))),
            "i":   str(mjust.get("i",   _CIA_FALLBACK.get(m.i, ""))),
            "a":   str(mjust.get("a",   _CIA_FALLBACK.get(m.a, ""))),
            "gel": str(mjust.get("gel", _GEL_FALLBACK.get(m.gel, ""))),
            "grl": str(mjust.get("grl", _GRL_FALLBACK.get(m.grl, ""))),
        },
    }


def av_justification(av: str, rationale: str = "") -> str:
    base = {
        "N": "Network (AV=N): The service listens on non-loopback addresses, making it reachable by any remote attacker without physical or adjacent-network access.",
        "A": "Adjacent (AV=A): The service is only reachable from the local network segment.",
        "L": "Local (AV=L): The service only listens on loopback (127.0.0.1).",
    }.get(av, f"AV={av}: access vector determined at scan time.")
    if rationale:
        return f"{base} Detected: {rationale}"
    return base


def au_justification(au: str, rationale: str = "") -> str:
    base = {
        "N": "None (Au=N): No authentication directives detected. The service accepts unauthenticated requests.",
        "S": "Single (Au=S): Single authentication required.",
        "M": "Multiple (Au=M): Multiple authentication steps required.",
    }.get(au, f"Au={au}: authentication level determined at scan time.")
    if rationale:
        return f"{base} Detected: {rationale}"
    return base


class NarrativePipeline:
    """
    Generates rich, internally-consistent narratives for all misconfigurations.

    v2: enforces that metric_justifications.ac text doesn't contradict the
    AC value direction. Contradictions are replaced with a deterministic,
    value-consistent fallback; the rest of the narrative is kept as-is.
    """

    def __init__(self, llm: LLMClient, max_retries: int = 2,
                 service_name: str = "Apache HTTP Server") -> None:
        self.llm = llm
        self.max_retries = max_retries
        self.service_name = service_name

    def generate_narrative(self, m: Misconfiguration) -> dict:
        prompt = _build_prompt(m, self.service_name)

        for attempt in range(self.max_retries):
            try:
                if hasattr(self.llm, "timeout"):
                    self.llm.timeout = 300
                raw_text = self.llm.complete(prompt, system=_system_prompt(self.service_name))
                raw = _extract_narrative(raw_text)
                if raw is None:
                    raise ValueError(f"Could not extract JSON from: {raw_text[:200]}")
                narrative = _validate_narrative(raw, m)
                logger.info(
                    "  Narrative OK: %s=%s (%d impact items)",
                    m.directive, m.bad_value, len(narrative["potential_impact"]),
                )
                return narrative
            except Exception as e:
                logger.warning(
                    "Narrative attempt %d/%d failed for %s=%s: %s",
                    attempt + 1, self.max_retries, m.directive, m.bad_value, e,
                )

        logger.error("All narrative attempts failed for %s=%s -- using fallback", m.directive, m.bad_value)
        return _validate_narrative({}, m)

    def run(self, misconfigs: list[Misconfiguration], db, dry_run: bool = False) -> int:
        total = len(misconfigs)
        written = 0
        for idx, m in enumerate(misconfigs, start=1):
            logger.info("[%d/%d] Narrative: %s=%s", idx, total, m.directive, m.bad_value)
            narrative = self.generate_narrative(m)
            if not dry_run:
                db.update_narrative(m.directive, m.bad_value, m.target_name, narrative)
                written += 1
        logger.info("Narratives complete: %d/%d written", written, total)
        return written
