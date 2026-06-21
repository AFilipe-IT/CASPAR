"""
core/benchmark_extractor.py
----------------------------
Heuristic (zero-LLM) extraction of misconfiguration entries from CIS Benchmark
sections. Peça 1: a deterministic first pass that recognises the common
"directive value" patterns so the LLM build can focus on the hard cases.

Three patterns observed in the Apache benchmark:
  P1  Remediation contains a "DirectiveName value" line (e.g. "ServerTokens Prod")
  P2  Default Value carries the bad_value explicitly (e.g. "Timeout 60")
  P3  Default Value says the feature "IS enabled" → an absence rule

No network, no LLM — pure text heuristics over the parsed Section fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
import re


@dataclass
class ExtractionResult:
    directive: str = ""
    bad_value: str = ""
    good_value: str = ""
    rule_type: Literal["value", "absence", "skip"] = "skip"
    confidence: Literal["high", "medium", "low"] = "low"
    method: str = ""  # which heuristic fired
    section_id: str = ""
    needs_review: bool = False  # heuristic+LLM could not resolve confidently


def classify_section(section) -> Literal["value", "absence", "procedure", "unknown"]:
    text = f"{section.description} {section.remediation} {section.default_value}".lower()
    procedure_signals = ["chmod", "chown", "chgrp", "chsh", "useradd", "systemctl",
                         "dpkg", "apt-get", "passwd", "usermod", "groupadd", "mount",
                         "fstab", "iptables"]
    if any(s in text for s in procedure_signals):
        return "procedure"
    if "is enabled" in section.default_value.lower() and "loadmodule" in text:
        return "absence"
    return "value"


def try_extract_entry(section) -> ExtractionResult:
    # Only operate on directives the parser actually detected in this section.
    # This is the key filter: it rejects pdftotext noise ("Page 17", "CIS
    # Controls:") that the parser does not recognise as a directive, and anchors
    # the "DirectiveName value" pattern to the real directive of the section.
    known = set(section.directives)
    directive_hint = section.directives[0] if section.directives else ""
    if not known:
        return ExtractionResult(confidence="low", method="no-directive")

    # Padrão 1: a "DirectiveName value" line whose first token is a KNOWN
    # directive of this section (e.g. "ServerTokens Prod", "Timeout 10").
    for line in section.remediation.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[0] in known:
            directive = parts[0]
            good_value = parts[1]
            bad_value = extract_bad_value_from_default(section.default_value, directive)
            # Reject a bad_value equal to the good_value: the default already
            # holds the recommended state (e.g. KeepAlive On) — not a value rule.
            if bad_value and bad_value.lower() == good_value.lower():
                bad_value = ""
            if bad_value:
                return ExtractionResult(directive=directive, bad_value=bad_value,
                    good_value=good_value, rule_type="value", confidence="high", method="P1+P2")
            return ExtractionResult(directive=directive, bad_value="",
                good_value=good_value, rule_type="value", confidence="medium", method="P1-no-bad")

    # Padrão 2-only: the remediation had no clean "Directive value" line, but the
    # Default Value itself is "Directive value" (e.g. "SSLProtocol all"). Extract
    # the bad_value there and infer the good_value from the title when possible.
    dv = section.default_value.strip()
    dv_parts = dv.split()
    if len(dv_parts) == 2 and dv_parts[0] in known:
        return ExtractionResult(directive=dv_parts[0], bad_value=dv_parts[1].strip("'\".,"),
            good_value="", rule_type="value", confidence="medium", method="P2-default-only")

    # Padrão 3: default_value says the feature "IS enabled" → absence rule.
    if "is enabled" in section.default_value.lower():
        return ExtractionResult(directive=directive_hint, bad_value="",
            good_value="disabled", rule_type="absence", confidence="medium", method="P3-enabled")

    return ExtractionResult(directive=directive_hint, confidence="low", method="no-match")


def extract_bad_value_from_default(default_value: str, directive: str) -> str:
    if not default_value.strip():
        return ""
    m = re.search(rf"{re.escape(directive)}\s+(\S+)", default_value, re.IGNORECASE)
    if m:
        return m.group(1).strip("'\".,")
    m = re.search(r"default.*?is\s+['\"]?(\w+)", default_value, re.IGNORECASE)
    if m:
        return m.group(1)
    first_word = default_value.strip().split()[0].strip("'\".,")
    if first_word and first_word[0].isupper() and len(first_word) > 1:
        return first_word
    return ""


# ------------------------------------------------------------------ #
# LLM extraction for ambiguous sections (Peça 3)                       #
# ------------------------------------------------------------------ #

def _extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of an LLM response."""
    import json
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def llm_extract_entry(section, llm) -> ExtractionResult | None:
    """Ask the LLM to extract a (directive, bad, good) from an ambiguous section.

    Used for sections the heuristic could not resolve (confidence != "high"),
    e.g. any non-Apache benchmark where directive names are not in the parser's
    regex. Returns an ExtractionResult, or None when the LLM says the section is
    not a config-value control (procedure / absence / unknown) or fails.
    """
    prompt = f'''CIS Benchmark section {section.section_id}: "{section.title}"
Remediation: {section.remediation[:400]}
Default Value: {section.default_value[:200]}

If this describes a config DIRECTIVE with a concrete BAD VALUE and GOOD VALUE, extract them.
If it's about file permissions, system state, or service management, output extract=false.

Output JSON only:
{{"extract": true, "directive": "name", "bad_value": "insecure", "good_value": "secure", "rule_type": "value"}}
or
{{"extract": false, "reason": "procedure/absence/unknown"}}'''

    try:
        raw = llm.complete(prompt, system="You extract CIS config directives. Output JSON only.")
    except Exception:
        return None

    data = _extract_json(raw)
    if not data or not data.get("extract"):
        return None

    directive = str(data.get("directive", "")).strip()
    if not directive:
        return None
    rule_type = data.get("rule_type", "value")
    if rule_type not in ("value", "absence"):
        rule_type = "value"
    return ExtractionResult(
        directive=directive,
        bad_value=str(data.get("bad_value", "")).strip(),
        good_value=str(data.get("good_value", "")).strip(),
        rule_type=rule_type,
        confidence="medium",   # LLM-derived: lower than a clean heuristic hit
        method="LLM",
        section_id=section.section_id,
    )


def extract_all(index, llm=None) -> list[ExtractionResult]:
    """Extract entries from every section: heuristic first, LLM for the rest.

    - High-confidence heuristic hits are kept as-is.
    - For anything else, if `llm` is given, try the LLM; otherwise mark
      needs_review. Procedure sections are skipped (not config values).
    - Returns results sorted high-confidence first, then by section id.
    """
    results: list[ExtractionResult] = []
    for section in index.sections:
        if classify_section(section) == "procedure":
            continue

        r = try_extract_entry(section)
        r.section_id = section.section_id

        if r.confidence == "high" and r.directive:
            results.append(r)
            continue

        if llm is not None:
            llm_r = llm_extract_entry(section, llm)
            if llm_r is not None:
                results.append(llm_r)
                continue

        # Unresolved: keep only if there is at least a directive hint to review.
        if r.directive:
            r.needs_review = True
            results.append(r)

    _rank = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda x: (_rank.get(x.confidence, 3), x.section_id))
    return results
