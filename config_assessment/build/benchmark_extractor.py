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

If this describes a config DIRECTIVE with a concrete BAD VALUE and GOOD VALUE, extract a value rule.
If it requires a directive to be PRESENT/ENABLED (e.g. "X must be set", "enable Y", "ensure Z is configured")
without a specific bad value, extract an ABSENCE rule with bad_value="" and good_value=<the required value>.
If it's about file permissions, system state, or service management, output extract=false.

Output JSON only:
{{"extract": true, "directive": "name", "bad_value": "insecure", "good_value": "secure", "rule_type": "value"}}
or, for a mandatory-presence control:
{{"extract": true, "directive": "name", "bad_value": "", "good_value": "on", "rule_type": "absence"}}
or
{{"extract": false, "reason": "procedure/unknown"}}'''

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


# ------------------------------------------------------------------ #
# XCCDF (DISA STIG) support                                            #
# ------------------------------------------------------------------ #

def detect_source_format(path: str) -> Literal["pdf", "xccdf", "unknown"]:
    """Best-effort source-format detection by extension + (for XML) root tag."""
    import xml.etree.ElementTree as ET

    low = path.lower()
    if low.endswith(".pdf"):
        return "pdf"
    if low.endswith(".xml"):
        try:
            root = ET.parse(path).getroot()
            tag = root.tag.lower()
            if "benchmark" in tag or "xccdf" in tag:
                return "xccdf"
        except ET.ParseError:
            pass
    return "unknown"


# Map STIG severity → extraction confidence. High-severity rules are the most
# important; we still send them through the LLM (the heuristics are PDF-shaped),
# but mark their confidence so the CLI can report a "High severity" count.
_SEVERITY_CONFIDENCE = {"high": "high", "medium": "medium", "low": "low"}

# Signals in a STIG fixtext that a control is about *presence* (absence rule)
# rather than a concrete bad→good value swap.
_ABSENCE_SIGNALS = ("enable", "configure", "ensure", "must be set", "set the",
                    "add the", "must be present", "must be configured")


# Vendor words that prefix a STIG title before the actual product name, e.g.
# "Apache Tomcat", "Oracle MySQL", "Microsoft IIS". Skipped when deriving the
# service identity so the target_id is the product, not the vendor.
VENDOR_WORDS = {
    "apache", "microsoft", "oracle", "vmware", "red", "ibm",
    "crunchy", "enterprisedb", "splunk", "tanium",
}


def extract_service_name(title: str) -> str:
    """Derive the service name from a benchmark/STIG title.

    Skips a leading vendor word: "Apache Tomcat ..." → "tomcat",
    "Oracle MySQL ..." → "mysql", "Microsoft IIS ..." → "iis".
    """
    words = title.lower().split()
    if words and words[0] in VENDOR_WORDS and len(words) > 1:
        return words[1]
    return words[0] if words else "unknown"


class XCCDFExtractor:
    """Parse a DISA STIG XCCDF XML and extract misconfiguration entries.

    Mirrors the PDF flow: high-severity rules first, then the LLM resolves the
    directive/values from the structured <fixtext>. Output is a list of
    ExtractionResult — identical to extract_all() — so the CLI is format-agnostic.
    """

    NAMESPACES = [
        "http://checklists.nist.gov/xccdf/1.1",
        "http://checklists.nist.gov/xccdf/1.2",
    ]

    XCCDF_LLM_PROMPT = '''You are extracting a security misconfiguration from a DISA STIG rule.

STIG Rule ID: {rule_id}
Severity: {severity}
Title: {title}
Fix Text: {fixtext}
Check Content: {check_content}

Extract the configuration directive and values. Return JSON only:
{{"extract": true, "directive": "name", "bad_value": "insecure_value", "good_value": "secure_value", "rule_type": "value"}}
or, for a control that requires a directive to be PRESENT/enabled:
{{"extract": true, "directive": "name", "bad_value": "", "good_value": "secure_value", "rule_type": "absence"}}
or, if not extractable (procedural/manual):
{{"extract": false, "reason": "procedural/manual"}}

Rules:
- directive: the exact config parameter name (e.g. "maxclients", "ssl")
- bad_value: literal insecure value, or "" for absence rules
- rule_type: "absence" if the fix says "enable/configure/ensure present"'''

    def _ns_for(self, root) -> str:
        """Return the XCCDF namespace URI actually used by this document."""
        if root.tag.startswith("{"):
            return root.tag[1:root.tag.find("}")]
        return self.NAMESPACES[0]

    def load(self, xml_path: str) -> tuple[str, list[dict]]:
        """Return (benchmark_title, rules). Each rule:
        {id, severity, title, fixtext, check_content}."""
        import xml.etree.ElementTree as ET

        root = ET.parse(xml_path).getroot()
        ns = {"x": self._ns_for(root)}

        title_el = root.find("x:title", ns)
        benchmark_title = (title_el.text or "").strip() if title_el is not None else ""

        rules: list[dict] = []
        for r in root.findall(".//x:Rule", ns):
            t = r.find("x:title", ns)
            fix = r.find("x:fixtext", ns)
            chk = r.find(".//x:check-content", ns)
            rules.append({
                "id": r.get("id", ""),
                "severity": (r.get("severity") or "medium").lower(),
                "title": (t.text or "").strip() if t is not None else "",
                "fixtext": "".join(fix.itertext()).strip() if fix is not None else "",
                "check_content": "".join(chk.itertext()).strip() if chk is not None else "",
            })
        return benchmark_title, rules

    def extract(self, xml_path: str, llm_client=None) -> list[ExtractionResult]:
        """Extract one ExtractionResult per rule (LLM-resolved). Rules the LLM
        cannot resolve (procedural/manual) are skipped."""
        _, rules = self.load(xml_path)
        results: list[ExtractionResult] = []

        for rule in rules:
            conf = _SEVERITY_CONFIDENCE.get(rule["severity"], "medium")

            if llm_client is None:
                # No LLM: we cannot resolve directive/values from free-form
                # fixtext deterministically — mark for review with the rule id.
                results.append(ExtractionResult(
                    directive="", rule_type="value", confidence=conf,
                    method="xccdf-no-llm", section_id=rule["id"], needs_review=True,
                ))
                continue

            r = self._llm_extract_rule(rule, llm_client, conf)
            if r is not None:
                results.append(r)

        _rank = {"high": 0, "medium": 1, "low": 2}
        results.sort(key=lambda x: (_rank.get(x.confidence, 3), x.section_id))
        return results

    def _llm_extract_rule(self, rule: dict, llm, confidence: str) -> ExtractionResult | None:
        prompt = self.XCCDF_LLM_PROMPT.format(
            rule_id=rule["id"], severity=rule["severity"],
            title=rule["title"][:200], fixtext=rule["fixtext"][:600],
            check_content=rule["check_content"][:400],
        )
        try:
            raw = llm.complete(prompt, system="You extract STIG config directives. Output JSON only.")
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
        bad_value = str(data.get("bad_value", "")).strip()
        # Absence heuristic fallback: if the LLM said "value" but the fixtext
        # clearly asks for presence and gave no bad_value, treat it as absence.
        if rule_type == "value" and not bad_value:
            low = rule["fixtext"].lower()
            if any(s in low for s in _ABSENCE_SIGNALS):
                rule_type = "absence"

        return ExtractionResult(
            directive=directive, bad_value=bad_value,
            good_value=str(data.get("good_value", "")).strip(),
            rule_type=rule_type, confidence=confidence,
            method="LLM", section_id=rule["id"],
        )
