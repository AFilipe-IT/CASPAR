"""
config_assessment/core/unknown_directives.py
---------------------------------------------
Unknown-directive detection: surface config directives the knowledge base does
not cover, so a new/undocumented directive (e.g. one introduced in a newer
service version) is no longer invisible to the scanner.

Three layers, kept strictly separate to protect the runtime's determinism:

  Layer 1 — surfacing (deterministic): which parsed directives have NO rule
            (value or absence) for the target. Pure set difference.
  Layer 2 — heuristic triage (deterministic): flag surfaced directives whose
            *value* looks risky by auditable pattern rules (no LLM).
  Layer 3 — LLM assessment (NON-deterministic, opt-in): for each unknown
            directive, ground an LLM in RAG context (benchmark + optional docs)
            and ask whether it is a misconfiguration. Produces *candidates*,
            never scored into the deterministic result.

Layers 1-2 are safe to run on every scan. Layer 3 lives behind an explicit flag
and its output is clearly labelled low-confidence, so the CCSS scores stay
reproducible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cycles / heavy imports at runtime
    from config_assessment.core.models import Directive


# ── Layer 1: surfacing ─────────────────────────────────────────────────

@dataclass
class UnknownDirective:
    name: str
    value: str
    source_file: str = ""
    line_number: int | None = None
    context: str = "global"
    # Layer 2 output:
    risk_signals: list[str] = field(default_factory=list)
    # Layer 3 output (only when assessed):
    llm_directive: str = ""
    llm_is_misconfig: bool | None = None
    llm_estimated_score: float | None = None
    llm_impact: str = ""
    llm_justification: str = ""

    @property
    def suspicious(self) -> bool:
        return bool(self.risk_signals)


def find_unknown_directives(directives: list["Directive"],
                            known_directive_names: set[str]) -> list[UnknownDirective]:
    """Layer 1 — directives with no rule in the knowledge base.

    `known_directive_names` is the set of directive names the DB has *any* rule
    for (value or absence), lowercased by the caller. Comparison is
    case-insensitive; order and de-duplication are stable.
    """
    known = {n.lower() for n in known_directive_names}
    seen: set[tuple[str, str]] = set()
    out: list[UnknownDirective] = []
    for d in directives:
        if d.name.lower() in known:
            continue
        key = (d.name.lower(), d.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(UnknownDirective(
            name=d.name, value=d.value,
            source_file=getattr(d, "source_file", "") or "",
            line_number=getattr(d, "line_number", None),
            context=getattr(d, "context", "global") or "global",
        ))
    return out


# ── Layer 2: heuristic triage ──────────────────────────────────────────

# Directive-name signals: a name containing one of these words suggests a
# security-relevant control, so a permissive value on it is worth flagging.
_SECURITY_NAME_WORDS = ("verify", "secure", "auth", "ssl", "tls", "cert",
                        "password", "secret", "token", "encrypt", "permission",
                        "allow", "trust", "cipher", "protocol")

# Value patterns that are risky in general (regardless of directive name).
_RISKY_VALUE_PATTERNS: list[tuple[str, str]] = [
    (r"^\*$", "wildcard '*' (matches everything)"),
    (r"0\.0\.0\.0(?::\d+)?", "binds to all interfaces (0.0.0.0)"),
    (r"(?i)^(all|any)$", "value 'all/any' — overly broad"),
    (r"(?i)\b(disable|disabled|none|no)\b", "feature disabled"),
    (r"(?i)\b(insecure|unsafe|permissive|debug|test)\b", "insecure/debug keyword"),
    (r"(?i)^(0|false|off)$", "boolean-off value"),
    (r"(?i)(chmod\s*)?0?777", "world-writable permissions (777)"),
]

# "off/false/0/no" is only risky when the directive NAME implies a protection.
_OFF_VALUES = {"off", "false", "0", "no", "none", "disabled"}

# Directive-name words that are risky on their own (a directive that shouldn't
# exist in a hardened production config, regardless of value).
_RISKY_NAME_WORDS = ("debug", "experimental", "test", "unsafe", "insecure",
                     "backdoor", "legacy", "deprecated")


def triage_unknown(u: UnknownDirective) -> UnknownDirective:
    """Layer 2 — attach deterministic risk signals to an unknown directive.

    Auditable pattern rules only; no LLM. Mutates and returns `u`.
    """
    name_l = u.name.lower()
    val = u.value.strip()
    val_l = val.lower()
    signals: list[str] = []

    name_is_security = any(w in name_l for w in _SECURITY_NAME_WORDS)

    for pat, label in _RISKY_VALUE_PATTERNS:
        if re.search(pat, val):
            # An off/false value is only meaningful if the directive guards
            # something (avoids flagging every "keepalive off").
            if val_l in _OFF_VALUES and not name_is_security:
                continue
            signals.append(label)

    # A security-named directive set to an off value is a strong signal.
    if name_is_security and val_l in _OFF_VALUES:
        sig = f"security-relevant directive '{u.name}' set to '{val}'"
        if sig not in signals:
            signals.append(sig)

    # A directive whose NAME suggests it should not be in production.
    risky_word = next((w for w in _RISKY_NAME_WORDS if w in name_l), None)
    if risky_word:
        signals.append(f"directive name suggests non-production ('{risky_word}')")

    u.risk_signals = signals
    return u


def surface_and_triage(directives: list["Directive"],
                       known_directive_names: set[str]) -> list[UnknownDirective]:
    """Layers 1+2 together: find unknown directives and triage each. Suspicious
    ones (with risk signals) are returned first, then the rest, both stable."""
    unknowns = [triage_unknown(u)
                for u in find_unknown_directives(directives, known_directive_names)]
    unknowns.sort(key=lambda u: (not u.suspicious, u.name.lower()))
    return unknowns


# ── Layer 3: LLM assessment (opt-in, non-deterministic) ─────────────────

_ASSESS_PROMPT = """You are assessing whether a configuration directive is a security misconfiguration.
This directive is NOT in our benchmark knowledge base — it may be new, third-party, or benign.

Service: {service}
Directive: {name}
Value: {value}

Relevant documentation/benchmark context (may be partial or absent):
{context}

Decide whether this directive+value is a security misconfiguration. Be conservative:
if the context does not support a concrete risk, say it is not a misconfiguration.

Return JSON only:
{{"is_misconfig": true, "estimated_score": 7.0, "impact": "C:P I:N A:N",
  "justification": "one concrete sentence grounded in the context"}}
or
{{"is_misconfig": false, "justification": "why it is benign/uncertain"}}"""


def assess_unknown_with_llm(unknowns: list[UnknownDirective], *, service: str,
                            llm, rag_index=None, top_k: int = 3) -> list[UnknownDirective]:
    """Layer 3 — ground an LLM in RAG context and assess each unknown directive.

    NON-deterministic and opt-in. `llm` is an LLMClient (.complete). `rag_index`
    is an optional object with `.query(text, top_k) -> [section-like]` (e.g.
    BenchmarkIndex); when given, the top matches for the directive become the
    context handed to the LLM. Results are attached to each UnknownDirective and
    are candidates only — callers must not fold them into CCSS scores.
    """
    from config_assessment.build.benchmark_extractor import _extract_json

    for u in unknowns:
        context = _rag_context(rag_index, f"{u.name} {u.value}", top_k)
        prompt = _ASSESS_PROMPT.format(
            service=service, name=u.name, value=u.value or "(no value)",
            context=context or "(no documentation found)")
        try:
            raw = llm.complete(
                prompt, system="You assess config security. Output JSON only.")
        except Exception:
            continue
        data = _extract_json(raw)
        if not data:
            continue
        u.llm_directive = u.name
        u.llm_is_misconfig = bool(data.get("is_misconfig"))
        u.llm_justification = str(data.get("justification", "")).strip()
        if u.llm_is_misconfig:
            try:
                u.llm_estimated_score = float(data.get("estimated_score"))
            except (TypeError, ValueError):
                u.llm_estimated_score = None
            u.llm_impact = str(data.get("impact", "")).strip()
    return unknowns


def _rag_context(rag_index, query: str, top_k: int) -> str:
    """Pull up to top_k relevant sections from a RAG index, as plain text."""
    if rag_index is None:
        return ""
    try:
        sections = rag_index.query(query, top_k=top_k)
    except Exception:
        return ""
    parts = []
    for s in sections:
        title = getattr(s, "title", "")
        body = getattr(s, "body", "") or getattr(s, "remediation", "")
        parts.append(f"- {title}: {body}"[:500])
    return "\n".join(parts)
