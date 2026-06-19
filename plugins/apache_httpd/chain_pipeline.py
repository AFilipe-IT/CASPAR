"""
plugins/apache_httpd/chain_pipeline.py
----------------------------------------
Stage LLM para geração de attack chains.

Corre DEPOIS de todos os scores estarem calculados (Opção A).
Recebe a lista de Misconfiguration com scores reais e pede ao LLM
que identifique combinações perigosas — com factor de amplificação
justificado pelos scores concretos.

Design do prompt:
  - O LLM recebe a lista completa de misconfigs com scores já calculados.
  - É instruído a pensar em termos de attack paths (recon → access → impact).
  - O factor de amplificação deve ser calibrado pelos scores das partes:
      * Se as partes são todas Medium (4-7) → amplification 1.2–1.4
      * Se pelo menos uma é High/Critical (7+) → amplification 1.5–1.7
      * Máximo razoável: 1.8 (acima disso o score estaria inflacionado)
  - O output é um JSON array de chains.
  - As chains hard-coded em chains.json são usadas como fallback se o LLM falhar.

Relação com chains.json:
  - chains.json passa a ser o fallback de último recurso.
  - Em produção, as chains vêm sempre do LLM.
  - O resultado LLM é mesclado com eventuais chains manuais (sem duplicados).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass

from core.llm_client import LLMClient
from core.models import AttackChain, Misconfiguration
from core.ccss import severity_label

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# System prompt                                                        #
# ------------------------------------------------------------------ #

_CHAIN_SYSTEM_PROMPT = """\
You are a senior penetration tester and Apache security expert.

You will receive a list of Apache HTTP Server misconfigurations with their CCSS scores.
Your task is to identify ATTACK CHAINS — combinations of misconfigurations that together
create a more dangerous attack path than any single misconfiguration alone.

WHAT MAKES A GOOD CHAIN:
  - The combination enables a complete attack sequence (e.g. recon → access → escalation)
  - Each misconfiguration in the chain contributes a distinct step or amplifies another
  - The chain should be realistic: an attacker would actually use these together
  - Minimum 2 directives, maximum 5 directives per chain

AMPLIFICATION FACTOR RULES (be precise — this affects scoring):
  - All parts are Medium (4.0–6.9 CCSS): amplification 1.2–1.4
  - At least one part is High (7.0–8.9 CCSS): amplification 1.4–1.6
  - At least one part is Critical (9.0–10.0 CCSS): amplification 1.6–1.8
  - Never exceed 1.8 — scores above 10.0 are capped anyway
  - The amplification must be JUSTIFIED by the attack path described

ATTACK PATH TYPES to look for:
  - Recon → Exploit: information disclosure enables targeted exploitation
  - Privilege escalation: misconfigured permissions + execution vector
  - DoS amplification: multiple resource-limit misconfigs compound each other
  - Credential theft: authentication bypass + session exposure
  - Data exfiltration: access control weakness + directory exposure
  - Lateral movement: server info disclosure + weak authentication

OUTPUT FORMAT — return ONLY a valid JSON array, no markdown, no preamble:
[
  {
    "chain_id": "short-kebab-case-name",
    "misconfig_directives": ["Directive1", "Directive2"],
    "amplification": 1.4,
    "justification": "Step 1 (directive1) enables X, which combined with step 2 (directive2) allows Y. Full attack path: recon → access → impact.",
    "cross_target": false
  }
]

IMPORTANT:
  - chain_id must be unique, descriptive, kebab-case
  - misconfig_directives must use ONLY the directive NAME — never include the value.
    CORRECT:   ["Options", "AllowOverride"]
    WRONG:     ["Options Indexes", "AllowOverride All"]
    CORRECT:   ["LoadModule", "AllowOverride"]
    WRONG:     ["LoadModule status_module", "AllowOverride All"]
  - Use the exact directive name as it appears in the DIRECTIVE column of the input table
  - justification must describe the CONCRETE attack path, not just say "these are dangerous"
  - If you find no meaningful chains, return an empty array []
  - Do NOT invent directives not present in the input
"""


# ------------------------------------------------------------------ #
# Prompt builder                                                       #
# ------------------------------------------------------------------ #

def _build_chain_prompt(misconfigs: list[Misconfiguration]) -> str:
    """Build the user prompt with the full list of scored misconfigurations."""

    lines = ["Here are the misconfigurations found in this Apache configuration:\n"]
    lines.append(f"{'DIRECTIVE':<35} {'BAD_VALUE':<25} {'SCORE':>6}  {'SEV':<10}  AC  C   I   A")
    lines.append("─" * 95)

    for m in sorted(misconfigs, key=lambda x: -x.temporal_score):
        sev = severity_label(m.temporal_score)
        lines.append(
            f"{m.directive:<35} {m.bad_value:<25} {m.temporal_score:>6.1f}  "
            f"{sev:<10}  {m.ac}   {m.c}   {m.i}   {m.a}"
        )

    lines.append("\n")
    if misconfigs:
        lines.append(
            f"Total: {len(misconfigs)} misconfigurations. "
            f"Score range: {min(m.temporal_score for m in misconfigs):.1f} – "
            f"{max(m.temporal_score for m in misconfigs):.1f}"
        )
    else:
        lines.append("Total: 0 misconfigurations.")
    lines.append("\nIdentify all meaningful attack chains from these misconfigurations.")
    lines.append("Return ONLY the JSON array.")

    return "\n".join(lines)


# ------------------------------------------------------------------ #
# JSON extraction + validation                                         #
# ------------------------------------------------------------------ #

# Valid directive names (to validate LLM output against hallucinations)
def _known_directives(misconfigs: list[Misconfiguration]) -> set[str]:
    return {m.directive for m in misconfigs}


def _extract_chains_json(text: str) -> list[dict] | None:
    """Extract JSON array from LLM response (handles markdown fences)."""
    # Strip markdown fences
    clean = re.sub(r'^\s*```(?:json)?\s*', '', text, flags=re.MULTILINE)
    clean = re.sub(r'\s*```\s*$', '', clean, flags=re.MULTILINE).strip()

    # Try direct parse
    try:
        result = json.loads(clean)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Try to find JSON array in text
    m = re.search(r'\[.*\]', text, re.DOTALL)
    if m:
        try:
            result = json.loads(m.group())
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    return None


def _normalise_directive(raw_name: str) -> str:
    """
    Normalise a directive name from the LLM response.

    The model sometimes includes the value alongside the name, e.g.:
      "Options Indexes"      → "Options"
      "LoadModule status_module" → "LoadModule"
      "KeepAlive Off"        → "KeepAlive"

    We take the first whitespace-delimited token, which is always the
    canonical directive name.
    """
    return str(raw_name).strip().split()[0] if raw_name else ""


def _validate_chain(raw: dict, known_directives: set[str]) -> AttackChain | None:
    """Validate and coerce one LLM chain entry."""
    try:
        chain_id = str(raw.get("chain_id", "")).strip()
        if not chain_id:
            return None

        # Normalise and validate directives exist in our misconfiguration set.
        # The model sometimes writes "Options Indexes" instead of "Options",
        # so we normalise to the first token before checking.
        raw_dirs = raw.get("misconfig_directives", [])
        normalised_dirs = [_normalise_directive(d) for d in raw_dirs]
        valid_dirs = [d for d in normalised_dirs if d in known_directives]

        # Deduplicate while preserving order (model may repeat after normalisation)
        seen = set()
        valid_dirs = [d for d in valid_dirs if not (d in seen or seen.add(d))]

        if len(valid_dirs) < 2:
            logger.warning(
                "Chain '%s' has fewer than 2 valid directives (raw: %s, normalised: %s, known sample: %s)",
                chain_id, raw_dirs[:4], normalised_dirs[:4], sorted(known_directives)[:6],
            )
            return None

        # Validate amplification
        amp = float(raw.get("amplification", 1.3))
        if not (1.1 <= amp <= 1.8):
            logger.warning("Chain '%s' amplification %.2f out of range [1.1, 1.8] — clamping", chain_id, amp)
            amp = max(1.1, min(1.8, amp))

        justification = str(raw.get("justification", ""))[:600]
        cross_target = bool(raw.get("cross_target", False))

        return AttackChain(
            chain_id=chain_id,
            target_name="apache-httpd",
            misconfig_directives=valid_dirs,
            amplification=round(amp, 2),
            justification=justification,
            cross_target=cross_target,
        )
    except Exception as e:
        logger.warning("Failed to validate chain: %s — %s", raw, e)
        return None


# ------------------------------------------------------------------ #
# Fallback chains (from hard-coded chains.json)                        #
# ------------------------------------------------------------------ #

def _load_fallback_chains() -> list[AttackChain]:
    """Load hand-curated chains.json as fallback."""
    import json as _json
    from pathlib import Path

    chains_path = Path(__file__).parent / "chains.json"
    try:
        raw = _json.loads(chains_path.read_text(encoding="utf-8"))
        return [
            AttackChain(
                chain_id=c["chain_id"],
                target_name=c.get("target_name", "apache-httpd"),
                misconfig_directives=c["misconfig_directives"],
                amplification=c.get("amplification", 1.3),
                justification=c.get("justification", ""),
                cross_target=c.get("cross_target", False),
            )
            for c in raw
        ]
    except Exception as e:
        logger.warning("Could not load fallback chains.json: %s", e)
        return []


# ------------------------------------------------------------------ #
# Main stage function                                                   #
# ------------------------------------------------------------------ #

def generate_chains(
    misconfigs: list[Misconfiguration],
    llm: LLMClient,
    max_retries: int = 3,
    merge_with_fallback: bool = False,
    timeout: int = 300,
) -> list[AttackChain]:
    """
    Generate attack chains from a list of scored misconfigurations using the LLM.

    Args:
        misconfigs:           List of Misconfiguration with scores already computed.
        llm:                  LLM client (Ollama or stub).
        max_retries:          Number of LLM call attempts before falling back.
        merge_with_fallback:  If True, merge LLM chains with chains.json (dedup by chain_id).
                              If False, use only LLM chains (or fallback if LLM fails entirely).

    Returns:
        List of AttackChain objects ready to upsert into the database.
    """
    if not misconfigs:
        logger.warning("No misconfigurations provided — skipping chain generation")
        return []

    known = _known_directives(misconfigs)
    prompt = _build_chain_prompt(misconfigs)

    chains: list[AttackChain] = []
    last_error = None

    for attempt in range(max_retries):
        try:
            logger.info("Chain generation — LLM attempt %d/%d", attempt + 1, max_retries)
            # Override timeout for chain generation — the prompt is much longer
            # than individual metric prompts (30 entries vs 1 section)
            if hasattr(llm, 'timeout'):
                original_timeout = llm.timeout
                llm.timeout = timeout
            try:
                raw_text = llm.complete(prompt, system=_CHAIN_SYSTEM_PROMPT)
            finally:
                if hasattr(llm, 'timeout'):
                    llm.timeout = original_timeout

            raw_list = _extract_chains_json(raw_text)
            if raw_list is None:
                raise ValueError(f"Could not extract JSON array from response: {raw_text[:300]}")

            for raw_chain in raw_list:
                chain = _validate_chain(raw_chain, known)
                if chain:
                    chains.append(chain)

            logger.info(
                "Chain generation complete — %d/%d chains valid",
                len(chains), len(raw_list),
            )

            # Log each chain
            for c in chains:
                logger.info(
                    "  Chain: %s  dirs=%s  amp=×%.1f",
                    c.chain_id, c.misconfig_directives, c.amplification,
                )

            break  # Success

        except Exception as e:
            last_error = e
            logger.warning("Chain generation attempt %d failed: %s", attempt + 1, e)

    # If all attempts failed, use fallback
    if not chains:
        logger.error(
            "All %d LLM attempts failed (%s) — using fallback chains.json",
            max_retries, last_error,
        )
        chains = _load_fallback_chains()

    # Optionally merge with hand-curated chains
    if merge_with_fallback and chains:
        fallback = _load_fallback_chains()
        existing_ids = {c.chain_id for c in chains}
        added = 0
        for fc in fallback:
            if fc.chain_id not in existing_ids:
                chains.append(fc)
                existing_ids.add(fc.chain_id)
                added += 1
        if added:
            logger.info("Merged %d additional chains from chains.json", added)

    return chains
