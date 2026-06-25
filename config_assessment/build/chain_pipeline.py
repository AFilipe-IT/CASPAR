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

from config_assessment.build.llm_client import LLMClient
from config_assessment.core.models import AttackChain, Misconfiguration
from config_assessment.core.ccss import severity_label

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


def _validate_chain(raw: dict, known_directives: set[str],
                    target_name: str = "apache-httpd") -> AttackChain | None:
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
            target_name=target_name,
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

def _load_curated_chains(chains_path) -> list[AttackChain]:
    """Load a hand-curated chains.json from *chains_path* (a Path or str).

    This is the source of truth for attack chains: the build prefers these
    versioned, deterministic chains over LLM generation (see generate_chains).
    The LLM path remains only as a bootstrap for targets that have no
    chains.json yet. ``target_name`` is taken from each entry (no plugin-specific
    default), so this loader works for any target's JSON.
    """
    import json as _json
    from pathlib import Path

    chains_path = Path(chains_path)
    if not chains_path.exists():
        return []
    try:
        raw = _json.loads(chains_path.read_text(encoding="utf-8"))
        return [
            AttackChain(
                chain_id=c["chain_id"],
                target_name=c["target_name"],
                misconfig_directives=c["misconfig_directives"],
                amplification=c.get("amplification", 1.3),
                justification=c.get("justification", ""),
                cross_target=c.get("cross_target", False),
            )
            for c in raw
        ]
    except Exception as e:
        logger.warning("Could not load curated chains %s: %s", chains_path, e)
        return []


def _write_curated_chains(chains: list[AttackChain], chains_path) -> None:
    """Persist chains to *chains_path* in the same schema _load_curated_chains
    reads, so an LLM-bootstrapped build becomes a deterministic curated source.
    """
    import json as _json
    from pathlib import Path

    chains_path = Path(chains_path)
    chains_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "chain_id": c.chain_id,
            "target_name": c.target_name,
            "misconfig_directives": list(c.misconfig_directives),
            "amplification": c.amplification,
            "justification": c.justification,
            "cross_target": c.cross_target,
        }
        for c in chains
    ]
    chains_path.write_text(_json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ------------------------------------------------------------------ #
# Main stage function                                                   #
# ------------------------------------------------------------------ #

def generate_chains(
    misconfigs: list[Misconfiguration],
    llm: LLMClient,
    max_retries: int = 3,
    merge_with_fallback: bool = False,
    timeout: int = 300,
    chains_json_path=None,
) -> list[AttackChain]:
    """
    Resolve the attack chains for a target.

    Source of truth is the curated, versioned chains.json (chains_json_path).
    When it exists with at least one chain, those chains are used directly —
    deterministic and reproducible — after the same directive-validity check the
    LLM path applies (every directive must exist in this build's misconfig bank).
    The LLM is only the bootstrap path for a target that has no chains.json yet.

    Args:
        misconfigs:           List of Misconfiguration with scores already computed.
        llm:                  LLM client (Ollama or stub).
        max_retries:          LLM call attempts (only used when there is no JSON).
        merge_with_fallback:  Kept for API compatibility; ignored in the
                              JSON-first path.
        chains_json_path:     Path to the target's curated chains.json. Defaults
                              to this module's apache chains.json (back-compat).

    Returns:
        List of AttackChain objects ready to upsert into the database.
    """
    if not misconfigs:
        logger.warning("No misconfigurations provided — skipping chain generation")
        return []

    known = _known_directives(misconfigs)
    # The target is whatever the misconfigs belong to — so LLM-bootstrapped
    # chains carry the right target_name (not the hardcoded "apache-httpd").
    target_name = misconfigs[0].target_name

    # --- JSON-first: curated chains are the source of truth ---
    if chains_json_path is None:
        from pathlib import Path
        chains_json_path = Path(__file__).parent / "chains.json"
    curated = _load_curated_chains(chains_json_path)
    if curated:
        valid = [c for c in curated if set(c.misconfig_directives) <= known]
        dropped = len(curated) - len(valid)
        if dropped:
            logger.warning(
                "%d curated chain(s) reference directives absent from the "
                "misconfig bank — skipped (check chains.json vs build).", dropped,
            )
        logger.info(
            "Using %d curated chains from %s (LLM skipped).",
            len(valid), chains_json_path,
        )
        return valid

    logger.info(
        "No curated chains at %s — bootstrapping via LLM.", chains_json_path,
    )
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
                chain = _validate_chain(raw_chain, known, target_name)
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

    # This point is only reached when there was no curated chains.json (the
    # bootstrap path). Persist the LLM output to chains.json so subsequent
    # builds are deterministic (curated-JSON path) and the human can review it.
    if chains:
        try:
            _write_curated_chains(chains, chains_json_path)
            logger.info("Wrote %d bootstrapped chain(s) to %s for review.",
                        len(chains), chains_json_path)
        except OSError as e:
            logger.warning("Could not write %s: %s", chains_json_path, e)
    else:
        logger.error(
            "All %d LLM attempts failed (%s) and no curated chains.json exists.",
            max_retries, last_error,
        )

    return chains
