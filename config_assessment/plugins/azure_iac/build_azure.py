"""
plugins/azure_iac/build_azure.py
--------------------------------
Build the Azure IaC knowledge base from the CIS Microsoft Azure Benchmarks,
with the VOCABULARY-MAPPING stage this target needs.

The problem this stage solves: CIS Azure controls are written in PORTAL
language ("Ensure that 'Secure transfer required' is set to 'Enabled'"), but
the scanner parses IaC files that say `https_traffic_only_enabled = false`
(Terraform/azurerm) or `supportsHttpsTrafficOnly: false` (Bicep/ARM). A
straight extraction would produce rules that never match anything.

So, at BUILD TIME (once, per benchmark), the LLM — grounded via RAG in the
benchmark section itself — maps each control to the concrete attribute in
EACH vocabulary, plus curatable CCSS metrics. Every mapped control becomes
TWO rule rows (terraform + arm vocabularies), so one build serves .tf,
.bicep and ARM .json scans. The runtime stays deterministic exact-match.

Controls the LLM judges not expressible as an IaC attribute (portal-only,
procedural, org-policy) are skipped and counted — honesty over coverage.

Usage:
    python3 -m config_assessment.plugins.azure_iac.build_azure \\
        -b CIS_Microsoft_Azure/CIS_..._Storage_...pdf [-b outro.pdf ...] \\
        [--db ccss.db] [--model qwen2.5:14b] [--max-sections N] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import logging
import re

logger = logging.getLogger("ccss")

_SYSTEM = ("You map CIS Microsoft Azure Benchmark controls to "
           "Infrastructure-as-Code attributes. Output JSON only.")

_PROMPT = """CIS Azure Benchmark control:

Section {sid}: {title}
Description: {description}
Rationale: {rationale}
Remediation (excerpt): {remediation}

Task: map this control to the concrete Infrastructure-as-Code attribute that
enforces it, in BOTH vocabularies:
  1. Terraform azurerm provider (attribute name as written in .tf files)
  2. ARM template / Bicep property name (as written under "properties")

Respond with ONLY this JSON (no prose):
{{
  "mappable": true|false,        // false if portal-only/procedural (no IaC attribute)
  "terraform": {{"attribute": "...", "bad_value": "...", "good_value": "..."}},
  "arm":       {{"attribute": "...", "bad_value": "...", "good_value": "..."}},
  "ac": "L|M|H",                 // exploit complexity if misconfigured
  "c": "N|P|C", "i": "N|P|C", "a": "N|P|C",   // CIA impact — at least ONE
                                              // must be P or C (a CIS control
                                              // always has some impact)
  "justification": "one sentence: why this is a risk",
  "recommendation": "one sentence: what to set"
}}

Rules: attribute names must be the EXACT identifiers used in files (snake_case
for terraform, camelCase for ARM) and must be the LEAF key ONLY — never a
dotted path, never a "properties." prefix (write "softDeleteEnabled", not
"properties.softDeleteEnabled"). bad_value/good_value must be literal values
as written in the file (e.g. "false", "true", "TLS1_0", "TLS1_2"). If only one
vocabulary applies, set the other to {{"attribute": ""}}. If unsure of the
exact attribute, set "mappable": false — do not guess."""

_VALID = {"ac": {"L", "M", "H"}, "cia": {"N", "P", "C"}}


def _extract_json(raw: str) -> dict | None:
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def _clean_vocab(d) -> tuple[str, str, str] | None:
    """(attribute, bad, good) or None if this vocabulary wasn't mapped."""
    if not isinstance(d, dict):
        return None
    attr = str(d.get("attribute", "")).strip()
    # The parsers emit LEAF names (parents go into Directive.context), so a
    # dotted path from the LLM ("properties.softDeleteEnabled") would never
    # match — keep only the leaf, whatever the model wrote.
    attr = attr.split(".")[-1].strip()
    bad = str(d.get("bad_value", "")).strip()
    good = str(d.get("good_value", "")).strip()
    if not attr or not bad or bad.lower() in ("none", "null", ""):
        return None                     # unmatchable placeholder — refuse
    if not re.fullmatch(r"[A-Za-z_][\w\-]*", attr):
        return None                     # not a plausible leaf identifier
    return attr, bad, good


def extract_azure_rules(benchmark_path: str, llm, *,
                        max_sections: int | None = None) -> tuple[list, dict]:
    """Extract + vocabulary-map one benchmark PDF.

    Returns (entries, stats) where entries are curated_build-style tuples:
    (directive, bad, good, section, ac, c, i, a, justification, recommendation)
    — one per successfully mapped vocabulary.
    """
    from config_assessment.build.rag import BenchmarkIndex

    idx = BenchmarkIndex(benchmark_path)
    sections = [s for s in idx.sections if s.title]
    if max_sections:
        sections = sections[:max_sections]

    entries: list = []
    stats = {"sections": len(sections), "mapped": 0, "skipped": 0, "failed": 0}

    for sec in sections:
        prompt = _PROMPT.format(
            sid=sec.section_id, title=sec.title,
            description=(sec.description or "")[:600],
            rationale=(sec.rationale or "")[:600],
            remediation=(sec.remediation or "")[:800],
        )
        try:
            raw = llm.complete(prompt, system=_SYSTEM)
        except Exception as exc:
            logger.warning("[azure-build] %s: LLM error: %s", sec.section_id, exc)
            stats["failed"] += 1
            continue

        data = _extract_json(raw)
        if not data:
            stats["failed"] += 1
            continue
        if not data.get("mappable"):
            stats["skipped"] += 1
            continue

        ac = str(data.get("ac", "")).upper()
        c = str(data.get("c", "")).upper()
        i = str(data.get("i", "")).upper()
        a = str(data.get("a", "")).upper()
        if ac not in _VALID["ac"] or not {c, i, a} <= _VALID["cia"]:
            stats["failed"] += 1
            continue
        if (c, i, a) == ("N", "N", "N"):
            # Zero impact ⇒ base score 0.0 ⇒ a rule that can never surface.
            # A control worth a CIS section has SOME impact — all-N means the
            # model didn't commit; refuse rather than seed dead weight.
            logger.warning("[azure-build] %s: all-N impact — rejected",
                           sec.section_id)
            stats["failed"] += 1
            continue

        just = str(data.get("justification", "")).strip() or sec.title
        rec = str(data.get("recommendation", "")).strip()
        section_label = f"CIS Azure {sec.section_id}"

        n_before = len(entries)
        for vocab_key in ("terraform", "arm"):
            vocab = _clean_vocab(data.get(vocab_key))
            if vocab:
                attr, bad, good = vocab
                entries.append((attr, bad, good, section_label,
                                ac, c, i, a, just, rec))
        if len(entries) > n_before:
            stats["mapped"] += 1
        else:
            stats["failed"] += 1

    return entries, stats


def run_build(benchmarks: list[str], db_path: str = "ccss.db", *,
              model: str = "qwen2.5:14b", max_sections: int | None = None,
              dry_run: bool = False, llm=None) -> dict:
    from config_assessment.build.curated_build import run_curated_build
    from config_assessment.build.llm_client import make_client
    from config_assessment.plugins.azure_iac import AzureIaCPlugin

    if llm is None:
        llm = make_client(backend="ollama", model=model, fallback_to_stub=True)

    all_entries: list = []
    totals = {"sections": 0, "mapped": 0, "skipped": 0, "failed": 0}
    for b in benchmarks:
        entries, stats = extract_azure_rules(b, llm, max_sections=max_sections)
        all_entries.extend(entries)
        for k in totals:
            totals[k] += stats[k]
        print(f"  {b}: {stats['mapped']} mapped / {stats['skipped']} not "
              f"IaC-expressible / {stats['failed']} failed "
              f"(of {stats['sections']} sections)")

    # De-duplicate (same attribute+bad_value may appear in several benchmarks).
    seen, unique = set(), []
    for e in all_entries:
        key = (e[0], e[1])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    if dry_run:
        for e in unique:
            print(f"  {e[0]:38} {e[1]:12} → {e[2]:14} {e[3]}")
        print(f"\n[dry-run] {len(unique)} rules would be written.")
        return {"misconfigs": 0, **totals}

    stats = run_curated_build(
        meta=AzureIaCPlugin().metadata(), entries=unique,
        absence_rules=[], chains_json=None, db_path=db_path)
    return {**stats, **totals}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-b", "--benchmark", action="append", required=True,
                    dest="benchmarks")
    ap.add_argument("--db", default="ccss.db")
    ap.add_argument("--model", default="qwen2.5:14b")
    ap.add_argument("--max-sections", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    out = run_build(args.benchmarks, args.db, model=args.model,
                    max_sections=args.max_sections, dry_run=args.dry_run)
    print(f"azure-iac: {out.get('misconfigs', 0)} rules seeded "
          f"({out['mapped']} controls mapped, {out['skipped']} portal-only, "
          f"{out['failed']} failed)")
