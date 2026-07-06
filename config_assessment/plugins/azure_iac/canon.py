"""
plugins/azure_iac/canon.py
--------------------------
Value canonicalisation for the Azure IaC vocabulary.

Azure/IaC authors write the SAME boolean/state in many casings and synonyms:
`off`/`OFF`/`Off`, `Disabled`/`false`, `Enabled`/`true`. The LLM extractor is
inconsistent between benchmark sections too. If a rule stores `bad="off"` but
a .tf writes `Off`, an exact-match runtime misses it.

Fix WITHOUT weakening the deterministic runtime or touching other targets:
canonicalise the same way at BOTH ends — the build (rule bad_value/good_value)
and the plugin's parse_config (the value read from the file). Rule and config
then meet on one canonical form; the generic exact-match engine is unchanged.

Only boolean-like state words are folded. Everything else (TLS1_0, Standard_LRS,
Microsoft.Storage, numbers) is left byte-exact — those distinctions matter.
"""

from __future__ import annotations

# Synonym → canonical. Lowercased key; compared case-insensitively.
_TRUE = {"true", "on", "enabled", "yes"}
_FALSE = {"false", "off", "disabled", "no"}


def canon_value(v: str) -> str:
    """Fold boolean/state synonyms to 'true'/'false'; pass everything else
    through unchanged (case and bytes preserved)."""
    key = v.strip().strip("'\"").lower()
    if key in _TRUE:
        return "true"
    if key in _FALSE:
        return "false"
    return v
