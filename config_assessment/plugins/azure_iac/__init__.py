"""
plugins/azure_iac/__init__.py
-----------------------------
Azure IaC plugin — Terraform (.tf), Bicep (.bicep) and ARM templates (.json).

One target, three languages, two vocabularies:
  - Terraform speaks azurerm attribute names (https_traffic_only_enabled);
  - Bicep and ARM share the ARM property vocabulary (supportsHttpsTrafficOnly).
The knowledge base holds each rule under BOTH vocabularies — produced at
build time by the LLM VOCABULARY MAPPING stage (build_azure.py), which reads
the CIS Microsoft Azure Benchmarks (they speak *portal* language: "Ensure
that 'Secure transfer required' is set to 'Enabled'") and maps every control
to the concrete attribute per language, grounded via RAG in the benchmark.

File detection:
  - *.tf whose content mentions azurerm            → Terraform
  - *.bicep                                        → Bicep (Azure-only DSL)
  - *.json with the deploymentTemplate $schema     → ARM template
  - a directory containing any of the above

Runtime stays 100% deterministic: parse → exact-match rules → CCSS arithmetic.
"""

from __future__ import annotations

from pathlib import Path

from config_assessment.core.models import Directive, SystemProfile, TargetMetadata
from config_assessment.core.runtime import register_plugin
from config_assessment.core.target import (
    Target, CONFIDENCE_EXACT_FILENAME, CONFIDENCE_SYNTAX_MARKER)
from config_assessment.parsers import arm_json, bicep_flat, hcl_flat
from config_assessment.plugins.azure_iac.canon import canon_value

CHAINS: list = []   # curated/generated later, at build time


def _is_azure_tf(p: Path) -> bool:
    if p.suffix.lower() != ".tf":
        return False
    try:
        return "azurerm" in p.read_text(encoding="utf-8", errors="replace")[:8192]
    except OSError:
        return False


def _is_arm_template(p: Path) -> bool:
    if p.suffix.lower() != ".json":
        return False
    try:
        sample = p.read_text(encoding="utf-8", errors="replace")[:2048]
    except OSError:
        return False
    return "deploymentTemplate.json" in sample and '"$schema"' in sample


def _is_azure_iac_file(p: Path) -> bool:
    return (p.suffix.lower() == ".bicep" or _is_azure_tf(p)
            or _is_arm_template(p))


def _parse_one(p: Path) -> list[Directive]:
    if p.suffix.lower() == ".bicep":
        directives = bicep_flat.parse_file(str(p))
    elif p.suffix.lower() == ".tf":
        directives = hcl_flat.parse_file(str(p))
    else:
        directives = arm_json.parse_file(str(p))
    # Canonicalise boolean/state values (Off/Disabled → false) so a config
    # meets the rules on the same form the build stored (see canon.py). Only
    # boolean-like words fold; TLS1_0, Standard_LRS, numbers stay byte-exact.
    for d in directives:
        d.value = canon_value(d.value)
    return directives


class AzureIaCPlugin(Target):
    """Azure IaC (CIS Microsoft Azure Benchmarks, LLM-extracted + mapped)."""

    def detect(self, path: str) -> bool:
        p = Path(path)
        if p.is_file():
            return _is_azure_iac_file(p)
        if p.is_dir():
            for pat in ("*.tf", "*.bicep", "*.json"):
                if any(_is_azure_iac_file(f) for f in sorted(p.glob(pat))):
                    return True
        return False

    def detection_confidence(self, path: str) -> int:
        p = Path(path)
        if p.is_file() and p.suffix.lower() == ".bicep":
            return CONFIDENCE_EXACT_FILENAME    # .bicep can only be Azure
        return CONFIDENCE_SYNTAX_MARKER         # azurerm / $schema markers

    def parse_config(self, path: str) -> list[Directive]:
        p = Path(path)
        if p.is_dir():
            directives: list[Directive] = []
            for pat in ("*.tf", "*.bicep", "*.json"):
                for f in sorted(p.glob(pat)):
                    if _is_azure_iac_file(f):
                        directives.extend(_parse_one(f))
            return directives
        return _parse_one(p)

    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        """Worst-case for cloud resources: an Azure resource is deployed to be
        reachable (AV=N) and none of the benchmark's config controls require an
        authenticated attacker to matter (Au=N)."""
        return SystemProfile(av="N", au="N")

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            name="azure-iac",
            display_name="Azure IaC (Terraform / Bicep / ARM)",
            version="1.0",
            benchmark_source="CIS Microsoft Azure Benchmarks (LLM-extracted)",
        )


register_plugin(AzureIaCPlugin())
