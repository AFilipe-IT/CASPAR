"""
plugins/kubernetes/__init__.py
------------------------------
Kubernetes workload-manifest plugin (IaC target).

Extends the framework beyond runtime daemon configs to Infrastructure-as-Code:
the same deterministic pipeline (parse → rules → CCSS arithmetic) scores a
Pod/Deployment manifest BEFORE it reaches a cluster — shift-left, and a
natural fit for the SARIF/CI-gate output the scan already has.

File detection:
  - .yaml/.yml content carrying BOTH `apiVersion` and `kind:`  → K8s manifest
  - a directory containing such a file
  - requires PyYAML; without it detect() steps aside (never crashes a scan)

Runtime (always deterministic): detect() -> parse_config() -> get_profile().
Rules: curated from CIS Kubernetes Benchmark §5 (see rules.py — no LLM).
"""

from __future__ import annotations

import json
from pathlib import Path

from config_assessment.core.models import AttackChain, Directive, SystemProfile, TargetMetadata
from config_assessment.core.runtime import register_plugin
from config_assessment.core.target import Target, CONFIDENCE_SYNTAX_MARKER
from config_assessment.parsers.yaml_flat import parse_file, yaml_available
from config_assessment.plugins.kubernetes.rules import infer_profile

_CHAINS_PATH = Path(__file__).parent / "chains.json"
CHAINS: list[AttackChain] = []
if _CHAINS_PATH.exists():
    try:
        _raw = json.loads(_CHAINS_PATH.read_text(encoding="utf-8"))
        CHAINS = [
            AttackChain(
                chain_id=c["chain_id"],
                target_name=c["target_name"],
                misconfig_directives=c["misconfig_directives"],
                amplification=c["amplification"],
                justification=c["justification"],
                cross_target=c.get("cross_target", False),
            )
            for c in _raw
        ]
    except Exception:
        CHAINS = []

_YAML_SUFFIXES = {".yaml", ".yml"}


def _is_manifest(p: Path) -> bool:
    """K8s marker check: every workload manifest carries apiVersion AND kind."""
    if p.suffix.lower() not in _YAML_SUFFIXES:
        return False
    try:
        sample = p.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False
    return "apiVersion" in sample and "kind:" in sample


class KubernetesPlugin(Target):
    """Kubernetes manifests (CIS Kubernetes Benchmark §5, curated)."""

    def detect(self, path: str) -> bool:
        if not yaml_available():
            return False        # optional dep missing — quietly step aside
        p = Path(path)
        if p.is_file():
            return _is_manifest(p)
        if p.is_dir():
            return any(_is_manifest(f) for suf in _YAML_SUFFIXES
                       for f in sorted(p.glob(f"*{suf}")))
        return False

    def detection_confidence(self, path: str) -> int:
        # apiVersion+kind is syntax only K8s manifests use; there is no
        # canonical filename to beat this with.
        return CONFIDENCE_SYNTAX_MARKER

    def parse_config(self, path: str) -> list[Directive]:
        p = Path(path)
        if p.is_dir():
            directives: list[Directive] = []
            for suf in _YAML_SUFFIXES:
                for f in sorted(p.glob(f"*{suf}")):
                    if _is_manifest(f):
                        directives.extend(parse_file(str(f)))
            return directives
        return parse_file(path)

    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        return infer_profile(directives)

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            name="kubernetes",
            display_name="Kubernetes manifests",
            version="1.0",
            benchmark_source="CIS Kubernetes Benchmark v1.9 §5 (curated)",
        )


register_plugin(KubernetesPlugin())
