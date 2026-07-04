"""
plugins/dockerfile/__init__.py
------------------------------
Dockerfile plugin (IaC target) — zero new dependencies.

Scores the IMAGE RECIPE before it is ever built: root-by-omission (no USER),
unpinned base images (:latest, written or implicit), SSH baked into
containers. Same deterministic pipeline as every other target; pairs with
`scan --report -f sarif` for PR gates.

File detection:
  - files named Dockerfile / Containerfile (any Dockerfile.<suffix> variant)
  - *.dockerfile
  - a directory containing one
  - content heuristic: first instruction is FROM/ARG (never matches YAML/conf)

Runtime (always deterministic): detect() -> parse_config() -> get_profile().
Rules: curated from the CIS Docker Benchmark (see rules.py — no LLM).
"""

from __future__ import annotations

from pathlib import Path

from config_assessment.core.models import Directive, SystemProfile, TargetMetadata
from config_assessment.core.runtime import register_plugin
from config_assessment.core.target import (
    Target, CONFIDENCE_EXACT_FILENAME, CONFIDENCE_SYNTAX_MARKER)
from config_assessment.parsers.dockerfile import parse_file
from config_assessment.plugins.dockerfile.rules import infer_profile

CHAINS: list = []   # none curated yet

_CANONICAL = {"dockerfile", "containerfile"}


def _named_like_dockerfile(p: Path) -> bool:
    n = p.name.lower()
    return (n in _CANONICAL
            or n.split(".")[0] in _CANONICAL      # Dockerfile.prod
            or n.endswith(".dockerfile"))


def _first_instruction_is_from(p: Path) -> bool:
    try:
        for line in p.read_text(encoding="utf-8", errors="replace")[:4096].splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            head = s.split(None, 1)[0].lower()
            return head in ("from", "arg")   # ARG may legally precede FROM
    except OSError:
        pass
    return False


class DockerfilePlugin(Target):
    """Dockerfiles / Containerfiles (CIS Docker Benchmark, curated)."""

    def detect(self, path: str) -> bool:
        p = Path(path)
        if p.is_file():
            return _named_like_dockerfile(p) or _first_instruction_is_from(p)
        if p.is_dir():
            return any(_named_like_dockerfile(f)
                       for f in sorted(p.iterdir()) if f.is_file())
        return False

    def detection_confidence(self, path: str) -> int:
        p = Path(path)
        if p.is_file() and _named_like_dockerfile(p):
            return CONFIDENCE_EXACT_FILENAME
        return CONFIDENCE_SYNTAX_MARKER

    def parse_config(self, path: str) -> list[Directive]:
        p = Path(path)
        if p.is_dir():
            directives: list[Directive] = []
            for f in sorted(p.iterdir()):
                if f.is_file() and _named_like_dockerfile(f):
                    directives.extend(parse_file(str(f)))
            return directives
        return parse_file(path)

    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        return infer_profile(directives)

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            name="dockerfile",
            display_name="Dockerfile / Containerfile",
            version="1.0",
            benchmark_source="CIS Docker Benchmark (curated)",
        )


register_plugin(DockerfilePlugin())
