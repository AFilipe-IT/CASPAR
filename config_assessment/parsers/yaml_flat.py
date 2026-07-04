"""
config_assessment/parsers/yaml_flat.py
--------------------------------------
Generic YAML parser for IaC manifests (Kubernetes, docker-compose, …).

Flattens the YAML tree into the framework's flat Directive model:
  - Directive.name    = the leaf key, ORIGINAL case (K8s is case-sensitive:
    `hostNetwork`, not `hostnetwork` — rules are written in the same case).
  - Directive.value   = the raw scalar as written (`true`, `0`, `latest`) —
    no type coercion, so matching stays deterministic and byte-faithful.
  - Directive.context = dotted path of the parents, with sequence indices
    (`spec.template.spec.containers[0].securityContext`), so a finding in a
    multi-container pod points at the exact container.
  - Directive.line_number = the KEY's line (from the YAML composer marks).

Multi-document files (`---`, the K8s norm) are all parsed; when there is more
than one document, contexts are prefixed `docN:`.

Uses PyYAML's compose API (SafeLoader — never instantiates objects). PyYAML is
an optional dependency: without it, parse_file raises a clear RuntimeError and
the IaC plugins' detect() quietly steps aside instead of crashing scans.

Like every parser in this package: NO security evaluation here — that is the
runtime engine's job. Structure in, flat Directives out.
"""

from __future__ import annotations

from pathlib import Path

from config_assessment.core.models import Directive


def _yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        return None


def yaml_available() -> bool:
    """Whether PyYAML is importable (plugins gate detect() on this)."""
    return _yaml() is not None


def _flatten(node, path: list[str], out: list[Directive], src: str, yaml) -> None:
    if isinstance(node, yaml.MappingNode):
        for key_node, val_node in node.value:
            key = str(key_node.value)
            if isinstance(val_node, (yaml.MappingNode, yaml.SequenceNode)):
                _flatten(val_node, path + [key], out, src, yaml)
            else:  # scalar leaf → one Directive
                out.append(Directive(
                    name=key,
                    value="" if val_node.value is None else str(val_node.value),
                    context=".".join(path) or "global",
                    source_file=src,
                    line_number=key_node.start_mark.line + 1,
                ))
    elif isinstance(node, yaml.SequenceNode):
        leaf = path[-1] if path else "item"
        for i, item in enumerate(node.value):
            if isinstance(item, (yaml.MappingNode, yaml.SequenceNode)):
                _flatten(item, path[:-1] + [f"{leaf}[{i}]"], out, src, yaml)
            else:
                # A list of scalars (e.g. capabilities.add: [SYS_ADMIN]):
                # each element becomes an instance of the SAME directive, so
                # token rules can fire per element.
                out.append(Directive(
                    name=leaf,
                    value="" if item.value is None else str(item.value),
                    context=".".join(path[:-1]) or "global",
                    source_file=src,
                    line_number=item.start_mark.line + 1,
                ))


def parse_file(path: str) -> list[Directive]:
    yaml = _yaml()
    if yaml is None:
        raise RuntimeError(
            "YAML parsing requires PyYAML — install with: pip install pyyaml")

    text = Path(path).read_text(encoding="utf-8", errors="replace")
    directives: list[Directive] = []
    try:
        docs = [d for d in yaml.compose_all(text, Loader=yaml.SafeLoader) if d]
    except yaml.YAMLError:
        return []   # not valid YAML — nothing to surface, never crash the scan

    for n, doc in enumerate(docs):
        out: list[Directive] = []
        _flatten(doc, [], out, path, yaml)
        if len(docs) > 1:
            for d in out:
                d.context = f"doc{n}:{d.context}"
        directives.extend(out)
    return directives
