"""
config_assessment/parsers/arm_json.py
-------------------------------------
ARM template (JSON) parser — stdlib only.

Flattens the `resources` array of an Azure Resource Manager template into
flat Directives (the same ARM property vocabulary Bicep uses, so ONE ruleset
serves both):

  { "type": "Microsoft.Storage/storageAccounts",
    "properties": { "supportsHttpsTrafficOnly": false } }

  → Directive(name="supportsHttpsTrafficOnly", value="false",
              context="Microsoft.Storage/storageAccounts[0].properties")

Values are stringified the way IaC authors write them (json booleans →
"true"/"false", numbers verbatim). Line numbers are best-effort: found by a
forward text search for the quoted key (stdlib json has no positions);
accurate for typical hand-written templates. Also flattens top-level
`parameters` defaults (defaultValue) under context `parameters.<name>`.
"""

from __future__ import annotations

import json
from pathlib import Path

from config_assessment.core.models import Directive


def _to_str(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return ""
    return str(v)


class _LineFinder:
    """Best-effort line numbers: forward search of '\"key\"' in the raw text."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0

    def find(self, key: str) -> int | None:
        idx = self._text.find(f'"{key}"', self._pos)
        if idx == -1:                     # key reused earlier — search from top
            idx = self._text.find(f'"{key}"')
            if idx == -1:
                return None
        self._pos = idx + 1
        return self._text.count("\n", 0, idx) + 1


def _flatten(obj, path: list[str], out: list[Directive], src: str,
             lf: _LineFinder) -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, (dict, list)):
                _flatten(val, path + [key], out, src, lf)
            else:
                out.append(Directive(
                    name=key, value=_to_str(val),
                    context=".".join(path) or "global",
                    source_file=src, line_number=lf.find(key)))
    elif isinstance(obj, list):
        leaf = path[-1] if path else "item"
        for i, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                _flatten(item, path[:-1] + [f"{leaf}[{i}]"], out, src, lf)
            else:
                out.append(Directive(
                    name=leaf, value=_to_str(item),
                    context=".".join(path[:-1]) or "global",
                    source_file=src, line_number=lf.find(leaf)))


def parse_file(path: str) -> list[Directive]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []                          # not valid JSON — never crash a scan
    if not isinstance(doc, dict):
        return []

    out: list[Directive] = []
    lf = _LineFinder(text)

    # resources[] — context anchored on the resource TYPE, not the array index
    # alone, so findings read as Microsoft.Storage/storageAccounts[0].…
    for i, res in enumerate(doc.get("resources", []) or []):
        if not isinstance(res, dict):
            continue
        rtype = res.get("type", f"resource[{i}]")
        _flatten(res, [f"{rtype}[{i}]"], out, path, lf)

    # parameters defaults are config too (a weak default is a finding surface).
    params = doc.get("parameters", {}) or {}
    if isinstance(params, dict):
        for name, spec in params.items():
            if isinstance(spec, dict) and "defaultValue" in spec \
                    and not isinstance(spec["defaultValue"], (dict, list)):
                out.append(Directive(
                    name=name, value=_to_str(spec["defaultValue"]),
                    context="parameters", source_file=path,
                    line_number=lf.find(name)))
    return out
