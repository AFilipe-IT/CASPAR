"""
config_assessment/reports/remediation.py
-----------------------------------------
Turn a scan's findings into concrete remediation — the "fix" half of the
detect→remediate loop. Deterministic and offline: every change comes from a
rule's good_value already in the DB, applied at the directive's known location.

Two kinds of finding:
  * value rules   — a directive is present with a bad value → rewrite that line
                    in place (bad_value → good_value).
  * absence rules — a directive that must be present is missing → cannot be
                    rewritten (there is no line); reported as a manual addition.

The module only proposes edits it can make safely: it rewrites the exact token
on the recorded line, never guesses, and leaves anything it cannot place as a
manual note. Nothing is written unless the caller asks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


# A good_value we can safely write into a config: a concrete token/value, not a
# prose instruction. Reject values that read like guidance ("with restrictions",
# "<organizationally defined>", "appropriate role") — applying those would break
# the config. Such findings are reported as manual instead.
_PROSE_SIGNALS = (" with ", " or ", "organization", "appropriate", "defined",
                  "<", ">", "e.g", "should", "recommended", "valid ", " and ")


def _is_literal_value(good: str) -> bool:
    g = good.strip().rstrip(";")
    if not g:
        return False
    low = g.lower()
    if any(sig in low for sig in _PROSE_SIGNALS):
        return False
    # At most a directive + a value or two (e.g. "ssl_protocols TLSv1.2 TLSv1.3").
    # More than ~4 whitespace-separated tokens is almost certainly prose.
    if len(g.split()) > 4:
        return False
    return True


@dataclass
class FixEdit:
    directive: str
    file: str
    line_number: int
    old_line: str
    new_line: str
    score: float = 0.0


@dataclass
class FixPlan:
    edits: list[FixEdit] = field(default_factory=list)      # applyable in place
    manual: list[dict] = field(default_factory=list)        # need human action

    @property
    def files(self) -> set[str]:
        return {e.file for e in self.edits}


def build_fix_plan(result) -> FixPlan:
    """Build a remediation plan from a ScanResult. Value-rule issues with a
    good_value and a known location become editable line rewrites; everything
    else (absence rules, missing location, no good_value) is a manual note."""
    plan = FixPlan()
    for issue in result.issues:
        good = getattr(issue, "good_value", "") or ""
        src = getattr(issue, "source_directive", None)
        rule_type = getattr(issue, "rule_type", "value")

        if rule_type != "value" or not good:
            plan.manual.append(_manual_note(issue, reason=(
                "absence rule — add the directive" if rule_type == "absence"
                else "no concrete good value")))
            continue
        if not _is_literal_value(good):
            # good_value is a prose instruction, not a writable value — applying
            # it would corrupt the config. Leave it for the human.
            plan.manual.append(_manual_note(
                issue, reason="good value is guidance, not a literal value"))
            continue
        if not src or not getattr(src, "source_file", "") or not getattr(src, "line_number", None):
            plan.manual.append(_manual_note(issue, reason="location unknown"))
            continue

        edit = _make_edit(issue, src, good)
        if edit is None:
            plan.manual.append(_manual_note(issue, reason="could not locate value on line"))
        else:
            plan.edits.append(edit)
    return plan


def _manual_note(issue, reason: str) -> dict:
    return {
        "directive": issue.directive,
        "bad_value": getattr(issue, "bad_value", ""),
        "good_value": getattr(issue, "good_value", ""),
        "recommendation": getattr(issue, "recommendation", ""),
        "score": getattr(issue, "temporal_score", 0.0),
        "reason": reason,
    }


def _make_edit(issue, src, good: str) -> FixEdit | None:
    """Read the target line and produce the rewritten line, replacing the bad
    value token with the good value. Returns None if the file/line can't be
    read or the value isn't found on that line."""
    path = Path(src.source_file)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    idx = src.line_number - 1
    if not (0 <= idx < len(lines)):
        return None
    old = lines[idx]
    bad = getattr(issue, "bad_value", "") or getattr(src, "value", "") or ""

    if bad and bad in old:
        new = old.replace(bad, good, 1)
    else:
        # Fall back to rewriting the directive's value: "<directive> <good>",
        # preserving leading indentation.
        stripped = old.lstrip()
        indent = old[: len(old) - len(stripped)]
        if not stripped.lower().startswith(issue.directive.lower()):
            return None
        new = f"{indent}{issue.directive} {good}"
    if new == old:
        return None
    return FixEdit(directive=issue.directive, file=str(path),
                   line_number=src.line_number, old_line=old, new_line=new,
                   score=getattr(issue, "temporal_score", 0.0))


def render_diff(plan: FixPlan) -> str:
    """A unified-diff-ish preview of the planned edits (for --dry-run)."""
    out: list[str] = []
    for f in sorted(plan.files):
        out.append(f"--- {f}")
        for e in sorted((e for e in plan.edits if e.file == f),
                        key=lambda e: e.line_number):
            out.append(f"@@ line {e.line_number}  ({e.directive}, score {e.score:.1f})")
            out.append(f"- {e.old_line}")
            out.append(f"+ {e.new_line}")
    return "\n".join(out)


def apply_plan(plan: FixPlan, *, in_place: bool = False,
               suffix: str = ".fixed") -> list[str]:
    """Apply the edits. With in_place=False (default), write each file to
    <file><suffix> and leave the original untouched. Returns the paths written.
    Edits to the same file are applied together."""
    written: list[str] = []
    by_file: dict[str, list[FixEdit]] = {}
    for e in plan.edits:
        by_file.setdefault(e.file, []).append(e)

    for f, edits in by_file.items():
        path = Path(f)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        for e in edits:
            i = e.line_number - 1
            if 0 <= i < len(lines):
                nl = "\n" if lines[i].endswith("\n") else ""
                lines[i] = e.new_line + nl
        target = path if in_place else path.with_name(path.name + suffix)
        target.write_text("".join(lines), encoding="utf-8")
        written.append(str(target))
    return written
