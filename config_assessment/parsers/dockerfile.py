"""
config_assessment/parsers/dockerfile.py
---------------------------------------
Dockerfile parser — stdlib only, no dependencies.

Emits one Directive per instruction (name = instruction, lowercase — the
Dockerfile spec is case-insensitive), plus SYNTHETIC directives that turn
patterns the exact-match rule engine can't express into plain key/values:

  FROM nginx:latest        → from=nginx:latest  AND  from_tag=latest
  FROM ubuntu              → from=ubuntu        AND  from_tag=latest  (implicit!)
  FROM x AS build          → tag from the image ref only; stage named in context
  EXPOSE 22 80             → expose=22, expose=80          (one per port)
  USER root                → user=root

Multi-stage builds set context to `stage:<name-or-index>`, so a finding says
WHICH stage runs as root. Line continuations (`\\`) are folded; comments and
blank lines skipped. Like every parser here: no security evaluation — flat
Directives out, the runtime engine judges them.
"""

from __future__ import annotations

from pathlib import Path

from config_assessment.core.models import Directive

_INSTRUCTIONS = {
    "from", "run", "cmd", "label", "expose", "env", "add", "copy",
    "entrypoint", "volume", "user", "workdir", "arg", "onbuild",
    "stopsignal", "healthcheck", "shell", "maintainer",
}


def _image_tag(image_ref: str) -> str:
    """Tag of an image reference; '' for digest pins, 'latest' when implicit."""
    ref = image_ref.strip()
    if "@" in ref:                    # pinned by digest — immutable, no tag
        return ""
    # Split registry/port from tag: the tag is after the LAST ':' only if that
    # colon comes after the last '/' (localhost:5000/img has no tag).
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        return ref[colon + 1:]
    return "latest"                   # no tag written ⇒ Docker pulls :latest


def parse_file(path: str) -> list[Directive]:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()

    directives: list[Directive] = []
    stage = "global"
    stage_n = 0
    buf, buf_start = "", 0

    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        if not buf:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            buf_start = lineno
        # Fold continuations into one logical line.
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical, buf = (buf + line).strip(), ""

        parts = logical.split(None, 1)
        instr = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if instr not in _INSTRUCTIONS:
            continue                   # not a Dockerfile instruction — skip

        if instr == "from":
            stage_n += 1
            tokens = value.split()
            image = tokens[0] if tokens else ""
            # FROM <image> [AS <name>] — the stage names all that follows.
            stage = (tokens[tokens.index("AS") + 1]
                     if "AS" in tokens and tokens.index("AS") + 1 < len(tokens)
                     else f"stage{stage_n}")
            directives.append(Directive(
                name="from", value=image, context=f"stage:{stage}",
                source_file=path, line_number=buf_start))
            tag = _image_tag(image)
            if tag:
                directives.append(Directive(
                    name="from_tag", value=tag, context=f"stage:{stage}",
                    source_file=path, line_number=buf_start))
            continue

        if instr == "expose":
            for port in value.split():
                directives.append(Directive(
                    name="expose", value=port.split("/")[0],
                    context=f"stage:{stage}", source_file=path,
                    line_number=buf_start))
            continue

        directives.append(Directive(
            name=instr, value=value, context=f"stage:{stage}",
            source_file=path, line_number=buf_start))

    return directives
