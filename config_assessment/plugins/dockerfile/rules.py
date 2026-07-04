"""
plugins/dockerfile/rules.py
---------------------------
Curated rules for Dockerfiles (IaC target), from the container-image sections
of the CIS Docker Benchmark. Metrics are hand-reviewed, no LLM (see the
kubernetes plugin's rules.py for the rationale) — scoring stays pure CCSS
arithmetic.

The parser emits synthetic directives so the exact-match engine applies:
`from_tag=latest` (incl. the implicit no-tag case) and one `expose=<port>`
per port. ABSENCE_RULES showcase the framework's absence machinery on IaC:
a Dockerfile without USER runs as root BY OMISSION.

ENTRIES:        (directive, bad_value, good_value, section, ac, c, i, a,
                 justification, recommendation)
ABSENCE_RULES:  (directive, good_value, section, ac, c, i, a,
                 justification, recommendation)
"""

from __future__ import annotations

from config_assessment.core.models import Directive, SystemProfile

ENTRIES = [
    ("user", "root", "a dedicated non-root user", "CIS Docker 4.1", "M", "C", "C", "P",
     "The container's processes run as uid 0: any code execution in the app "
     "is root against every mounted path and the container runtime.",
     "Create an application user in the image and set USER <name> after the "
     "install steps."),

    ("from_tag", "latest", "a pinned version tag or digest", "CIS Docker 4.2", "M", "P", "P", "P",
     "':latest' (written or implicit) makes the build non-reproducible and "
     "silently pulls whatever the registry serves next — supply-chain drift "
     "you cannot audit.",
     "Pin the base image (FROM img:1.2.3 or img@sha256:…) and update it "
     "deliberately."),

    ("expose", "22", "no SSH inside containers", "CIS Docker 5.6", "M", "C", "P", "N",
     "An SSH daemon inside a container is a second, unmanaged entry point "
     "with its own credentials and patch cycle, invisible to the "
     "orchestrator.",
     "Remove EXPOSE 22 and the sshd package; use `docker exec` / `kubectl "
     "exec` for debugging."),
]

ABSENCE_RULES = [
    ("user", "USER <non-root> present", "CIS Docker 4.1", "M", "C", "C", "P",
     "No USER instruction: Docker defaults to root, so the image runs as "
     "root by omission — the most common containerised-workload finding.",
     "Add a USER instruction with a dedicated non-root user as the last "
     "user-switching step."),

    ("healthcheck", "HEALTHCHECK CMD … present", "CIS Docker 4.6", "H", "N", "N", "P",
     "Without HEALTHCHECK the runtime cannot tell a hung container from a "
     "healthy one, so failures persist silently instead of being restarted.",
     "Add HEALTHCHECK CMD probing the app's real readiness endpoint."),
]


def infer_profile(directives: list[Directive]) -> SystemProfile:
    """Worst-case profile for container images.

    AV=N: an image is built to be deployed and reached over a network; the
    Dockerfile itself often lives in a public repo. Au=N: none of the flagged
    instructions require an authenticated attacker to matter.
    """
    return SystemProfile(av="N", au="N")
