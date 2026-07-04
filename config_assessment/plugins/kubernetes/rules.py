"""
plugins/kubernetes/rules.py
---------------------------
Curated rules for Kubernetes workload manifests (Pods/Deployments/…),
from the pod-security section of the CIS Kubernetes Benchmark (§5).

Directive names are the manifest's leaf keys in their ORIGINAL case
(K8s YAML is case-sensitive; the yaml_flat parser preserves it), so the
runtime's exact-match engine works unchanged.

CCSS metrics are CURATED here, not LLM-assigned: this plugin exists to show
the framework generalising to IaC, so its knowledge base is deliberately
hand-reviewed (like the promoted-rule path, metrics feed the normal CCSS
formulas — scoring itself stays pure arithmetic).

ENTRIES:        (directive, bad_value, good_value, section, ac, c, i, a,
                 justification, recommendation)
ABSENCE_RULES:  intentionally empty for K8s — absence rules fire on EVERY
                manifest missing the key, and most real manifests omit most of
                securityContext; flagging all of them would bury the signal.
                (The unknown-directive layers still surface what we don't know.)
"""

from __future__ import annotations

from config_assessment.core.models import Directive, SystemProfile

ENTRIES = [
    ("privileged", "true", "false", "CIS K8s 5.2.1", "L", "C", "C", "C",
     "A privileged container disables all isolation: it sees host devices and "
     "kernel interfaces, so a compromise of the container is a compromise of "
     "the node.",
     "Set securityContext.privileged: false (or drop the field — false is the "
     "default) and grant specific capabilities instead."),

    ("allowPrivilegeEscalation", "true", "false", "CIS K8s 5.2.5", "L", "C", "P", "N",
     "Allows the process to gain more privileges than its parent (setuid "
     "binaries, file capabilities) — the enabling step of most container "
     "breakout chains.",
     "Set securityContext.allowPrivilegeEscalation: false."),

    ("runAsNonRoot", "false", "true", "CIS K8s 5.2.6", "M", "C", "C", "P",
     "Explicitly permits the container to run as root; root inside the "
     "container maps to uid 0 against the runtime and any mounted paths.",
     "Set securityContext.runAsNonRoot: true and give the image a non-root "
     "USER."),

    ("runAsUser", "0", "a non-zero UID", "CIS K8s 5.2.6", "M", "C", "C", "P",
     "Pins the container to uid 0 (root), overriding any image-level USER.",
     "Set runAsUser to the application's dedicated non-zero UID."),

    ("hostNetwork", "true", "false", "CIS K8s 5.2.4", "L", "P", "P", "N",
     "The pod joins the node's network namespace: it sees node-local "
     "services (kubelet, metadata endpoints) and bypasses NetworkPolicies.",
     "Remove hostNetwork; expose ports via a Service instead."),

    ("hostPID", "true", "false", "CIS K8s 5.2.2", "L", "C", "P", "N",
     "Shares the node's PID namespace: container processes can inspect (and "
     "with ptrace, manipulate) every process on the node.",
     "Remove hostPID: true from the pod spec."),

    ("hostIPC", "true", "false", "CIS K8s 5.2.3", "L", "P", "N", "N",
     "Shares the node's IPC namespace, exposing shared-memory segments of "
     "unrelated processes to the container.",
     "Remove hostIPC: true from the pod spec."),

    ("readOnlyRootFilesystem", "false", "true", "CIS K8s 5.2.12", "M", "N", "P", "N",
     "A writable root filesystem lets an intruder drop tools and persist "
     "inside the container between requests.",
     "Set securityContext.readOnlyRootFilesystem: true and mount writable "
     "emptyDirs only where the app needs them."),

    ("automountServiceAccountToken", "true", "false", "CIS K8s 5.1.6", "M", "P", "P", "N",
     "Mounts API credentials into every container of the pod; any code "
     "execution in the pod can talk to the cluster API with them.",
     "Set automountServiceAccountToken: false unless the workload really "
     "calls the API."),

    ("add", "SYS_ADMIN", "drop: [ALL]", "CIS K8s 5.2.8", "L", "C", "C", "P",
     "CAP_SYS_ADMIN is 'root by another name' — it alone enables mounts, "
     "namespace manipulation and most documented container escapes.",
     "Never add SYS_ADMIN; start from capabilities.drop: [ALL] and add only "
     "the specific capabilities the app needs."),
]

ABSENCE_RULES: list = []


def infer_profile(directives: list[Directive]) -> SystemProfile:
    """Worst-case profile for cluster workloads.

    AV=N: a workload is reachable over the cluster network (Services,
    ingress) and its manifest may come from a public repo — Network is the
    honest worst case; hostNetwork only makes it worse, never better.
    Au=N: none of the flagged fields require an authenticated attacker to
    matter — they amplify whatever foothold exists.
    """
    return SystemProfile(av="N", au="N")
