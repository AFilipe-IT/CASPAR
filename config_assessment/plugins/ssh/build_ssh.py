"""
plugins/ssh/build_ssh.py
-------------------------
Entry point for the SSH LLM build (mirrors apache_httpd/build_llm.py and
nginx/build_nginx.py). Reuses the generic LLMBuildPipeline, NarrativePipeline
and generate_chains from the Apache plugin — only the ENTRIES, ABSENCE_RULES and
profile inference are SSH-specific.

The ENTRIES list is the ground truth: directives evaluated, with bad_value,
good_value, and CIS section (CIS Ubuntu 24.04 Benchmark, Section 5.1).
CCE IDs are intentionally empty — like Nginx, SSH has no published CCE ground
truth, so SSH is validated by manual review rather than MAE against CCE.

Scope notes (documented limitations):
  - File-permission recommendations 5.1.1–5.1.3 (access to sshd_config and host
    key files) are EXCLUDED: they are `stat`-based system checks, not
    directive-in-config values, so they fall outside this config parser's model.
  - PasswordAuthentication has no standalone 5.1.x section in this benchmark
    (it is only referenced inside other sections), so it is not an ENTRY.
  - Weak-algorithm entries (Ciphers, MACs) use one representative weak value as
    bad_value; sshd accepts comma-separated lists, so a real config may mix
    strong and weak — the runtime flags the presence of the weak token.

Usage:
    python3 -m config_assessment.plugins.ssh.build_ssh \\
        --benchmark plugins/ssh/CIS_SSH_Benchmark.pdf \\
        --db ccss.db \\
        [--model qwen2.5:14b] [--dry-run] [--ollama-url http://localhost:11434]
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from config_assessment.core.db.database import Database
from config_assessment.build.llm_client import make_client
from config_assessment.core.models import Misconfiguration, TargetMetadata
from config_assessment.plugins.ssh import SSHPlugin
from config_assessment.plugins.apache_httpd.llm_pipeline import LLMBuildPipeline, MisconfigEntry
from config_assessment.build.chain_pipeline import generate_chains

logger = logging.getLogger(__name__)

_TARGET = "ssh"


# ── Cat-1 directive-with-value recommendations (CIS Ubuntu 24.04 §5.1) ────────
# Section IDs verified against plugins/ssh/CIS_SSH_Benchmark.pdf.
ENTRIES: list[MisconfigEntry] = [
    # Access and authentication
    MisconfigEntry("PermitRootLogin",        "yes",      "no",               "5.1.20", "", _TARGET),
    MisconfigEntry("PermitEmptyPasswords",   "yes",      "no",               "5.1.19", "", _TARGET),
    MisconfigEntry("GSSAPIAuthentication",   "yes",      "no",               "5.1.9",  "", _TARGET),
    MisconfigEntry("HostbasedAuthentication","yes",      "no",               "5.1.10", "", _TARGET),
    MisconfigEntry("IgnoreRhosts",           "no",       "yes",              "5.1.11", "", _TARGET),
    MisconfigEntry("PermitUserEnvironment",  "yes",      "no",               "5.1.21", "", _TARGET),
    MisconfigEntry("UsePAM",                 "no",       "yes",              "5.1.22", "", _TARGET),

    # Logging and session limits
    # LogLevel: the benchmark accepts VERBOSE or INFO; the bad value is a level
    # that suppresses authentication logging (QUIET).
    MisconfigEntry("LogLevel",               "QUIET",    "VERBOSE",          "5.1.14", "", _TARGET),
    MisconfigEntry("MaxAuthTries",           "6",        "4",                "5.1.16", "", _TARGET),
    MisconfigEntry("MaxSessions",            "20",       "10",               "5.1.18", "", _TARGET),
    MisconfigEntry("LoginGraceTime",         "120",      "60",               "5.1.13", "", _TARGET),

    # Weak cryptographic algorithms — representative weak bad_value.
    MisconfigEntry("Ciphers", "3des-cbc",   "aes256-ctr,aes192-ctr,aes128-ctr", "5.1.6",  "", _TARGET),
    MisconfigEntry("MACs",    "hmac-md5",   "hmac-sha2-256,hmac-sha2-512",       "5.1.15", "", _TARGET),
]


# ── Absence rules: directives that should be present explicitly (§5.1) ────────
def _absence(directive, good_value, cis_section, required_when="always",
             ac="L", c="P", i="N", a="N", justification="", recommendation=""):
    return Misconfiguration(
        target_name=_TARGET,
        directive=directive,
        bad_value="",
        good_value=good_value,
        rule_type="absence",
        required_when=required_when,
        ac=ac, c=c, i=i, a=a,
        gel="L", grl="W",
        cis_section=cis_section,
        justification=justification,
        recommendation=recommendation,
    )


ABSENCE_RULES: list[Misconfiguration] = [
    _absence(
        "ClientAliveInterval", "ClientAliveInterval 15", "5.1.7",
        justification=(
            "Without ClientAliveInterval, sshd never probes idle clients, so a "
            "session whose network connection has dropped can remain open and "
            "consume resources or be hijacked from an unattended terminal."
        ),
        recommendation="Set 'ClientAliveInterval 15' (with ClientAliveCountMax 3).",
    ),
    _absence(
        "ClientAliveCountMax", "ClientAliveCountMax 3", "5.1.7",
        justification=(
            "Without ClientAliveCountMax, sshd does not bound how many missed "
            "keepalive probes are tolerated, so unresponsive sessions are not "
            "terminated, leaving idle authenticated channels open."
        ),
        recommendation="Set 'ClientAliveCountMax 3' (with ClientAliveInterval 15).",
    ),
    _absence(
        "Banner", "Banner /etc/issue.net", "5.1.5",
        justification=(
            "Without a Banner, sshd presents no legal/authorised-use warning "
            "before authentication, weakening the deterrent and legal posture "
            "against unauthorised access."
        ),
        recommendation="Set 'Banner /etc/issue.net' and populate the banner file.",
    ),
    _absence(
        "DisableForwarding", "DisableForwarding yes", "5.1.8",
        justification=(
            "Without DisableForwarding, sshd permits TCP/X11/agent forwarding by "
            "default, which can be abused to pivot through the host or tunnel "
            "traffic past network controls."
        ),
        recommendation="Set 'DisableForwarding yes' unless forwarding is required.",
    ),
]


def run_build(
    benchmark_path: str,
    db_path: str,
    model: str = "qwen2.5:14b",
    ollama_url: str = "http://localhost:11434",
    dry_run: bool = False,
    stub: bool = False,
) -> int:
    """Run the SSH LLM build pipeline. Returns the number of entries processed."""
    backend = "stub" if stub else "ollama"
    llm = make_client(backend=backend, model=model, base_url=ollama_url, fallback_to_stub=True)
    if stub:
        logger.warning("Running in STUB mode — LLM responses are synthetic")

    with Database(db_path) as db:
        meta = SSHPlugin().metadata()
        db.upsert_target(TargetMetadata(
            name=meta.name,
            display_name=meta.display_name,
            version=meta.version,
            benchmark_source=meta.benchmark_source,
        ))

        # Idempotency: drop misconfigs no longer in ENTRIES or ABSENCE_RULES.
        keep_pairs = (
            [(e.directive, e.bad_value, "") for e in ENTRIES]
            + [(r.directive, r.bad_value, r.expected_value_prefix) for r in ABSENCE_RULES]
        )
        removed = db.delete_misconfigurations_not_in(meta.name, keep_pairs)
        if removed:
            logger.info("Removed %d orphaned misconfiguration(s) not in ENTRIES", removed)

        pipeline = LLMBuildPipeline(benchmark_path=benchmark_path, llm=llm)
        results = pipeline.run(ENTRIES, db, dry_run=dry_run)

        # Absence rules are pre-scored manually and inserted directly (no LLM).
        for rule in ABSENCE_RULES:
            if not dry_run:
                db.upsert_misconfiguration(rule)
                logger.info(
                    "Absence rule upserted: %s (required_when=%s)",
                    rule.directive, rule.required_when,
                )
        results = results + ABSENCE_RULES

        logger.info("Stage 2 — generating attack chains via LLM...")
        chains = generate_chains(
            misconfigs=results,
            llm=llm,
            merge_with_fallback=False,
            timeout=300,
            chains_json_path=Path(__file__).parent / "chains.json",
        )
        if not dry_run:
            for chain in chains:
                db.upsert_attack_chain(chain)
            logger.info("Wrote %d attack chains", len(chains))

    logger.info(
        "Build %s: %d misconfigurations, %d chains",
        "dry-run" if dry_run else "complete",
        len(results),
        len(chains) if not dry_run else 0,
    )
    return len(results)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    parser = argparse.ArgumentParser(description="Stage 1+2: build SSH misconfigurations + chains")
    parser.add_argument("--benchmark", "-b", required=True)
    parser.add_argument("--db", default="ccss.db")
    parser.add_argument("--model", "-m", default="qwen2.5:14b")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--stub", action="store_true")
    args = parser.parse_args()
    n = run_build(
        benchmark_path=args.benchmark, db_path=args.db, model=args.model,
        ollama_url=args.ollama_url, dry_run=args.dry_run, stub=args.stub,
    )
    print(f"Done: {n} misconfigurations.")
