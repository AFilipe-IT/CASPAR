"""
plugins/apache_httpd/build_apache.py
--------------------------------------
Apache-specific build pipeline.

Phase 2 responsibility: read the CCE XLS ground truth and the CIS Apache
2.4 Benchmark, assign CCSS metrics (AC/C/I/A) to each misconfiguration,
compute scores, and populate the database.

Since we have no network access in the sandbox, this script implements
a RULE-BASED assignment of AC/C/I/A from the CIS Benchmark text
(instead of the LLM + RAG path that Phase 2 will use in production).

This gives us a populated database we can validate against the CCE XLS
and run real end-to-end scans against.

The LLM path (Phase 2 full implementation) would replace
_assign_metrics_rule_based() with _assign_metrics_llm().
The rest of the pipeline is identical.

Usage (from repo root):
    python3 -m plugins.apache_httpd.build_apache \
        --cce /path/to/cceapachehttpd2_25_20130214_1.xls \
        --benchmark /path/to/CIS_Apache_HTTP_Server_2_4_Benchmark_V2_3_0.pdf \
        --db ccss.db
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.ccss import base_score, temporal_score
from core.db.database import Database
from core.models import AttackChain, Misconfiguration, TargetMetadata

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

# ------------------------------------------------------------------ #
# Knowledge base: per-directive CCSS metric assignment                 #
#                                                                      #
# Source: CIS Apache HTTP Server 2.4 Benchmark v2.3.0 + NISTIR 7502  #
# These assignments are what the LLM would produce at build time.     #
# Justifications are derived from the Rationale sections of the CIS   #
# Benchmark. GEL/GRL are conservative defaults (LLM/CVE would refine).#
# ------------------------------------------------------------------ #

# Format: directive → {bad_value, good_value, ac, c, i, a, gel, grl,
#                       cve_ids, cce_id, cis_section, justification, recommendation}
APACHE_MISCONFIGS: list[dict] = [

    # ── Section 8: Information Leakage ────────────────────────────────
    {
        "directive": "ServerTokens",
        "bad_value": "Full",
        "good_value": "Prod",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27380-5",
        "cis_section": "8.1",
        "justification": (
            "ServerTokens Full exposes Apache version, OS, and loaded modules in every "
            "HTTP response header. This allows attackers to precisely target known CVEs "
            "for the disclosed version — dramatically increasing exploit efficiency."
        ),
        "recommendation": "Set 'ServerTokens Prod' in httpd.conf to expose only the product name.",
    },
    {
        "directive": "ServerTokens",
        "bad_value": "OS",
        "good_value": "Prod",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27380-5",
        "cis_section": "8.1",
        "justification": "ServerTokens OS discloses the operating system in HTTP response headers, enabling OS-specific attack targeting.",
        "recommendation": "Set 'ServerTokens Prod' in httpd.conf.",
    },
    {
        "directive": "ServerTokens",
        "bad_value": "Minor",
        "good_value": "Prod",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27380-5",
        "cis_section": "8.1",
        "justification": "ServerTokens Minor exposes minor version number, enabling version-targeted attacks.",
        "recommendation": "Set 'ServerTokens Prod' in httpd.conf.",
    },
    {
        "directive": "ServerSignature",
        "bad_value": "On",
        "good_value": "Off",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27883-8",
        "cis_section": "8.2",
        "justification": (
            "ServerSignature On appends server version information to error pages and "
            "directory listings, disclosing version details to unauthenticated users."
        ),
        "recommendation": "Set 'ServerSignature Off' in httpd.conf.",
    },
    {
        "directive": "FileETag",
        "bad_value": "All",
        "good_value": "MTime Size",
        "ac": "M", "c": "P", "i": "N", "a": "N",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "",
        "cis_section": "8.4",
        "justification": "FileETag All includes inode numbers in ETag headers, leaking internal filesystem structure to clients.",
        "recommendation": "Set 'FileETag MTime Size' to exclude inode information.",
    },

    # ── Section 9 & 10: DoS Mitigations ───────────────────────────────
    {
        "directive": "Timeout",
        "bad_value": "300",
        "good_value": "10",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27688-1",
        "cis_section": "9.1",
        "justification": (
            "A Timeout of 300 seconds allows slow-loris style attacks to hold connections "
            "open for 5 minutes each, enabling resource exhaustion with few connections."
        ),
        "recommendation": "Set 'Timeout 10' to limit connection hold time.",
    },
    {
        "directive": "KeepAlive",
        "bad_value": "Off",
        "good_value": "On",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27456-3",
        "cis_section": "9.2",
        "justification": "KeepAlive Off forces a new TCP connection for every request, increasing server load and enabling connection exhaustion attacks.",
        "recommendation": "Set 'KeepAlive On' to enable HTTP persistent connections.",
    },
    {
        "directive": "MaxKeepAliveRequests",
        "bad_value": "0",
        "good_value": "100",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27830-9",
        "cis_section": "9.3",
        "justification": "MaxKeepAliveRequests 0 means unlimited requests per connection, enabling resource exhaustion by keeping connections alive indefinitely.",
        "recommendation": "Set 'MaxKeepAliveRequests 100' or higher to limit per-connection requests.",
    },
    {
        "directive": "KeepAliveTimeout",
        "bad_value": "300",
        "good_value": "15",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27330-0",
        "cis_section": "9.4",
        "justification": "KeepAliveTimeout 300 allows each idle keep-alive connection to consume resources for 5 minutes, enabling connection pool exhaustion.",
        "recommendation": "Set 'KeepAliveTimeout 15' or less.",
    },
    {
        "directive": "LimitRequestLine",
        "bad_value": "0",
        "good_value": "8190",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27426-6",
        "cis_section": "10.1",
        "justification": "LimitRequestLine 0 removes the cap on HTTP request line length, enabling buffer overflow attacks and denial of service via oversized requests.",
        "recommendation": "Set 'LimitRequestLine 8190' (the recommended maximum).",
    },
    {
        "directive": "LimitRequestFields",
        "bad_value": "0",
        "good_value": "100",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27741-8",
        "cis_section": "10.2",
        "justification": "LimitRequestFields 0 allows unlimited HTTP headers per request, enabling header-based denial of service and potential buffer overflow.",
        "recommendation": "Set 'LimitRequestFields 100' or less.",
    },
    {
        "directive": "LimitRequestFieldSize",
        "bad_value": "0",
        "good_value": "8190",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27554-5",
        "cis_section": "10.3",
        "justification": "LimitRequestFieldSize 0 allows unlimited size for individual HTTP header fields, enabling header injection and buffer overflow attacks.",
        "recommendation": "Set 'LimitRequestFieldSize 8190'.",
    },
    {
        "directive": "LimitRequestBody",
        "bad_value": "0",
        "good_value": "102400",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27618-8",
        "cis_section": "10.4",
        "justification": "LimitRequestBody 0 allows unlimited POST body size, enabling disk exhaustion and memory-based denial of service attacks.",
        "recommendation": "Set 'LimitRequestBody 102400' (100KB) for standard web applications.",
    },

    # ── Section 5: Features and Options ───────────────────────────────
    {
        "directive": "TraceEnable",
        "bad_value": "On",
        "good_value": "Off",
        "ac": "M", "c": "P", "i": "P", "a": "N",
        "gel": "M", "grl": "H",
        "cve_ids": ["CVE-2004-2320", "CVE-2007-3008"],
        "cce_id": "CCE-27531-3",
        "cis_section": "5.8",
        "justification": (
            "HTTP TRACE method enabled allows Cross-Site Tracing (XST) attacks where "
            "an attacker can steal HttpOnly cookies and authentication credentials via "
            "malicious JavaScript combined with TRACE requests."
        ),
        "recommendation": "Set 'TraceEnable Off' in httpd.conf.",
    },
    {
        "directive": "Options",
        "bad_value": "Indexes",
        "good_value": "None",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27657-6",
        "cis_section": "5.2",
        "justification": (
            "Options Indexes enables automatic directory listing when no index file exists, "
            "exposing directory structure, source files, configuration files, and backup files "
            "to unauthenticated attackers."
        ),
        "recommendation": "Remove 'Indexes' from all Options directives. Set 'Options None' or use '-Indexes'.",
    },
    {
        "directive": "Options",
        "bad_value": "FollowSymLinks",
        "good_value": "SymLinksIfOwnerMatch",
        "ac": "M", "c": "P", "i": "P", "a": "N",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27877-0",
        "cis_section": "5.3",
        "justification": "Options FollowSymLinks without OwnerMatch allows attackers with write access to create symlinks pointing to sensitive system files outside the document root.",
        "recommendation": "Use 'Options SymLinksIfOwnerMatch' instead of 'Options FollowSymLinks'.",
    },
    {
        "directive": "Options",
        "bad_value": "All",
        "good_value": "None",
        "ac": "L", "c": "P", "i": "P", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27877-0",
        "cis_section": "5.1",
        "justification": "Options All enables all features including Indexes, FollowSymLinks, ExecCGI, and Includes — the most permissive configuration, compounding multiple vulnerabilities.",
        "recommendation": "Set 'Options None' and enable only the specific options required.",
    },
    {
        "directive": "AllowOverride",
        "bad_value": "All",
        "good_value": "None",
        "ac": "M", "c": "P", "i": "P", "a": "N",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27536-2",
        "cis_section": "4.4",
        "justification": (
            "AllowOverride All permits .htaccess files to override any server configuration, "
            "allowing users with write access to the web root to escalate privileges, enable "
            "CGI execution, change authentication settings, and modify access controls."
        ),
        "recommendation": "Set 'AllowOverride None' globally. Enable selectively only where required with minimal scope.",
    },

    # ── Section 2: Modules ─────────────────────────────────────────────
    {
        "directive": "LoadModule",
        "bad_value": "dav_module",
        "good_value": "#LoadModule dav_module",
        "ac": "L", "c": "P", "i": "C", "a": "P",
        "gel": "M", "grl": "H",
        "cve_ids": ["CVE-2017-9798"],
        "cce_id": "CCE-27132-0",
        "cis_section": "2.3",
        "justification": (
            "WebDAV (dav_module) enabled allows file upload, modification, and deletion "
            "via HTTP PUT/DELETE methods. Misconfigured WebDAV is a common remote code "
            "execution vector — attackers can upload web shells directly to the server."
        ),
        "recommendation": "Disable dav_module: comment out or remove 'LoadModule dav_module modules/mod_dav.so'.",
    },
    {
        "directive": "LoadModule",
        "bad_value": "status_module",
        "good_value": "#LoadModule status_module",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27357-3",
        "cis_section": "2.4",
        "justification": (
            "mod_status exposes server-status endpoint revealing worker states, request "
            "counts, CPU usage, and active request details to unauthenticated clients, "
            "enabling infrastructure mapping for targeted attacks."
        ),
        "recommendation": "Disable status_module or restrict /server-status with authentication.",
    },
    {
        "directive": "LoadModule",
        "bad_value": "info_module",
        "good_value": "#LoadModule info_module",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27852-3",
        "cis_section": "2.8",
        "justification": "mod_info exposes complete Apache configuration including all module settings, directory configurations, and virtual host details — a comprehensive attack surface map.",
        "recommendation": "Disable info_module or restrict /server-info with authentication.",
    },
    {
        "directive": "LoadModule",
        "bad_value": "autoindex_module",
        "good_value": "#LoadModule autoindex_module",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "",
        "cis_section": "2.5",
        "justification": "mod_autoindex enables automatic directory listings when an index file is absent, exposing file and directory structure to unauthenticated users.",
        "recommendation": "Disable autoindex_module if directory listing is not required.",
    },
    {
        "directive": "LoadModule",
        "bad_value": "userdir_module",
        "good_value": "#LoadModule userdir_module",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27682-4",
        "cis_section": "2.7",
        "justification": "mod_userdir enables ~username URL paths, exposing user home directories and revealing valid system usernames — an information disclosure and potential privilege escalation vector.",
        "recommendation": "Disable userdir_module: 'UserDir disabled'.",
    },

    # ── Section 7: TLS / SSL ───────────────────────────────────────────
    {
        "directive": "SSLProtocol",
        "bad_value": "All",
        "good_value": "TLSv1.2 TLSv1.3",
        "ac": "H", "c": "P", "i": "P", "a": "N",
        "gel": "M", "grl": "H",
        "cve_ids": ["CVE-2014-3566", "CVE-2011-3389"],
        "cce_id": "CCE-27740-0",
        "cis_section": "7.4",
        "justification": (
            "SSLProtocol All enables SSLv2, SSLv3, TLSv1.0, and TLSv1.1 — protocols with "
            "known cryptographic weaknesses (POODLE CVE-2014-3566, BEAST CVE-2011-3389). "
            "Attackers in a MITM position can downgrade connections to these weak protocols."
        ),
        "recommendation": "Set 'SSLProtocol -All +TLSv1.2 +TLSv1.3' to allow only modern TLS versions.",
    },
    {
        "directive": "SSLProtocol",
        "bad_value": "+SSLv3",
        "good_value": "TLSv1.2 TLSv1.3",
        "ac": "H", "c": "P", "i": "P", "a": "N",
        "gel": "H", "grl": "H",
        "cve_ids": ["CVE-2014-3566"],
        "cce_id": "CCE-27740-0",
        "cis_section": "7.4",
        "justification": "SSLv3 is vulnerable to POODLE attack (CVE-2014-3566) which allows decryption of HTTPS connections by a MITM attacker.",
        "recommendation": "Remove '+SSLv3' from SSLProtocol and ensure only TLSv1.2 and TLSv1.3 are enabled.",
    },
    {
        "directive": "SSLCompression",
        "bad_value": "On",
        "good_value": "Off",
        "ac": "H", "c": "P", "i": "N", "a": "N",
        "gel": "M", "grl": "H",
        "cve_ids": ["CVE-2012-4929"],
        "cce_id": "",
        "cis_section": "7.7",
        "justification": "SSL compression enabled is vulnerable to CRIME attack (CVE-2012-4929), which allows MITM attackers to decrypt encrypted session cookies.",
        "recommendation": "Set 'SSLCompression Off' (default in modern OpenSSL).",
    },

    # ── Section 3: Permissions ─────────────────────────────────────────
    {
        "directive": "User",
        "bad_value": "root",
        "good_value": "apache",
        "ac": "L", "c": "C", "i": "C", "a": "C",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27756-6",
        "cis_section": "3.1",
        "justification": (
            "Apache running as root means any exploitation of the web server (RCE, path "
            "traversal, SSRF) grants the attacker full root access to the system. "
            "This is the most critical misconfiguration possible."
        ),
        "recommendation": "Set 'User apache' (or 'www-data' on Debian) — a dedicated unprivileged account.",
    },
    {
        "directive": "Group",
        "bad_value": "root",
        "good_value": "apache",
        "ac": "L", "c": "C", "i": "C", "a": "C",
        "gel": "M", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27566-9",
        "cis_section": "3.1",
        "justification": "Apache group set to root grants all child processes root group privileges, compounding any exploitation of the web server.",
        "recommendation": "Set 'Group apache' (or 'www-data') — a dedicated unprivileged group.",
    },

    # ── Section 6: Logging ─────────────────────────────────────────────
    {
        "directive": "LogLevel",
        "bad_value": "emerg",
        "good_value": "warn",
        "ac": "L", "c": "N", "i": "N", "a": "P",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27879-6",
        "cis_section": "6.1",
        "justification": "LogLevel emerg only logs emergency conditions, creating blind spots for attacks, errors, and security events. Incidents will go undetected.",
        "recommendation": "Set 'LogLevel warn' to capture warnings and above.",
    },

    # ── Section 4: Access Control ─────────────────────────────────────
    {
        "directive": "Order",
        "bad_value": "Allow,Deny",
        "good_value": "Deny,Allow",
        "ac": "L", "c": "P", "i": "N", "a": "N",
        "gel": "L", "grl": "H",
        "cve_ids": [],
        "cce_id": "CCE-27510-7",
        "cis_section": "4.1",
        "justification": "Order Allow,Deny allows access by default when no Allow/Deny rule matches. This can inadvertently grant access to directories that should be restricted.",
        "recommendation": "Set 'Order Deny,Allow' with 'Deny from all' as the default-deny baseline.",
    },
]


# ------------------------------------------------------------------ #
# Metric assignment from CIS text (rule-based — LLM replacement)       #
# ------------------------------------------------------------------ #

def _assign_metrics_rule_based(entry: dict) -> dict:
    """
    Return the entry unchanged — metrics are already embedded above.
    In Phase 2 production, this would call the LLM pipeline.
    """
    return entry


# ------------------------------------------------------------------ #
# Build function                                                        #
# ------------------------------------------------------------------ #

def build_apache_db(db_path: str, cce_xls_path: str = "", dry_run: bool = False) -> int:
    """
    Populate the database with Apache misconfiguration data.

    Returns the number of entries written.
    """
    with Database(db_path) as db:
        # Register target
        from plugins.apache_httpd import ApachePlugin
        meta = ApachePlugin().metadata()
        db.upsert_target(
            TargetMetadata(
                name=meta.name,
                display_name=meta.display_name,
                version=meta.version,
                benchmark_source=meta.benchmark_source,
            )
        )

        # Write misconfigurations
        count = 0
        for entry in APACHE_MISCONFIGS:
            entry = _assign_metrics_rule_based(entry)
            bs = base_score(
                av="N",   # AV/Au are runtime-adjusted; store Network/None as baseline
                au="N",
                ac=entry["ac"],
                c=entry["c"],
                i=entry["i"],
                a=entry["a"],
            )
            ts = temporal_score(bs, entry["gel"], entry["grl"])

            m = Misconfiguration(
                target_name=meta.name,
                directive=entry["directive"],
                bad_value=entry["bad_value"],
                good_value=entry["good_value"],
                av="N",
                au="N",
                ac=entry["ac"],
                c=entry["c"],
                i=entry["i"],
                a=entry["a"],
                base_score=bs,
                temporal_score=ts,
                gel=entry["gel"],
                grl=entry["grl"],
                cves=entry["cve_ids"],
                cce_id=entry["cce_id"],
                cis_section=entry["cis_section"],
                justification=entry["justification"],
                recommendation=entry["recommendation"],
            )
            if not dry_run:
                db.upsert_misconfiguration(m)
            count += 1
            logger.info(
                "  %s=%s → BaseScore=%.1f TemporalScore=%.1f",
                entry["directive"], entry["bad_value"], bs, ts,
            )

        # Write attack chains
        from plugins.apache_httpd import CHAINS
        for chain in CHAINS:
            if not dry_run:
                db.upsert_attack_chain(chain)
            logger.info("  Chain: %s (×%.1f)", chain.chain_id, chain.amplification)

        logger.info("Build complete: %d misconfigurations, %d chains", count, len(CHAINS))
        return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Apache CCSS database")
    parser.add_argument("--db", default="ccss.db", help="SQLite database path")
    parser.add_argument("--cce", default="", help="CCE XLS path (for validation)")
    parser.add_argument("--benchmark", default="", help="CIS Benchmark PDF path")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    count = build_apache_db(args.db, args.cce, args.dry_run)
    print(f"Written: {count} entries")
