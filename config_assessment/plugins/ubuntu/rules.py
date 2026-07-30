"""
plugins/ubuntu/rules.py
-----------------------
Curated rules for the CONFIG-BASED subset of the CIS Ubuntu 22.04 Benchmark
(Level 1 Server) — the controls expressed as a value in a config file, which
this framework's parser can read directly.

DELIBERATE SCOPE (documented limitation, important for the thesis): OpenSCAP
evaluates whole-system STATE (file permissions via stat, loaded kernel modules,
running services, package presence). AEGIS evaluates config FILES. This target
covers only the overlapping, file-based controls — kernel/network hardening
(`/etc/sysctl.conf`, sysctl.d) and password policy (`/etc/login.defs`). That is
the fair basis for the OpenSCAP comparison: same controls, different output
(reproducible CCSS score + narrative vs pass/fail).

Values are the CIS-recommended settings taken from the SSG CIS L1 Server guide;
`bad_value` is the insecure setting the scan flags. CCSS metrics are curated
(no LLM in this path) — the curated_build seeds them deterministically.

ENTRIES: (directive, bad_value, good_value, section, ac, c, i, a, just, rec)
  where ac ∈ {L,M,H} (Access Complexity) and c/i/a ∈ {N,P,C} (CIA impact).
  The curated build fixes AV=N, Au=N (system-global worst case); per-control
  exposure nuance is out of scope for this curated subset.
"""

from __future__ import annotations

from config_assessment.core.models import Directive, SystemProfile

# ── sysctl: kernel / network hardening (CIS Ubuntu 22.04 §3.x, §1.5) ─────────
# The parser reads `key = value` from sysctl.conf / sysctl.d; the leaf key is
# the full dotted sysctl name. bad_value is the INSECURE value CIS warns about.
# ac = Access Complexity (L/M/H); most of these need a network position (not
# trivially remote), so AC=M is the honest default; c/i/a = CIA impact.
_SYSCTL = [
    ("net.ipv4.conf.all.accept_redirects", "1", "0", "CIS Ubuntu 3.3.2",
     "M", "N", "P", "N",
     "Accepting ICMP redirects lets an attacker on the local network alter the "
     "host's routing table and redirect traffic through a machine they control.",
     "Set net.ipv4.conf.all.accept_redirects = 0."),
    ("net.ipv4.conf.default.accept_redirects", "1", "0", "CIS Ubuntu 3.3.2",
     "M", "N", "P", "N",
     "New interfaces inherit the insecure default of accepting ICMP redirects.",
     "Set net.ipv4.conf.default.accept_redirects = 0."),
    ("net.ipv4.conf.all.secure_redirects", "1", "0", "CIS Ubuntu 3.3.3",
     "M", "N", "P", "N",
     "Accepting 'secure' ICMP redirects still trusts gateways to reroute "
     "traffic, enabling man-in-the-middle on the local segment.",
     "Set net.ipv4.conf.all.secure_redirects = 0."),
    ("net.ipv4.conf.all.accept_source_route", "1", "0", "CIS Ubuntu 3.3.1",
     "M", "N", "P", "N",
     "Source-routed packets let a sender dictate the return path, bypassing "
     "routing controls and spoofing trusted addresses.",
     "Set net.ipv4.conf.all.accept_source_route = 0."),
    ("net.ipv4.conf.default.accept_source_route", "1", "0", "CIS Ubuntu 3.3.1",
     "M", "N", "P", "N",
     "New interfaces inherit acceptance of source-routed packets.",
     "Set net.ipv4.conf.default.accept_source_route = 0."),
    ("net.ipv4.conf.all.send_redirects", "1", "0", "CIS Ubuntu 3.2.1",
     "M", "N", "P", "N",
     "Sending ICMP redirects reveals routing topology and can be abused to "
     "poison other hosts' routing tables; only routers should do it.",
     "Set net.ipv4.conf.all.send_redirects = 0."),
    ("net.ipv4.conf.default.send_redirects", "1", "0", "CIS Ubuntu 3.2.1",
     "M", "N", "P", "N",
     "New interfaces inherit sending of ICMP redirects.",
     "Set net.ipv4.conf.default.send_redirects = 0."),
    ("net.ipv4.conf.all.rp_filter", "0", "1", "CIS Ubuntu 3.3.7",
     "M", "N", "P", "N",
     "Without reverse-path filtering the host accepts packets with spoofed "
     "source addresses, aiding spoofing and reflection attacks.",
     "Set net.ipv4.conf.all.rp_filter = 1."),
    ("net.ipv4.conf.all.log_martians", "0", "1", "CIS Ubuntu 3.3.4",
     "L", "N", "N", "N",
     "Not logging 'martian' (impossible-source) packets hides spoofing "
     "attempts from detection.",
     "Set net.ipv4.conf.all.log_martians = 1."),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "0", "1", "CIS Ubuntu 3.3.5",
     "L", "N", "N", "P",
     "Responding to broadcast ICMP echo makes the host a Smurf-attack "
     "amplifier for denial-of-service against third parties.",
     "Set net.ipv4.icmp_echo_ignore_broadcasts = 1."),
    ("net.ipv4.tcp_syncookies", "0", "1", "CIS Ubuntu 3.3.6",
     "L", "N", "N", "P",
     "Without SYN cookies the host is easily exhausted by a SYN-flood, "
     "denying service to legitimate clients.",
     "Set net.ipv4.tcp_syncookies = 1."),
    ("net.ipv4.ip_forward", "1", "0", "CIS Ubuntu 3.1.1",
     "M", "N", "P", "N",
     "IP forwarding turns a host into a router, potentially bridging network "
     "segments that should be isolated.",
     "Set net.ipv4.ip_forward = 0 unless the host is a deliberate router."),
    ("kernel.randomize_va_space", "0", "2", "CIS Ubuntu 1.5.3",
     "M", "P", "P", "N",
     "Disabling ASLR makes memory-corruption exploits reliable by removing "
     "address-space randomisation.",
     "Set kernel.randomize_va_space = 2."),
    ("fs.suid_dumpable", "1", "0", "CIS Ubuntu 1.5.1",
     "L", "P", "N", "N",
     "Allowing setuid programs to dump core can leak privileged memory "
     "(secrets, hashes) to disk.",
     "Set fs.suid_dumpable = 0."),
]

# ── /etc/login.defs: password policy (CIS Ubuntu §5.5.x) ─────────────────────
# The parser reads `KEY value` and NORMALISES keys to lowercase (the canonical
# key_value form, as apache/nginx/ssh), so the directive names here are
# lowercase to match what the runtime parses. good/bad values are byte-exact.
_LOGIN_DEFS = [
    ("pass_max_days", "99999", "365", "CIS Ubuntu 5.5.1.1",
     "L", "P", "N", "N",
     "Passwords that never expire give a compromised credential an unlimited "
     "useful lifetime.",
     "Set PASS_MAX_DAYS to 365 or fewer in /etc/login.defs."),
    ("pass_min_days", "0", "1", "CIS Ubuntu 5.5.1.2",
     "L", "N", "P", "N",
     "A zero minimum age lets a user cycle through passwords instantly to "
     "defeat history and return to a known one.",
     "Set PASS_MIN_DAYS to 1 or more in /etc/login.defs."),
    ("pass_warn_age", "0", "7", "CIS Ubuntu 5.5.1.3",
     "L", "N", "N", "N",
     "No expiry warning leads to last-minute changes or lockouts rather than "
     "considered password updates.",
     "Set PASS_WARN_AGE to 7 or more in /etc/login.defs."),
    ("encrypt_method", "MD5", "SHA512", "CIS Ubuntu 5.5.4",
     "M", "P", "N", "N",
     "Hashing passwords with MD5 (or DES) makes offline cracking of a stolen "
     "shadow file trivial with modern hardware.",
     "Set ENCRYPT_METHOD SHA512 (or yescrypt) in /etc/login.defs."),
]

ENTRIES = _SYSCTL + _LOGIN_DEFS
ABSENCE_RULES: list = []


def infer_profile(directives: list[Directive]) -> SystemProfile:
    """OS hardening baseline: a server is network-reachable and these controls
    are system-global. AV=N (Network) worst-case, Au=None — none require an
    authenticated attacker to matter. Matches the AV the curated build fixes."""
    return SystemProfile(av="N", au="N")
