"""
config_assessment/core/manifest.py — reproducibility manifest for a scan.

The thesis claim is that the runtime is deterministic: identical config +
identical knowledge base ⇒ identical CCSS scores. This module makes that claim
VERIFIABLE by stamping every ScanResult with exactly what produced it:

  - caspar_version   the scoring code
  - db_sha256        the knowledge base content (rules, chains, CVE enrichment)
  - target/rules     which plugin ruleset was applied, and how many rules
  - python           interpreter version (formula arithmetic is pure stdlib)

Two scans whose manifests match MUST produce the same scores for the same
input (same input_hash). Anyone can re-run and audit the result — no trust
in the report needed.

db_sha256 hashes a canonical dump of the *content* tables only (targets,
misconfigurations, attack_chains, version_exploits) — not the raw ccss.db
file. The file also holds scan_results (every past scan's history, appended
to on every run) and timestamp bookkeeping columns; hashing the file bytes
directly would make the manifest change on every scan even when the rules
themselves are untouched, which defeats its purpose. Rows are ordered by
primary key and timestamp columns are excluded so the hash reflects only
content that can affect scoring.

Deterministic and offline by construction: reading from the already-open
connection and hashing bytes. Never calls the network or an LLM.
"""

from __future__ import annotations

import hashlib
import platform
import sqlite3
from pathlib import Path

CASPAR_VERSION = "1.0.0"

# (table, primary-key columns to order by, columns to include in the hash —
# excludes created_at/updated_at/fetched_at bookkeeping timestamps, which
# carry no scoring-relevant information but would otherwise make the hash
# vary between machines/runs on logically identical content).
_CONTENT_TABLES = (
    ("targets", ("id",),
     ("id", "name", "display_name", "version", "benchmark_source")),
    ("misconfigurations", ("id",),
     ("id", "target_id", "target_name", "directive", "bad_value", "good_value",
      "av", "au", "ac", "c", "i", "a", "base_score", "temporal_score",
      "gel", "grl", "cves", "cce_id", "cis_section", "justification",
      "recommendation", "rule_type", "required_when", "expected_value_prefix",
      "narrative", "confidence")),
    ("attack_chains", ("id",),
     ("id", "target_id", "target_name", "chain_id", "misconfig_directives",
      "amplification", "justification", "cross_target")),
    ("version_exploits", ("product", "version"),
     ("product", "version", "cve_count", "kev_count", "max_cvss",
      "cve_ids", "exploits")),
)


def _sha256_db_content(conn: sqlite3.Connection) -> str | None:
    """SHA-256 of a canonical dump of the knowledge-base content tables.

    Excludes scan_results (history log, grows every scan) and timestamp
    columns, so the hash is stable across runs against the same rules.
    """
    h = hashlib.sha256()
    for table, order_cols, cols in _CONTENT_TABLES:
        try:
            order_by = ", ".join(order_cols)
            col_list = ", ".join(cols)
            rows = conn.execute(
                f"SELECT {col_list} FROM {table} ORDER BY {order_by}"
            ).fetchall()
        except sqlite3.OperationalError:
            continue
        for row in rows:
            h.update("|".join("" if v is None else str(v) for v in row).encode())
            h.update(b"\n")
        h.update(b"--\n")
    return h.hexdigest()


def build_manifest(db_path: str | Path, target_name: str,
                   rules_count: int | None = None,
                   conn: sqlite3.Connection | None = None) -> dict:
    """The provenance record embedded in every ScanResult (see module docstring)."""
    own_conn = conn is None
    if own_conn:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        db_hash = _sha256_db_content(conn)
    finally:
        if own_conn:
            conn.close()
    return {
        "caspar_version": CASPAR_VERSION,
        "python": platform.python_version(),
        "db_file": Path(str(db_path)).name,
        "db_sha256": db_hash,
        "target": target_name,
        "rules_for_target": rules_count,
    }
