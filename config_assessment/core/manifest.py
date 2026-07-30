"""
config_assessment/core/manifest.py — reproducibility manifest for a scan.

The thesis claim is that the runtime is deterministic: identical config +
identical knowledge base ⇒ identical CCSS scores. This module makes that claim
VERIFIABLE by stamping every ScanResult with exactly what produced it:

  - caspar_version   the scoring code
  - db_sha256        the knowledge base (rules, chains, CVE enrichment)
  - target/rules     which plugin ruleset was applied, and how many rules
  - python           interpreter version (formula arithmetic is pure stdlib)

Two scans whose manifests match MUST produce the same scores for the same
input (same input_hash). Anyone can re-run and audit the result — no trust
in the report needed.

Deterministic and offline by construction: hashing a file and reading package
metadata. Never calls the network or an LLM.
"""

from __future__ import annotations

import hashlib
import platform
from pathlib import Path

AEGIS_VERSION = "0.1.0"


def _sha256_file(path: str | Path, chunk: int = 1 << 20) -> str | None:
    """Streamed SHA-256 of a file; None if it doesn't exist (e.g. :memory:)."""
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def build_manifest(db_path: str | Path, target_name: str,
                   rules_count: int | None = None) -> dict:
    """The provenance record embedded in every ScanResult (see module docstring)."""
    return {
        "caspar_version": AEGIS_VERSION,
        "python": platform.python_version(),
        "db_file": Path(str(db_path)).name,
        "db_sha256": _sha256_file(db_path),
        "target": target_name,
        "rules_for_target": rules_count,
    }
