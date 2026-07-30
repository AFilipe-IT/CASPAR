"""
config_assessment/core/watch.py
-------------------------------
Continuous configuration-audit loop. Watches a config file (or directory) and,
whenever its content changes, re-runs the deterministic scan and reports the
misconfigurations found and their impact — data already in the DB.

Design notes (keeps the AEGIS runtime invariants):
  * Deterministic detection — the loop only *triggers* re-scans; scoring stays
    the zero-LLM/zero-network `runtime.scan`.
  * No baseline, no history, no alerting side-channel. A change → a re-scan →
    the findings on screen. Nothing is written.
  * Polling (mtime + content hash), not inotify — works identically on native
    Linux, WSL2, and bind-mounted Docker volumes where inotify is unreliable.

The module is I/O-only: it computes *when* to re-scan and yields an event. The
CLI owns *what to print* (it reuses the normal scan renderer), so watch and scan
never drift apart in how a finding looks.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator


@dataclass(frozen=True)
class ChangeEvent:
    """Emitted once per detected content change of the watched path."""
    path: Path
    digest: str          # content hash after the change
    previous: str | None  # content hash before the change (None on first sight)


def _fingerprint(path: Path) -> str:
    """A content fingerprint of the watched target.

    For a file: sha256 of its bytes. For a directory: sha256 over the sorted
    (relative-path, size, mtime) tuples of the files it contains — cheap and
    stable, and it changes on add/remove/edit without reading every byte.
    """
    if path.is_dir():
        h = hashlib.sha256()
        for f in sorted(p for p in path.rglob("*") if p.is_file()):
            try:
                st = f.stat()
            except OSError:
                continue
            h.update(str(f.relative_to(path)).encode("utf-8", "replace"))
            h.update(f"{st.st_size}:{st.st_mtime_ns}".encode())
        return h.hexdigest()
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        # Transient read failure during an editor's atomic-rename save — treat
        # as "no readable state yet"; the next poll picks up the new content.
        return ""


def watch(
    path: str | Path,
    *,
    interval: float = 1.0,
    scan_on_start: bool = True,
    stop: Callable[[], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[ChangeEvent]:
    """Yield a ChangeEvent every time the watched path's content changes.

    Args:
      interval: seconds between polls.
      scan_on_start: emit an initial event for the current state, so the user
        sees the baseline findings immediately (not only after the first edit).
      stop: optional predicate; when it returns True the loop ends cleanly.
      sleep: injectable for tests (defaults to time.sleep).

    The generator runs until `stop()` is true or it is closed. It never raises
    on a transient read error — it simply waits for the next stable state.
    """
    target = Path(path)
    last: str | None = None

    if scan_on_start:
        cur = _fingerprint(target)
        if cur:
            last = cur
            yield ChangeEvent(target, cur, None)

    while stop is None or not stop():
        sleep(interval)
        cur = _fingerprint(target)
        # Empty digest = unreadable mid-save; skip until it settles.
        if cur and cur != last:
            yield ChangeEvent(target, cur, last)
            last = cur
