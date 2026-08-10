"""
config_assessment/core/watch.py
-------------------------------
Continuous configuration-audit loop. Watches a config file (or directory) and,
whenever its content changes, re-runs the deterministic scan and reports the
misconfigurations found and their impact — data already in the DB.

Design notes (keeps the CASPAR runtime invariants):
  * Deterministic detection — the loop only *triggers* re-scans; scoring stays
    the zero-LLM/zero-network `runtime.scan`.
  * No alerting side-channel beyond the terminal/log/notify the CLI already
    offers. A change → a re-scan → the findings on screen.
  * Polling (mtime + content hash), not inotify — works identically on native
    Linux, WSL2, and bind-mounted Docker volumes where inotify is unreliable.

The module itself is I/O-only: it computes *when* to re-scan and yields an
event. The CLI owns *what to print* (it reuses the normal scan renderer) and
*what to persist* — each event's ScanResult is saved under a shared watch
session id, so a run can be followed live from the console's Watch page —
so watch and scan never drift apart in how a finding looks or is stored.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator


@dataclass(frozen=True)
class ChangeEvent:
    """Emitted once per detected content change of the watched path."""
    path: Path
    digest: str          # content hash after the change
    previous: str | None  # content hash before the change (None on first sight)


def _digest_file(path: Path, h: "hashlib._Hash") -> bool:
    """Fold one file's bytes into *h*. False if it could not be read."""
    try:
        h.update(path.read_bytes())
        return True
    except OSError:
        return False


def _fingerprint(path: Path, extra: tuple[str, ...] = ()) -> str:
    """A content fingerprint of everything a scan of *path* would read.

    For a file: sha256 of its bytes. For a directory: sha256 over the sorted
    (relative-path, size, mtime) tuples of the files it contains — cheap and
    stable, and it changes on add/remove/edit without reading every byte.

    `extra` are the other files the scan actually read — an Apache
    `apache2.conf` pulls in ~36 of them through `Include`. They must be part
    of the fingerprint: a scan follows the includes, so a watch that hashes
    only the entry point reports findings it cannot see change. Fixing
    `ServerTokens` in `conf-available/security.conf` left `apache2.conf`
    byte-identical, so no event fired and the session sat on a stale score
    while still beating — indistinguishable from "your edit did nothing".

    The path is folded in beside the bytes so that a *rename* — same content,
    different file — still registers as a change.
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
        _digest_extra(h, extra, exclude={str(path)})
        return h.hexdigest()

    h = hashlib.sha256()
    if not _digest_file(path, h):
        # Transient read failure during an editor's atomic-rename save — treat
        # as "no readable state yet"; the next poll picks up the new content.
        return ""
    _digest_extra(h, extra, exclude={str(path)})
    return h.hexdigest()


def _digest_extra(h: "hashlib._Hash", extra: tuple[str, ...],
                   *, exclude: set[str]) -> None:
    """Fold the included files into *h*, sorted so the order is stable.

    An unreadable include is folded in as a marker rather than skipped: a file
    that becomes unreadable (deleted, permissions changed) is itself a change
    worth re-scanning for, and skipping it would make it invisible.
    """
    for name in sorted(set(extra) - exclude):
        h.update(name.encode("utf-8", "replace"))
        if not _digest_file(Path(name), h):
            h.update(b"\0<unreadable>")


def watch(
    path: str | Path,
    *,
    interval: float = 1.0,
    scan_on_start: bool = True,
    stop: Callable[[], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    included_files: Callable[[], Iterable[str]] | None = None,
) -> Iterator[ChangeEvent]:
    """Yield a ChangeEvent every time the watched path's content changes.

    Args:
      interval: seconds between polls.
      scan_on_start: emit an initial event for the current state, so the user
        sees the baseline findings immediately (not only after the first edit).
      stop: optional predicate; when it returns True the loop ends cleanly.
      sleep: injectable for tests (defaults to time.sleep).
      included_files: returns the other files a scan of *path* reads (an
        Apache entry point pulls in dozens via `Include`). Watching only the
        entry point misses edits to them, which is how a fix could land
        without the score ever moving. A callable rather than a fixed set
        because an edit can add or remove an include: it is re-consulted
        every poll so the watched set follows the config. Kept injectable so
        this module stays plugin-agnostic — the caller knows how to parse.

    The generator runs until `stop()` is true or it is closed. It never raises
    on a transient read error — it simply waits for the next stable state.
    """
    target = Path(path)
    last: str | None = None

    def _extra() -> tuple[str, ...]:
        # Never let a parse failure kill the loop: a config mid-edit can be
        # unparseable for a moment. Degrading to "entry point only" for that
        # tick is strictly better than ending the session, and the next poll
        # recovers the full set.
        if included_files is None:
            return ()
        try:
            return tuple(included_files())
        except Exception:                              # noqa: BLE001
            return ()

    if scan_on_start:
        cur = _fingerprint(target, _extra())
        if cur:
            last = cur
            yield ChangeEvent(target, cur, None)

    while stop is None or not stop():
        sleep(interval)
        cur = _fingerprint(target, _extra())
        # Empty digest = unreadable mid-save; skip until it settles.
        if cur and cur != last:
            yield ChangeEvent(target, cur, last)
            last = cur
