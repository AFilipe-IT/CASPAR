"""
tests/test_watch.py
-------------------
The continuous-audit watch loop: emits a ChangeEvent when the watched config's
content changes, and only then. Detection is deterministic (content hash), so
the tests drive it without real time by injecting `sleep` and `stop`.
"""

from __future__ import annotations

from pathlib import Path

from config_assessment.core.watch import ChangeEvent, _fingerprint, watch


def _drain(gen, max_events):
    """Collect up to max_events, then stop the (otherwise infinite) generator."""
    out = []
    for ev in gen:
        out.append(ev)
        if len(out) >= max_events:
            gen.close()
            break
    return out


def test_emits_baseline_event_on_start(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text("ssl_protocols TLSv1.2;\n")
    # stop immediately after the start event: the loop body never runs.
    events = list(watch(f, stop=lambda: True, sleep=lambda _: None))
    assert len(events) == 1
    assert events[0].previous is None
    assert events[0].digest == _fingerprint(f)


def test_no_start_event_when_disabled(tmp_path):
    f = tmp_path / "c.conf"
    f.write_text("a\n")
    events = list(watch(f, scan_on_start=False, stop=lambda: True,
                        sleep=lambda _: None))
    assert events == []


def test_emits_on_content_change(tmp_path):
    f = tmp_path / "c.conf"
    f.write_text("v1\n")

    # Mutate the file on the 1st poll's sleep, then stop after we've seen it.
    state = {"polls": 0}

    def fake_sleep(_):
        state["polls"] += 1
        if state["polls"] == 1:
            f.write_text("v2\n")

    gen = watch(f, sleep=fake_sleep)
    events = _drain(gen, 2)   # baseline + one change

    assert len(events) == 2
    assert events[0].previous is None          # baseline
    assert events[1].previous == events[0].digest  # change references prior
    assert events[1].digest == _fingerprint(f)


def test_no_event_when_content_unchanged(tmp_path):
    f = tmp_path / "c.conf"
    f.write_text("same\n")

    # Never touch the file; stop after a few polls. Only the baseline is emitted.
    state = {"n": 0}

    def stop():
        state["n"] += 1
        return state["n"] > 5

    events = list(watch(f, sleep=lambda _: None, stop=stop))
    assert len(events) == 1
    assert events[0].previous is None


def test_rewriting_same_content_does_not_fire(tmp_path):
    f = tmp_path / "c.conf"
    f.write_text("x\n")

    def fake_sleep(_):
        f.write_text("x\n")   # touch, but identical bytes → same hash

    state = {"n": 0}

    def stop():
        state["n"] += 1
        return state["n"] > 4

    events = list(watch(f, sleep=fake_sleep, stop=stop))
    assert len(events) == 1   # baseline only; no spurious change events


def test_fingerprint_tracks_directory_edits(tmp_path):
    d = tmp_path / "conf.d"
    d.mkdir()
    (d / "a.conf").write_text("1\n")
    before = _fingerprint(d)
    (d / "b.conf").write_text("2\n")
    assert _fingerprint(d) != before


def test_unreadable_target_yields_empty_and_no_crash(tmp_path):
    missing = tmp_path / "nope.conf"
    # No baseline (empty digest) and the loop tolerates it without raising.
    events = list(watch(missing, stop=lambda: True, sleep=lambda _: None))
    assert events == []
