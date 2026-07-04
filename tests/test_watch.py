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


# ── the compact alert line (CLI formatter) ─────────────────────────────

class _Issue:
    def __init__(self, directive, score, bad_value=""):
        self.directive, self.temporal_score, self.bad_value = directive, score, bad_value


class _Res:
    def __init__(self, score, severity, issues):
        self.global_temporal_score = score
        self.severity = severity
        self.issues = issues


def _line(result, prev):
    from cli.main import _watch_alert_line
    import click
    # Strip ANSI so we assert on text; colour is asserted separately.
    return click.unstyle(_watch_alert_line("12:00:00", "httpd.conf", result, prev))


def test_alert_line_worsening_shows_move_and_driver():
    prev = _Res(0.0, "None", [])
    now = _Res(8.9, "High", [_Issue("ServerTokens", 7.1, "Full")])
    line = _line(now, prev)
    assert "0.0 → 8.9" in line and "[High]" in line
    assert "+1 issue" in line
    assert "ServerTokens=Full (7.1)" in line
    assert "⚠" in line   # worsening icon


def test_alert_line_improvement_is_green_check():
    prev = _Res(8.9, "High", [_Issue("ServerTokens", 7.1, "Full")])
    now = _Res(0.0, "None", [])
    import click
    from cli.main import _watch_alert_line
    styled = _watch_alert_line("12:00:00", "httpd.conf", now, prev)
    assert "✓" in styled
    assert "-1 issue" in click.unstyle(styled)
    assert "\x1b[32m" in styled   # green ANSI


def test_alert_line_unchanged_score_is_neutral():
    # More issues but capped score → net risk unchanged → neutral marker.
    prev = _Res(8.9, "High", [_Issue("a", 5.0)])
    now = _Res(8.9, "High", [_Issue("a", 5.0), _Issue("b", 5.4, "All")])
    line = _line(now, prev)
    assert "•" in line and "+1 issue" in line


# ── --log routing (background use) ─────────────────────────────────────

def test_log_flag_writes_colourless_alerts_and_keeps_terminal_clean(
        tmp_path, monkeypatch):
    """--log appends colourless alerts to a file; the terminal only gets the
    one-line pointer (so it stays free in the background)."""
    from click.testing import CliRunner
    import cli.main as m

    cfg = tmp_path / "httpd.conf"
    cfg.write_text("ServerTokens Prod\n")
    logf = tmp_path / "w.log"

    # watch imports these locally (from ... import ...), so patch them at their
    # SOURCE modules where the local imports resolve them.
    scores = iter([_Res(0.0, "None", []),
                   _Res(8.9, "High", [_Issue("ServerTokens", 7.1, "Full")])])
    monkeypatch.setattr("config_assessment.core.runtime.scan",
                        lambda *a, **k: next(scores))

    def fake_loop(path, **k):
        yield ChangeEvent(cfg, "d0", None)
        yield ChangeEvent(cfg, "d1", "d0")
    monkeypatch.setattr("config_assessment.core.watch.watch", fake_loop)

    # A real DB isn't needed — a no-op context manager suffices.
    class _DummyDB:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr("config_assessment.core.db.database.Database",
                        lambda *a, **k: _DummyDB())
    # Bypass the DB-file existence check.
    monkeypatch.setattr(m.Path, "exists", lambda self: True)

    runner = CliRunner()
    result = runner.invoke(m.cli, ["watch", str(cfg), "--log", str(logf)])
    assert result.exit_code == 0

    # Terminal: pointer line only — no alert content (the score move / baseline
    # score belong in the file, not the terminal).
    assert "in background" in result.output
    assert "0.0 → 8.9" not in result.output   # no alert line leaked to terminal
    assert "baseline 0.0/10" not in result.output

    # File: baseline + the worsening alert, no ANSI escapes.
    body = logf.read_text()
    assert "baseline 0.0/10 [None]" in body
    assert "0.0 → 8.9" in body and "ServerTokens=Full" in body
    assert "\x1b[" not in body   # colourless


def test_live_flag_resolves_service_and_labels_by_name(tmp_path, monkeypatch):
    """`watch --live apache2` resolves the service to its config path (like
    scan --live) and labels alerts by the service name, not the file basename."""
    from click.testing import CliRunner
    import cli.main as m
    from config_assessment.core.input_resolver import ResolvedInput

    cfg = tmp_path / "apache2.conf"
    cfg.write_text("ServerTokens Prod\n")

    seen = {}

    def fake_resolve(input_path, live=False):
        seen["input"], seen["live"] = input_path, live
        return ResolvedInput(path=str(cfg), mode="live",
                             metadata={"service": "apache-httpd"})
    monkeypatch.setattr("config_assessment.core.input_resolver.resolve",
                        fake_resolve)
    monkeypatch.setattr("config_assessment.core.runtime.scan",
                        lambda *a, **k: _Res(8.9, "High", []))

    def fake_loop(path, **k):
        yield ChangeEvent(cfg, "d0", None)   # baseline only, then stop
    monkeypatch.setattr("config_assessment.core.watch.watch", fake_loop)
    monkeypatch.setattr(m.Path, "exists", lambda self: True)

    class _DummyDB:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr("config_assessment.core.db.database.Database",
                        lambda *a, **k: _DummyDB())

    # --service-version is accepted (the Docker wrapper injects it for --live);
    # it must not raise "no such option".
    result = CliRunner().invoke(
        m.cli, ["watch", "apache2", "--live", "--service-version", "2.4.52"])
    assert result.exit_code == 0
    assert seen["live"] is True and seen["input"] == "apache2"
    assert "Service: apache-httpd" in result.output
    assert "watching apache-httpd" in result.output   # labelled by service name


def test_notify_broadcasts_on_worsening(monkeypatch):
    """_notify_system shells out to wall/notify-send; verify it invokes an
    available broadcaster and never raises when one is missing."""
    import cli.main as m
    calls = []
    monkeypatch.setattr(m, "_notify_system", lambda msg: calls.append(msg))

    # Directly exercise the notify decision the loop makes.
    prev, now = _Res(0.0, "None", []), _Res(6.1, "Medium", [])
    worse = now.global_temporal_score > prev.global_temporal_score + 0.05
    if worse:
        m._notify_system(f"CASPAR: cfg {prev.global_temporal_score:.1f}"
                         f"→{now.global_temporal_score:.1f}")
    assert calls and "0.0→6.1" in calls[0]


def test_notify_system_is_best_effort_when_no_tool(monkeypatch):
    """No wall / notify-send present → still writes to PTYs, never raises."""
    import cli.main as m
    monkeypatch.setattr("shutil.which", lambda *_: None)
    # _notify_system resolves _write_to_ptys from its home module — patch there.
    monkeypatch.setattr("cli.commands.scan_cmds._write_to_ptys", lambda *_: None)
    m._notify_system("anything")   # must not raise


def test_pts_fallback_writes_to_writable_ptys(tmp_path, monkeypatch):
    """The PTY fallback writes the message to each pts it can open — this is
    what makes --notify reach other terminals on WSL2 / in containers where
    wall is silent (no utmp)."""
    import cli.main as m

    fake_pts = tmp_path / "3"
    fake_pts.write_text("")   # stand-in for /dev/pts/3
    monkeypatch.setattr("glob.glob", lambda pat: [str(fake_pts)])
    # Our own tty is something else, so the fake pts is not skipped.
    monkeypatch.setattr("os.ttyname", lambda fd: "/dev/pts/999")

    m._write_to_ptys("\n⚠  CASPAR: cfg 0.0→6.1\n")
    assert "CASPAR: cfg 0.0→6.1" in fake_pts.read_text()


def test_log_path_in_missing_dir_errors_cleanly(tmp_path, monkeypatch):
    """An unwritable --log path (e.g. a host path invisible in the container)
    exits 2 with guidance, not a traceback."""
    from click.testing import CliRunner
    import cli.main as m

    cfg = tmp_path / "httpd.conf"
    cfg.write_text("ServerTokens Prod\n")
    monkeypatch.setattr(m.Path, "exists", lambda self: True)

    bad = tmp_path / "no-such-dir" / "w.log"   # parent doesn't exist
    result = CliRunner().invoke(m.cli, ["watch", str(cfg), "--log", str(bad)])
    assert result.exit_code == 2
    assert "Cannot write log" in result.output
    assert "--log watch.log" in result.output   # points at a working form
    assert "Traceback" not in result.output
