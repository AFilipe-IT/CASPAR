"""
tests/test_trend.py
-------------------
`sca trend` — configuration drift, quantified: one sparkline per input,
first→last score and net direction, built on the automatically-recorded
scan history.
"""

from __future__ import annotations

from click.testing import CliRunner

import cli.main as m
from cli.commands.report_cmds import _sparkline


def _seed_db(path, rows):
    """Insert minimal scan_results rows (schema-initialised via Database)."""
    from config_assessment.core.db.database import Database
    with Database(str(path)) as db:
        for i, (input_path, score, ts) in enumerate(rows):
            db._conn.execute(
                "INSERT INTO scan_results (id, target_name, input_path, "
                "input_hash, profile_av, profile_au, global_temporal_score, "
                "severity, timestamp) VALUES (?,?,?,?,?,?,?,?,?)",
                (f"id{i}", "nginx", input_path, "h", "N", "N", score,
                 "Medium", ts))
        db._conn.commit()


def test_sparkline_maps_scores_to_blocks():
    assert _sparkline([0.0]) == "▁"
    assert _sparkline([10.0]) == "█"
    assert len(_sparkline([1, 5, 9])) == 3


def test_trend_shows_worsening_input(tmp_path):
    db = tmp_path / "t.db"
    _seed_db(db, [("nginx.conf", 2.0, "2026-07-01T10:00:00Z"),
                  ("nginx.conf", 8.0, "2026-07-02T10:00:00Z")])
    res = CliRunner().invoke(m.cli, ["--db", str(db), "trend"])
    assert res.exit_code == 0, res.output
    assert "2.0 → 8.0" in res.output
    assert "risk increased" in res.output


def test_trend_shows_improvement_and_filters(tmp_path):
    db = tmp_path / "t.db"
    _seed_db(db, [("nginx.conf", 8.0, "2026-07-01T10:00:00Z"),
                  ("nginx.conf", 3.0, "2026-07-02T10:00:00Z"),
                  ("httpd.conf", 5.0, "2026-07-01T10:00:00Z"),
                  ("httpd.conf", 5.0, "2026-07-02T10:00:00Z")])
    res = CliRunner().invoke(m.cli, ["--db", str(db), "trend", "nginx"])
    assert res.exit_code == 0, res.output
    assert "risk reduced" in res.output
    assert "httpd.conf" not in res.output    # filtered out


def test_trend_needs_two_scans(tmp_path):
    db = tmp_path / "t.db"
    _seed_db(db, [("nginx.conf", 5.0, "2026-07-01T10:00:00Z")])
    res = CliRunner().invoke(m.cli, ["--db", str(db), "trend"])
    assert res.exit_code == 0
    assert "Not enough history" in res.output
