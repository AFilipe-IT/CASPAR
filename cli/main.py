"""
cli/main.py — CASPAR CLI entry point.

  caspar scan /tmp/httpd.conf
  caspar scan /etc/apache2/
  caspar scan --live apache2
  caspar scan docker://httpd:2.4
  caspar scan docker://ccss-test-apache:vulnerable --report --format html

This module only assembles the CLI: the `cli` click group, command
registration, and logging setup. The implementation lives in:

  cli/_output.py             terminal rendering + SARIF
  cli/_discovery.py          plugin auto-discovery
  cli/_knowledge.py          build-time RAG knowledge base
  cli/commands/scan_cmds.py    scan, watch
  cli/commands/publish_cmds.py publish
  cli/commands/plugin_cmds.py  plugin add / fetch
  cli/commands/build_cmds.py   build, fetch-exploits, refresh
  cli/commands/report_cmds.py  targets, diff, badge, explain, history, report
  cli/commands/manage_cmds.py  suppress, doctor, fix, promote

Historical names are re-exported below, so `from cli.main import X` and
`import cli.main as m; m.X` keep working.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import click

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.WARNING,
    stream=sys.stderr,
)
logger = logging.getLogger("ccss")

# ── Re-exports (compatibility: cli.main was a single module for a long time) ──
from cli._discovery import _plugin_dirs, _discover_plugins            # noqa: E402,F401
from cli._output import (                                             # noqa: E402,F401
    _sev_color, _bar, _dedup_issues, _dedup_chains, _print_result,
    _print_unknown_directives, _print_issue_compact, _print_chain_compact,
    _to_sarif,
)
from cli._knowledge import (                                          # noqa: E402,F401
    _find_benchmark_file, _find_knowledge_docs, _CombinedRAG,
    _assess_unknown_directives, _ingest_manual,
)
from cli.commands.scan_cmds import (                                  # noqa: E402,F401
    scan, watch, _notify_system, _write_to_ptys, _watch_alert_line,
)
from cli.commands.publish_cmds import publish                          # noqa: E402,F401
from cli.commands.plugin_cmds import plugin_group, plugin_add, plugin_fetch  # noqa: E402,F401
from cli.commands.build_cmds import build, fetch_exploits, refresh    # noqa: E402,F401
from cli.commands.report_cmds import (                                # noqa: E402,F401
    targets, diff, badge, explain, history, report, trend,
)
from cli.commands.manage_cmds import suppress, doctor, fix, promote   # noqa: E402,F401


# ── CLI ────────────────────────────────────────────────────────────

@click.group()
@click.option("--db", default=lambda: os.environ.get("CASPAR_DB", "ccss.db"),
              show_default="ccss.db (or $CASPAR_DB)")
@click.option("--verbose", "-v", is_flag=True)
@click.pass_context
def cli(ctx: click.Context, db: str, verbose: bool) -> None:
    """CASPAR — Configuration Analysis, Security Posture Assessment and Reporting.

    Security configuration scoring framework based on CCSS/NISTIR 7502.
    """
    if verbose:
        logging.getLogger().setLevel(logging.INFO)
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db


for _cmd in (
    scan, watch, publish,                          # runtime
    plugin_group,                                  # plugin add / fetch
    build, fetch_exploits, refresh,                # build-time
    targets, diff, badge, explain, history, report, trend,  # reporting
    suppress, doctor, fix, promote,                # state management
):
    cli.add_command(_cmd)


if __name__ == "__main__":
    cli()
