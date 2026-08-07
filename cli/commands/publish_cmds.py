"""
cli/commands/publish_cmds.py — `caspar publish`.

Publishes an already-produced ScanResult JSON file (from `caspar scan -r -f
json -o result.json`) to a platform API. Decoupled from `scan` on purpose —
see cli/_publish.py for the rationale — so old scans, offline scans, and
third-party results can all be published uniformly.

Registered on the group in cli/main.py.
"""

from __future__ import annotations

import sys

import click

from cli._publish import publish_scan_result


@click.command("publish")
@click.argument("result_path", metavar="RESULT_JSON")
@click.option("--api", "api_url", required=True,
              help="Platform ingest URL, e.g. "
                   "http://localhost:8000/api/v1/assets/<asset_id>/scans")
def publish(result_path, api_url) -> None:
    """Publish a previously-produced ScanResult JSON file to a platform API.

    \b
      caspar scan /etc/apache2/ -r -f json -o result.json
      CASPAR_API_KEY=... caspar publish result.json --api "http://host/api/v1/assets/<id>/scans"
    """
    ok = publish_scan_result(result_path, api_url)
    if ok:
        click.echo(click.style(f"  Published to {api_url}", fg="green"))
    else:
        click.echo(click.style(
            f"  Could not publish {result_path} to {api_url} (see warnings above)",
            fg="red"), err=True)
        sys.exit(1)
