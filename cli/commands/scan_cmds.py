"""
cli/commands/scan_cmds.py — `caspar scan` and `caspar watch`.

The two runtime entry points: the one-shot deterministic scan, and the
continuous watcher built on top of it. Registered on the group in cli/main.py.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import click

from cli._discovery import _discover_plugins
from cli._knowledge import _assess_unknown_directives
from cli._output import _print_result, _to_sarif, warn_if_inside_container

logger = logging.getLogger("ccss")


@click.command("scan")
@click.argument("input_path", metavar="CONFIG")
@click.option("--live", "-l", is_flag=True, default=False,
              help="Detect an installed service (e.g. --live apache2).")
@click.option("--report", "-r", is_flag=True, default=False,
              help="Save the report to a file.")
@click.option("--format", "-f", "fmt", default="html",
              type=click.Choice(["html", "dashboard", "json", "sarif"], case_sensitive=False),
              show_default=True)
@click.option("--output", "-o", default=None,
              help="Directory for reports (default: <project>/reports/).")
@click.option("--online", is_flag=True, default=False,
              help="Use online charts (ECharts via CDN) for the dashboard format.")
@click.option("--threshold", "-t", default=0.0, type=float,
              help="Exit 1 if score > threshold (CI/CD).")
@click.option("--exit-code", "differentiated_exit", is_flag=True, default=False,
              help="Exit 2 if any Critical issue is present, 1 if over "
                   "--threshold, 0 otherwise (finer CI control).")
@click.option("--suppress-file", "suppress_file", default=None,
              help="Suppression file (default .caspar-suppress.json if present) "
                   "— accepted-risk issues are hidden and excluded from scoring "
                   "of the exit code.")
@click.option("--service-version", "service_version", default=None,
              help="Service version (e.g. 2.4.58) to cross-reference with "
                   "CVEs/exploits. If omitted, it is auto-detected (Docker tag, "
                   "binary, config).")
@click.option("--assess-unknown", "assess_unknown", is_flag=True, default=False,
              help="Also run an LLM (Ollama) over UNCOVERED directives to guess "
                   "if they are misconfigurations. Non-deterministic, opt-in; "
                   "results are low-confidence candidates, never scored.")
@click.option("--docs", "docs_path", default=None,
              help="Extra service documentation (file/dir) to ground the "
                   "--assess-unknown LLM via RAG, on top of the benchmark.")
@click.option("--show-uncovered", "show_uncovered", is_flag=True, default=False,
              help="List every uncovered directive, not just the suspicious "
                   "ones (a real config has hundreds of benign unknowns).")
@click.option("--verbose", "-v", "verbose", is_flag=True, default=False,
              help="Full detail for every finding and attack chain. Without "
                   "it, scan prints an operational summary.")
@click.option("--show-chains", "show_chains", is_flag=True, default=False,
              help="Full attack-chain analysis (narratives and component "
                   "directives), without the per-finding detail of --verbose.")
@click.option("--profile", "env_profile", default=None,
              type=click.Choice(["production", "internal", "dev"]),
              help="Deployment profile — adjusts exposure (AV) used for scoring: "
                   "production=Network (default), internal=Adjacent, dev=Local.")
@click.option("--host", "host_label", default=None,
              help="Tag this scan as belonging to a host/OS instance (e.g. "
                   "--host web01). Groups this scan with others sharing the "
                   "same label under the Operating System dashboard level.")
@click.option("--publish-to", "publish_to", default=None,
              help="Convenience: publish this scan's result to a platform API "
                   "after scanning, e.g. http://host/api/v1/assets/<id>/scans "
                   "(same effect as `caspar scan ... -r -f json -o x.json && "
                   "caspar publish x.json --api <url>`, routed through the "
                   "same publishing code). Reads CASPAR_API_KEY from the "
                   "environment; best-effort, never fails the scan.")
@click.pass_context
def scan(ctx, input_path, live, report, fmt, output, threshold,
         differentiated_exit, suppress_file, online, service_version,
         assess_unknown, docs_path, show_uncovered, verbose, show_chains,
         env_profile, host_label, publish_to) -> None:
    """Analyse service configurations — 4 modes.

    \b
    Mode 1 — file:        caspar scan /tmp/httpd.conf
    Mode 2 — directory:   caspar scan /etc/apache2/
    Mode 3 — live service: caspar scan --live apache2
    Mode 4 — Docker:      caspar scan docker://httpd:2.4
    """
    from config_assessment.core.db.database import Database
    from config_assessment.core.input_resolver import resolve
    from config_assessment.core import runtime

    _discover_plugins()
    db_path: str = ctx.obj["db_path"]

    if not Path(db_path).exists():
        click.echo(
            click.style(f"DB '{db_path}' not found.\n", fg="yellow") +
            "Run: " + click.style("caspar build --benchmark <pdf>", bold=True),
            err=True,
        )
        sys.exit(2)

    try:
        resolved = resolve(input_path, live=live)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)

    # Show what was detected
    if resolved.mode == "live":
        v = resolved.metadata.get("version", "")
        vs = f" {v}" if v and v != "unknown" else ""
        click.echo(click.style(f"  Service: {resolved.metadata.get('service', '')}{vs}", fg="cyan"))
        click.echo(click.style(f"  Config: {resolved.path}", dim=True))
        # O --live lê a configuração em disco, e continua a funcionar com o
        # serviço parado — de propósito. O que faltava era dizê-lo: sem este
        # aviso o scan devolve um score plausível de um serviço em baixo, e
        # quem estiver a degradar a configuração para ver o score mexer conclui
        # que é o CASPAR que não reage. `running` é None quando não há systemd
        # (containers) — aí a pergunta não se põe e não avisamos.
        if resolved.metadata.get("running") is False:
            click.echo(click.style(
                "  ⚠ O serviço não está a correr — a configuração em disco foi "
                "lida na mesma.\n"
                "    O score é da configuração, não de um serviço activo. Um "
                "`reload` falhado\n"
                "    significa que estas alterações ainda não estão em vigor.",
                fg="yellow"), err=True)
        click.echo()
    elif resolved.mode == "docker":
        click.echo(click.style(f"  Image: {resolved.metadata.get('image', '')}", fg="cyan"))
        click.echo()
    elif resolved.mode == "directory":
        click.echo(click.style(
            f"  Dir: {resolved.metadata.get('root_dir', '')}  [{resolved.metadata.get('entry_file', '')}]",
            fg="cyan",
        ))
        click.echo()

    _deferred_cleanup = resolved.cleanup if resolved.cleanup else None
    try:
        with Database(db_path) as db:
            # Precedência: --service-version explícito > versão do resolver (--live).
            # Sem nenhuma, o runtime auto-detecta (tag Docker, binário, config).
            detected_version = (service_version
                                or resolved.metadata.get("version") or None)
            if detected_version == "unknown":
                detected_version = None
            image_hint = resolved.metadata.get("image")
            result = runtime.scan(resolved.path, db, version=detected_version,
                                  image=image_hint, env_profile=env_profile)
            # Record the scan for history/trending (#4). Best-effort — a failure
            # to persist history must never break the scan itself.
            try:
                host_id = db.upsert_host(host_label) if host_label else None
                db.save_scan_result(result, host_id=host_id)
            except Exception as exc:
                logger.warning("Could not save scan history: %s", exc)

            if publish_to:
                from cli._publish import publish_scan_result
                publish_scan_result(result, publish_to)
    except Exception:
        if _deferred_cleanup:
            _deferred_cleanup()
        raise

    # Apply accepted-risk suppressions (#2): hide matching issues and drop them
    # from the exit-code decision. Only loads a file if given, or the default
    # exists — no surprise filtering.
    suppressed_issues: list = []
    from config_assessment.reports.scan_features import SuppressionStore
    _supp_path = suppress_file or SuppressionStore.DEFAULT_PATH
    if suppress_file or Path(_supp_path).exists():
        store = SuppressionStore(_supp_path)
        kept = []
        for issue in result.issues:
            i_dict = {"directive": issue.directive, "bad_value": issue.bad_value}
            if store.is_suppressed(i_dict):
                suppressed_issues.append(issue)
            else:
                kept.append(issue)
        if suppressed_issues:
            result.issues = kept

    # Layer 3 of unknown-directive detection (opt-in, non-deterministic): assess
    # the surfaced UNCOVERED directives with an LLM grounded in RAG context
    # (benchmark + optional --docs). Auto-fires only when there ARE unknowns.
    # Never touches the deterministic scores — fills each unknown's llm_* fields.
    if assess_unknown and result.unknown_directives:
        _assess_unknown_directives(result, docs_path)

    _print_result(result, resolved=resolved, show_uncovered=show_uncovered,
                  verbose=verbose, show_chains=show_chains)
    if suppressed_issues:
        click.echo(click.style(
            f"  ({len(suppressed_issues)} issue(s) suppressed via {_supp_path})",
            dim=True))
        click.echo()

    if report:
        # Where reports go, in order of precedence:
        #   1. explicit -o/--output
        #   2. $CASPAR_REPORTS_DIR (the Docker image sets this to the mounted
        #      /reports volume, so reports survive a --rm container)
        #   3. a reports/ dir next to the package (native use / dev)
        if output:
            od = Path(output)
        elif os.environ.get("CASPAR_REPORTS_DIR"):
            od = Path(os.environ["CASPAR_REPORTS_DIR"])
        else:
            od = Path(__file__).resolve().parent.parent.parent / "reports"
        # A assessment already ran and its output is on screen; failing to
        # create the directory must not bury that behind a traceback. The
        # read-only case is called out by name because it is the one a Docker
        # user hits: the wrapper mounts the working directory read-only unless
        # the command asks to write there.
        try:
            od.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            hint = ""
            if exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
                hint = ("\n  Drop -o and the report lands in the reports "
                        "directory, or point -o at a writable path.")
            raise click.ClickException(
                f"cannot create report directory '{od}': {exc.strerror}{hint}"
            ) from exc

        # Only an explicit -o can land outside the bound directories; the two
        # fallbacks above are the reports volume and a native-install path.
        if output:
            warn_if_inside_container(od, what="report")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = (
            input_path
            .replace("://", "_").replace("/", "_").replace(":", "_")
            .strip("_")[:30]
        ) or "scan"

        if fmt == "html":
            from config_assessment.reports.report_html import generate_html
            p = od / f"ccss_{stem}_{ts}.html"
            p.write_text(generate_html(result, resolved=resolved), encoding="utf-8")
            click.echo(f"  HTML: {click.style(str(p), fg='cyan')}")
        elif fmt == "dashboard":
            if online:
                from config_assessment.reports.report_dashboard_online import generate_dashboard_online as _gen_dash
                _suffix = "dashboard_online"
            else:
                from config_assessment.reports.report_dashboard import generate_dashboard as _gen_dash
                _suffix = "dashboard"
            p = od / f"ccss_{stem}_{ts}_{_suffix}.html"
            p.write_text(_gen_dash(result, resolved=resolved), encoding="utf-8")
            _label = "Dashboard (online)" if online else "Dashboard"
            click.echo(f"  {_label}: {click.style(str(p), fg='cyan')}")
        elif fmt == "json":
            p = od / f"ccss_{stem}_{ts}.json"
            p.write_text(result.model_dump_json(indent=2), encoding="utf-8")
            click.echo(f"  JSON: {click.style(str(p), fg='cyan')}")
        else:
            p = od / f"ccss_{stem}_{ts}.sarif"
            p.write_text(json.dumps(_to_sarif(result), indent=2), encoding="utf-8")
            click.echo(f"  SARIF: {click.style(str(p), fg='cyan')}")
        click.echo()

    # Cleanup temp files (e.g. Docker extraction dir) AFTER reports are written,
    # so the HTML snippet feature can still read the config file.
    if _deferred_cleanup:
        _deferred_cleanup()

    # Exit-code policy (#11). Default keeps the old contract (exit 1 over
    # threshold). --exit-code adds a Critical→2 tier for finer CI control.
    from config_assessment.core.ccss import severity_label
    from config_assessment.reports.scan_features import (
        classify_exit, EXIT_CRITICAL, EXIT_THRESHOLD)
    sevs = [severity_label(i.temporal_score) for i in result.issues]

    if differentiated_exit:
        code = classify_exit(sevs, result.global_temporal_score, threshold)
        if code == EXIT_CRITICAL:
            click.echo(click.style(
                "  Critical issue present — FAIL (exit 2)", fg="bright_red",
                bold=True), err=True)
        elif code == EXIT_THRESHOLD:
            click.echo(click.style(
                f"  Score {result.global_temporal_score:.1f} > {threshold:.1f} "
                "— FAIL (exit 1)", fg="red", bold=True), err=True)
        if code:
            sys.exit(code)
    elif threshold > 0.0 and result.global_temporal_score > threshold:
        click.echo(
            click.style(f"  Score {result.global_temporal_score:.1f} > {threshold:.1f} — FAIL", fg="red", bold=True),
            err=True,
        )
        sys.exit(1)


@click.command("watch")
@click.argument("input_path", metavar="CONFIG")
@click.option("--live", "-l", is_flag=True, default=False,
              help="CONFIG is an installed service name (e.g. apache2); watch "
                   "its config directory. Resolves the path like `scan --live`.")
@click.option("--service-version", "service_version", default=None,
              help="Service version for CVE/exploit cross-reference (the Docker "
                   "wrapper injects this from the host in --live mode).")
@click.option("--interval", "-i", default=1.0, type=float, show_default=True,
              help="Seconds between checks for a config change.")
@click.option("--profile", "env_profile", default=None,
              type=click.Choice(["production", "internal", "dev"]),
              help="Environment baseline for scoring (as in scan).")
@click.option("--host", "host_label", default=None,
              help="Tag this watch session's scans as belonging to a host/OS "
                   "instance (as in scan --host), so they appear under that "
                   "host's Operating System dashboard page too.")
@click.option("--log", "log_path", default=None, metavar="FILE",
              help="Append alerts to FILE instead of the terminal (for "
                   "background use: `caspar watch cfg --log watch.log &`).")
@click.option("--notify", is_flag=True, default=False,
              help="Also broadcast worsening alerts as a system notification "
                   "(wall / notify-send), so they reach any terminal.")
@click.pass_context
def watch(ctx, input_path, live, service_version, interval, env_profile,
          host_label, log_path, notify) -> None:
    """Continuously audit a config: alert on screen whenever it changes.

    Watches a file, a directory, or (with --live) an installed service's config
    directory. On every change it re-runs the deterministic scan and prints ONE
    compact log line: the new score and what changed — red when risk worsened,
    green when it improved. Runs in the background with the terminal free.

    With --log, alerts are appended to a file and the terminal stays clean —
    ideal for `caspar watch cfg --log watch.log &`; read it with `cat watch.log`.

    Full detail is intentionally omitted — run `caspar scan <config>` for the
    complete report. Scoring comes from the DB (zero-LLM, zero-network); each
    event is also persisted under a session id, so the run can be followed
    live from the dashboard's Watch page while it's running.

    \b
    caspar watch /etc/nginx/nginx.conf
    caspar watch /etc/apache2/ --profile production
    caspar watch --live apache2                    # find + watch its config dir
    caspar watch nginx.conf --log watch.log &      # background, terminal free
    """
    import time
    from uuid import uuid4

    from config_assessment.core.db.database import Database
    from config_assessment.core.input_resolver import resolve
    from config_assessment.core.watch import watch as watch_loop
    from config_assessment.core.watch_loop import included_files
    from config_assessment.core.watch_loop import run_watch_tick

    _discover_plugins()
    db_path: str = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(click.style(f"DB '{db_path}' not found.", fg="yellow"), err=True)
        sys.exit(2)

    # Resolve once to fail fast. With --live, CONFIG is a service name resolved
    # to its config dir (same mapping as `scan --live`); otherwise a disk path.
    try:
        resolved = resolve(input_path, live=live)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(2)

    # Label: the service name in --live mode (clearer than the entry file's
    # basename), otherwise the path's basename.
    if live:
        name = resolved.metadata.get("service") or input_path
        click.echo(click.style(
            f"  Service: {name}  ({resolved.path})", fg="cyan"))
        # Vale ainda mais aqui do que no `scan`: quem põe um watch a correr está
        # à espera de ver o score mexer quando altera a configuração. Com o
        # serviço parado o watch funciona — vigia os ficheiros — mas um `reload`
        # falhado não põe nada em vigor, e a leitura fácil é que o watch está
        # avariado.
        if resolved.metadata.get("running") is False:
            click.echo(click.style(
                "  ⚠ O serviço não está a correr. O watch segue as alterações "
                "aos ficheiros na mesma,\n"
                "    mas o que fores medindo não está em vigor até o serviço "
                "arrancar.", fg="yellow"), err=True)
    else:
        name = Path(resolved.path).name

    # --log routes alerts to a file (append, colourless so it stays greppable).
    # The terminal then only gets a one-line pointer, so it stays free.
    _log_fh = None
    if log_path:
        try:
            _log_fh = open(log_path, "a", encoding="utf-8", buffering=1)  # line-buffered
        except OSError as e:
            # Common under the Docker wrapper: an absolute host path like
            # ~/watch.log isn't visible inside the container (only the mounted
            # cwd is). Point the user at a path that works, don't dump a trace.
            click.echo(click.style(
                f"Cannot write log to '{log_path}': {e.strerror}.", fg="red"),
                err=True)
            click.echo(
                "  In Docker, the log must land in the mounted working dir — "
                "use a path inside it, e.g. " +
                click.style("--log watch.log", bold=True) +
                " (relative), then read it with " +
                click.style("cat watch.log", bold=True) + ".", err=True)
            sys.exit(2)
        click.echo(
            f"  {click.style('○', fg='cyan')} watching {name} in background — "
            f"alerts → {click.style(log_path, bold=True)}"
            + click.style("  (stop: docker stop caspar-watch, or Ctrl-C)", dim=True))

    def _emit(styled_line: str) -> None:
        if _log_fh is not None:
            _log_fh.write(click.unstyle(styled_line) + "\n")
        else:
            click.echo("  " + styled_line)

    # Version for CVE/exploit cross-reference: explicit flag wins, else the
    # resolver's --live detection (same precedence as `scan`).
    _version = service_version or resolved.metadata.get("version") or None
    if _version == "unknown":
        _version = None

    # One session id for this whole watch invocation — every persisted event
    # shares it, so the dashboard's Watch page can group them and tell one
    # "caspar watch" run apart from another over the same input.
    session_id = str(uuid4())
    with Database(db_path) as db:
        host_id = db.upsert_host(host_label) if host_label else None
        db.touch_watch_heartbeat(session_id)   # live immediately, not after 1 interval

    def _scan():
        # Shared with the API's watch runner (config_assessment/api/
        # watch_runner.py) so both paths scan and persist identically.
        with Database(db_path) as db:
            return run_watch_tick(db, resolved.path, session_id=session_id,
                                  interval=interval, host_id=host_id,
                                  version=_version, env_profile=env_profile)

    # watch_loop only yields on a real content change — a quiet, unchanged
    # config would otherwise go stale on the dashboard within one interval
    # even though this process is still running. Piggyback a heartbeat touch
    # on its injectable `sleep`, which fires every poll tick regardless of
    # whether anything changed.
    def _sleep_and_heartbeat(seconds: float) -> None:
        time.sleep(seconds)
        with Database(db_path) as db:
            db.touch_watch_heartbeat(session_id)

    prev = None   # previous ScanResult, for the delta
    try:
        for event in watch_loop(resolved.path, interval=interval,
                                sleep=_sleep_and_heartbeat,
                                included_files=lambda: included_files(resolved.path)):
            result = _scan()
            ts = datetime.now().strftime("%H:%M:%S")
            if event.previous is None:
                base = (
                    f"{click.style(f'[{ts}]', dim=True)} "
                    f"{click.style('○', fg='cyan')} watching {name} — "
                    f"baseline {result.global_temporal_score:.1f}/10 "
                    f"[{result.severity}]")
                # In terminal mode also show the poll cadence; in --log the
                # pointer line above already covered how to stop.
                if _log_fh is None:
                    base += click.style(
                        f"  (every {interval:g}s · Ctrl-C to stop)", dim=True)
                _emit(base)
            else:
                _emit(_watch_alert_line(ts, name, result, prev))
                # System notification on a WORSENING change, so the alert reaches
                # whoever is editing the config in another terminal.
                if notify and result.global_temporal_score > \
                        (prev.global_temporal_score if prev else 0.0) + 0.05:
                    _notify_system(
                        f"CASPAR: {name} risk {prev.global_temporal_score:.1f}"
                        f"→{result.global_temporal_score:.1f} [{result.severity}]")
            prev = result
    except KeyboardInterrupt:
        click.echo(click.style("\n  Stopped.", dim=True))
    finally:
        if _log_fh is not None:
            _log_fh.close()


def _notify_system(message: str) -> None:
    """Best-effort system notification, so an alert reaches any terminal.

    Three layers, all best-effort (a failure never breaks the watch):
      1. `notify-send` — desktop popup, if a GUI is present.
      2. `wall` — the standard util-linux broadcast (all the user's login
         terminals); works on a real Linux server / over SSH.
      3. Direct write to each writable /dev/pts/* — what wall does underneath,
         but WITHOUT needing utmp to be populated. This is the fallback that
         makes --notify work where wall can't: WSL2, containers, minimal
         systems with no login records."""
    import shutil
    import subprocess
    banner = f"\n\N{WARNING SIGN}  {message}\n"

    if shutil.which("notify-send"):
        try:
            subprocess.run(["notify-send", "CASPAR", message],
                           timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            pass

    delivered = False
    if shutil.which("wall"):
        try:
            # wall -n suppresses the banner header if permitted; ignore failure.
            subprocess.run(["wall"], input=message, text=True,
                           timeout=5, check=False)
            delivered = True
        except (OSError, subprocess.SubprocessError):
            pass

    # Fallback: write straight to the active PTYs. Independent of utmp, so it
    # reaches other terminals on WSL2 / in containers where wall stays silent.
    _write_to_ptys(banner)


def _write_to_ptys(text: str) -> None:
    """Write text to every /dev/pts/* we can open for writing (best-effort)."""
    import os
    import glob
    my_tty = None
    try:
        my_tty = os.ttyname(1)   # don't double-print on our own terminal
    except OSError:
        pass
    for pts in glob.glob("/dev/pts/[0-9]*"):
        if pts == my_tty:
            continue
        try:
            fd = os.open(pts, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            continue          # not ours / not writable — skip
        try:
            os.write(fd, text.encode("utf-8", "replace"))
        except OSError:
            pass
        finally:
            os.close(fd)


def _watch_alert_line(ts, name, result, prev) -> str:
    """One compact, colored log line describing a config change.

    Red when risk worsened (score up), green when it improved (score down),
    neutral when unchanged. Summarises the score move, the net issue
    count change, and the single worst driver — never the full report."""
    score = result.global_temporal_score
    old = prev.global_temporal_score if prev else 0.0
    worse = score > old + 0.05
    better = score < old - 0.05
    color = "red" if worse else "green" if better else "white"
    icon = "⚠" if worse else "✓" if better else "•"

    # Score move: "0.0 → 6.1".
    move = f"{old:.1f} → {score:.1f}" if prev else f"{score:.1f}"

    # Net issue delta and the newly-appearing worst issue, if any.
    prev_dirs = {i.directive for i in prev.issues} if prev else set()
    new_issues = [i for i in result.issues if i.directive not in prev_dirs]
    net = len(result.issues) - (len(prev.issues) if prev else 0)
    net_str = f"{net:+d} issue" + ("s" if abs(net) != 1 else "")

    parts = [
        click.style(f"[{ts}]", dim=True),
        click.style(f"{icon} {name}", fg=color, bold=worse),
        click.style(f"{move}  [{result.severity}]", fg=color, bold=worse),
        click.style(net_str, fg=color),
    ]
    if new_issues:
        top = max(new_issues, key=lambda i: i.temporal_score)
        val = f"={top.bad_value}" if getattr(top, "bad_value", "") else ""
        parts.append(click.style(
            f"↑ {top.directive}{val} ({top.temporal_score:.1f})", fg=color))
    return "  ".join(parts)
