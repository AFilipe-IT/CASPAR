"""
cli/commands/serve_cmds.py — `caspar serve`.

Launches the REST API (config_assessment/api/) and the CVM Console
(frontend/dist) in one Uvicorn process, both mounted on the same FastAPI app
so they share one CVM Core and one DB connection pool.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address. Use 0.0.0.0 to expose beyond localhost.")
@click.option("--port", default=2027, show_default=True, type=int)
@click.option("--reload", is_flag=True, default=False,
              help="Auto-reload on source changes (development only).")
@click.pass_context
def serve(ctx: click.Context, host: str, port: int, reload: bool) -> None:
    """Serve the REST API + CVM Console (same CVM Core as `caspar scan`).

    \b
    Swagger UI:   http://127.0.0.1:2027/docs
    CVM Console:  http://127.0.0.1:2027/app
    """
    # As dependências do servidor são um extra opcional: quem só usa a CLI não
    # precisa de instalar fastapi/uvicorn. Sem esta captura, um `pip install -e .`
    # sem o extra (o que o install-native.sh evita, mas quem instala à mão faz)
    # rebentava com um traceback de ModuleNotFoundError, que não diz a ninguém
    # qual é o comando que falta.
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        click.echo(
            click.style(f"O 'caspar serve' precisa do extra [api] (falta: {exc.name}).\n",
                        fg="yellow") +
            "Instale com: " + click.style('pip install -e ".[api]"', bold=True) + "\n"
            "A CLI (scan, build, plugin, report) funciona sem ele.",
            err=True,
        )
        sys.exit(2)

    db_path: str = ctx.obj["db_path"]
    if not Path(db_path).exists():
        click.echo(
            click.style(f"DB '{db_path}' not found.\n", fg="yellow") +
            "Run: " + click.style("caspar build --benchmark <pdf>", bold=True),
            err=True,
        )
        sys.exit(2)

    click.echo(click.style(f"  DB: {db_path}", dim=True))
    click.echo(click.style(f"  Swagger UI:  http://{host}:{port}/docs", fg="cyan"))
    # Announcing the console unconditionally sent people to a URL that 404s
    # when the bundle isn't there. The mount is soft-failing by design, so the
    # startup line is the only place the absence can be reported.
    if _console_dist().is_dir():
        click.echo(click.style(f"  CVM Console: http://{host}:{port}/app", fg="cyan"))
    else:
        click.echo(click.style(
            "  CVM Console: unavailable — the frontend bundle is missing.\n"
            "               Reinstall (./install-native.sh) or use the Docker "
            "image, which ships it.", fg="yellow"))
    click.echo()

    if reload:
        # Uvicorn's reloader re-imports the app by string path; db_path must
        # travel via env var since a fresh process re-executes create_app().
        import os
        os.environ["CASPAR_DB"] = db_path
        uvicorn.run("cli.commands.serve_cmds:_reload_app", host=host, port=port, reload=True, factory=True)
    else:
        from config_assessment.api.app import create_app
        app = create_app(db_path=db_path)
        _mount_frontend(app)
        uvicorn.run(app, host=host, port=port)


def _console_dist() -> Path:
    """Where the built console lives, for both the mount and the startup line.

    One function so `serve` cannot advertise a console the mount then declines
    to serve — the two used to derive the path independently."""
    return Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _mount_frontend(app) -> None:
    """Mount the built CVM React console (frontend/dist) at /app, if present.

    The bundle is committed to the repository and the Docker image builds its
    own, so in both supported installations it is there. Soft-failing covers
    the remaining case — a source tree whose dist was cleaned — where the REST
    API is still useful on its own; `serve` reports the absence on startup."""
    dist_dir = _console_dist()
    if not dist_dir.is_dir():
        return

    from fastapi.staticfiles import StaticFiles
    from starlette.exceptions import HTTPException as StarletteHTTPException
    from starlette.types import Scope

    class SpaStaticFiles(StaticFiles):
        """StaticFiles with an index.html fallback for client-side routes.

        React Router paths like /app/knowledge-base have no matching file on
        disk — Starlette's own html=True only serves index.html for
        directory-shaped requests, not arbitrary sub-paths, so a hard
        refresh on any page but /app/ would 404 without this."""

        async def get_response(self, path: str, scope: Scope):
            try:
                return await super().get_response(path, scope)
            except StarletteHTTPException as exc:
                if exc.status_code == 404 and not path.startswith("assets/"):
                    return await super().get_response("index.html", scope)
                raise

    app.mount("/app", SpaStaticFiles(directory=str(dist_dir), html=True), name="cvm-console")


def _reload_app():
    """Factory target for `uvicorn --reload` (reads CASPAR_DB)."""
    import os
    from config_assessment.api.app import create_app
    db_path = os.environ.get("CASPAR_DB", "ccss.db")
    app = create_app(db_path=db_path)
    _mount_frontend(app)
    return app
