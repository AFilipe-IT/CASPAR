"""
cli/_discovery.py — plugin auto-discovery.

Where plugins live on disk and how they get imported/registered.
Split out of cli/main.py (which re-exports these names for compatibility).
"""

from __future__ import annotations

import importlib
import logging
import os
from pathlib import Path

logger = logging.getLogger("ccss")


def _plugin_dirs() -> list[Path]:
    """Directories to scan for plugins: the built-in package dir, plus the
    external $CASPAR_PLUGINS_DIR (a mounted volume) when set, so fetched
    plugins persist outside the image."""
    dirs = [Path(__file__).parent.parent / "config_assessment" / "plugins"]
    external = os.environ.get("CASPAR_PLUGINS_DIR")
    if external:
        dirs.append(Path(external))
    return dirs


def _discover_plugins() -> None:
    seen: set[str] = set()
    for plugins_dir in _plugin_dirs():
        if not plugins_dir.exists():
            continue
        for plugin_dir in sorted(plugins_dir.iterdir()):
            name = plugin_dir.name
            if name in seen:
                continue  # built-in dir wins on a name clash
            if plugin_dir.is_dir() and (plugin_dir / "__init__.py").exists():
                seen.add(name)
                try:
                    importlib.import_module(f"config_assessment.plugins.{name}")
                except Exception as exc:
                    logger.warning("Plugin '%s' not loaded: %s", name, exc)
