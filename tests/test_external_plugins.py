"""
tests/test_external_plugins.py
------------------------------
$CASPAR_PLUGINS_DIR lets fetched plugins live outside the image (on a mounted
volume) so they survive a --rm container. These tests verify that a plugin
placed in the external directory is (a) on the package __path__ and (b)
discovered/imported as config_assessment.plugins.<id>, while built-in plugins
keep working.
"""

from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture
def external_dir(tmp_path, monkeypatch):
    """Point CASPAR_PLUGINS_DIR at a fresh dir and reload the plugins package
    so its __path__ picks it up. Cleaned up automatically."""
    ext = tmp_path / "plugins"
    ext.mkdir()
    monkeypatch.setenv("CASPAR_PLUGINS_DIR", str(ext))
    import config_assessment.plugins as pkg
    importlib.reload(pkg)
    yield ext
    # Drop any modules imported from the external dir and restore the package.
    for m in list(sys.modules):
        if m.startswith("config_assessment.plugins.extplug"):
            del sys.modules[m]
    monkeypatch.delenv("CASPAR_PLUGINS_DIR", raising=False)
    importlib.reload(pkg)


def _write_plugin(ext_dir, name):
    p = ext_dir / name
    p.mkdir()
    (p / "__init__.py").write_text(
        "LOADED = True\n", encoding="utf-8")
    return p


def test_external_dir_joins_package_path(external_dir):
    import config_assessment.plugins as pkg
    assert str(external_dir) in pkg.__path__
    # Built-in dir is still there and comes first.
    assert any(p.endswith("config_assessment/plugins") for p in pkg.__path__)
    assert pkg.__path__[0].endswith("config_assessment/plugins")


def test_plugin_dirs_includes_external(external_dir):
    from cli.main import _plugin_dirs
    dirs = [str(d) for d in _plugin_dirs()]
    assert str(external_dir) in dirs


def test_discover_imports_external_plugin(external_dir):
    _write_plugin(external_dir, "extplug")
    from cli.main import _discover_plugins
    _discover_plugins()
    mod = sys.modules.get("config_assessment.plugins.extplug")
    assert mod is not None and getattr(mod, "LOADED", False) is True


def test_builtin_wins_on_name_clash(external_dir):
    # A dir in the external location named like a built-in must not shadow it.
    _write_plugin(external_dir, "nginx")  # nginx is a built-in
    from cli.main import _discover_plugins
    _discover_plugins()
    # The imported nginx module resolves to the built-in package path,
    # not the external stub (which has no real plugin code).
    mod = sys.modules.get("config_assessment.plugins.nginx")
    assert mod is not None
    assert "config_assessment/plugins/nginx" in mod.__file__.replace("\\", "/")


def test_no_external_dir_uses_builtin_only(monkeypatch):
    monkeypatch.delenv("CASPAR_PLUGINS_DIR", raising=False)
    import config_assessment.plugins as pkg
    importlib.reload(pkg)
    from cli.main import _plugin_dirs
    dirs = _plugin_dirs()
    assert len(dirs) == 1
    assert dirs[0].name == "plugins"
