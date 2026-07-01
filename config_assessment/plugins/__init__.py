"""CASPAR plugins package.

Built-in plugins live in this directory. To let user-installed plugins persist
outside the image (e.g. on a mounted Docker volume), the package path is
extended with the directory named by $CASPAR_PLUGINS_DIR when it is set. That
makes `config_assessment.plugins.<id>` importable whether <id> was shipped in
the image or fetched into the external directory at runtime.
"""

from __future__ import annotations

import os as _os
from pathlib import Path as _Path

_external = _os.environ.get("CASPAR_PLUGINS_DIR")
if _external:
    _ext_path = _Path(_external)
    _ext_path.mkdir(parents=True, exist_ok=True)
    _ext = str(_ext_path)
    if _ext not in __path__:
        # Append so built-ins take precedence on name clashes.
        __path__.append(_ext)
