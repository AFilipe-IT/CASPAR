"""
config_assessment/api/deps.py
-------------------------------
FastAPI dependencies: DB handle per-request, optional API-key gate for
mutating routes.
"""

from __future__ import annotations

import os
from typing import Iterator

from fastapi import Header, HTTPException, Request, status

from config_assessment.core.db.database import Database


def get_db(request: Request) -> Iterator[Database]:
    """One Database connection per request, opened against the path the
    app was created with (`create_app(db_path=...)`)."""
    with Database(request.app.state.db_path) as db:
        yield db


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Gate mutating routes (POST/DELETE) behind CASPAR_API_KEY when set.
    No-op (open) when the env var is unset — the default for a local,
    single-user tool bound to 127.0.0.1."""
    expected = os.environ.get("CASPAR_API_KEY")
    if not expected:
        return
    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-API-Key",
        )
