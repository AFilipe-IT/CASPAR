"""
core/plugin_detector.py
------------------------
Identify which service a CIS Benchmark PDF describes, so `ccss plugin add` can
pre-fill the PluginSpec (config format, paths, bind directive, ...).

Detection cascade:
  1. PDF filename   — "CIS_PostgreSQL_13_Benchmark..." → "postgresql"
  2. PDF content    — the title on the first page
  3. LLM (optional) — fallback when the above don't match a known service
"""

from __future__ import annotations

import re


# Known services and their config shape. Extend this to support more targets.
_KNOWN_SERVICES: dict[str, dict] = {
    "postgresql": {
        "service_name": "PostgreSQL",
        "config_format": "key_value",
        "config_paths": [
            "/etc/postgresql/*/main/postgresql.conf",
            "/var/lib/pgsql/data/postgresql.conf",
        ],
        "config_filenames": ["postgresql.conf"],
        "bind_directive": "listen_addresses",
        "version_exposing": [],
    },
    "mysql": {
        "service_name": "MySQL",
        "config_format": "ini",
        "config_paths": ["/etc/mysql/my.cnf", "/etc/my.cnf"],
        "config_filenames": ["my.cnf", "mysqld.cnf"],
        "bind_directive": "bind-address",
        "version_exposing": [],
    },
    "mongodb": {
        "service_name": "MongoDB",
        "config_format": "yaml",
        "config_paths": ["/etc/mongod.conf"],
        "config_filenames": ["mongod.conf"],
        "bind_directive": "bindIp",
        "version_exposing": [],
    },
    "redis": {
        "service_name": "Redis",
        "config_format": "key_value",
        "config_paths": ["/etc/redis/redis.conf"],
        "config_filenames": ["redis.conf"],
        "bind_directive": "bind",
        "version_exposing": [],
    },
    "docker": {
        "service_name": "Docker",
        "config_format": "json",
        "config_paths": ["/etc/docker/daemon.json"],
        "config_filenames": ["daemon.json"],
        "bind_directive": None,
        "version_exposing": [],
    },
}

# Aliases / spellings that map onto a canonical service id.
_ALIASES = {
    "postgres": "postgresql",
    "postgre": "postgresql",
    "mariadb": "mysql",
    "mongo": "mongodb",
}


def _normalise(token: str) -> str | None:
    t = token.lower()
    if t in _KNOWN_SERVICES:
        return t
    return _ALIASES.get(t)


def _result(service_id: str) -> dict:
    spec = dict(_KNOWN_SERVICES[service_id])
    spec["target_id"] = service_id
    return spec


def _from_filename(pdf_path: str) -> str | None:
    name = pdf_path.rsplit("/", 1)[-1].lower()
    # Split on non-alphanumerics: "cis_postgresql_13_benchmark" → tokens.
    for token in re.split(r"[^a-z0-9]+", name):
        sid = _normalise(token)
        if sid:
            return sid
    return None


def _from_content(pdf_path: str) -> str | None:
    try:
        from config_assessment.build.rag import _read_pdf
        text = _read_pdf(pdf_path)[:2000].lower()  # first page is enough
    except Exception:
        return None
    # Whole-name match first (handles "postgresql" before "postgres").
    for sid in _KNOWN_SERVICES:
        if sid in text:
            return sid
    for alias, sid in _ALIASES.items():
        if alias in text:
            return sid
    return None


def _from_llm(pdf_path: str, llm) -> str | None:
    try:
        from config_assessment.build.rag import _read_pdf
        text = _read_pdf(pdf_path)[:1500]
    except Exception:
        return None
    prompt = (
        "What service does this CIS Benchmark cover? Answer with one lowercase "
        "word from this list, or 'unknown':\n"
        f"{', '.join(_KNOWN_SERVICES)}\n\n"
        f"Benchmark excerpt:\n{text}"
    )
    try:
        ans = llm.complete(prompt, system="Answer with one word only.").strip().lower()
    except Exception:
        return None
    for token in re.split(r"[^a-z0-9]+", ans):
        sid = _normalise(token)
        if sid:
            return sid
    return None


def detect_service_from_pdf(pdf_path: str, llm=None) -> dict | None:
    """Identify the service a benchmark PDF describes.

    Returns the service descriptor (a copy of _KNOWN_SERVICES[id] plus
    "target_id"), or None when the service is unknown. Tries the filename, then
    the PDF content, then the LLM (if provided).
    """
    for finder in (_from_filename, _from_content):
        sid = finder(pdf_path)
        if sid:
            return _result(sid)
    if llm is not None:
        sid = _from_llm(pdf_path, llm)
        if sid:
            return _result(sid)
    return None
