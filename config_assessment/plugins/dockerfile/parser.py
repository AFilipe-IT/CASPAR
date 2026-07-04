"""
plugins/dockerfile/parser.py — thin wrapper over the generic Dockerfile parser.

Instructions become flat Directives (lowercase names, stage context) plus the
synthetic `from_tag`/per-port `expose` directives the rules match on.
"""

from config_assessment.parsers.dockerfile import parse_file as parse_file  # re-export
