"""
plugins/ubuntu/parser.py — thin wrapper over the generic key-value parser.

sysctl.conf (`key = value`) and login.defs (`KEY value`) are both flat
key-value files the canonical parser already handles. Leaf key = the directive
(full dotted sysctl name, or the login.defs parameter). Edit only if Ubuntu
needs format-specific handling.
"""

from config_assessment.parsers.key_value import parse_file as parse_file  # re-export
