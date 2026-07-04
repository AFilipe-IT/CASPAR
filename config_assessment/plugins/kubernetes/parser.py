"""
plugins/kubernetes/parser.py — thin wrapper over the generic YAML flattener.

Manifests become flat Directives: leaf key (original case), raw scalar value,
dotted context with container indices. Edit only if K8s needs format-specific
handling beyond the generic parser.
"""

from config_assessment.parsers.yaml_flat import parse_file as parse_file  # re-export
