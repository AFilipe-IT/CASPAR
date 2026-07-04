"""
tests/test_iac_parsers.py
-------------------------
IaC parsers: YAML flattener (Kubernetes manifests) and Dockerfile.
Structure in → flat Directives out; no security evaluation here.
"""

from __future__ import annotations

import pytest

from config_assessment.parsers import dockerfile as dfp
from config_assessment.parsers import yaml_flat

yaml = pytest.importorskip("yaml", reason="PyYAML not installed")

_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
        runAsNonRoot: false
    - name: sidecar
      securityContext:
        capabilities:
          add:
            - SYS_ADMIN
"""


def _parse_yaml(tmp_path, text, name="pod.yaml"):
    f = tmp_path / name
    f.write_text(text)
    return yaml_flat.parse_file(str(f))


class TestYamlFlat:

    def test_leaf_names_keep_original_case(self, tmp_path):
        ds = _parse_yaml(tmp_path, _POD)
        names = {d.name for d in ds}
        assert "hostNetwork" in names and "privileged" in names

    def test_values_are_raw_scalars(self, tmp_path):
        ds = {d.name: d.value for d in _parse_yaml(tmp_path, _POD)}
        assert ds["privileged"] == "true"       # raw, not bool
        assert ds["runAsNonRoot"] == "false"

    def test_context_carries_container_index(self, tmp_path):
        ds = _parse_yaml(tmp_path, _POD)
        priv = next(d for d in ds if d.name == "privileged")
        assert "containers[0]" in priv.context
        assert "securityContext" in priv.context

    def test_scalar_sequences_become_instances(self, tmp_path):
        ds = _parse_yaml(tmp_path, _POD)
        caps = [d for d in ds if d.name == "add"]
        assert caps and caps[0].value == "SYS_ADMIN"

    def test_line_numbers_point_at_keys(self, tmp_path):
        ds = _parse_yaml(tmp_path, _POD)
        host = next(d for d in ds if d.name == "hostNetwork")
        assert host.line_number == 6

    def test_multi_document_gets_doc_prefix(self, tmp_path):
        ds = _parse_yaml(tmp_path, "a: 1\n---\nb: 2\n")
        ctxs = {d.name: d.context for d in ds}
        assert ctxs["a"].startswith("doc0:") and ctxs["b"].startswith("doc1:")

    def test_invalid_yaml_never_crashes(self, tmp_path):
        assert _parse_yaml(tmp_path, "a: [unclosed\n  broken: {") == []


_DOCKERFILE = """\
# demo
FROM ubuntu:22.04 AS build
RUN apt-get update && \\
    apt-get install -y curl
FROM nginx
USER root
EXPOSE 22 80/tcp
COPY app /srv/app
"""


class TestDockerfileParser:

    def _parse(self, tmp_path, text=_DOCKERFILE):
        f = tmp_path / "Dockerfile"
        f.write_text(text)
        return dfp.parse_file(str(f))

    def test_instructions_lowercased(self, tmp_path):
        names = {d.name for d in self._parse(tmp_path)}
        assert {"from", "run", "user", "expose", "copy"} <= names

    def test_implicit_latest_tag_is_surfaced(self, tmp_path):
        ds = self._parse(tmp_path)
        tags = [d for d in ds if d.name == "from_tag"]
        # ubuntu:22.04 → 22.04 ; nginx (sem tag) → latest IMPLÍCITO
        assert {t.value for t in tags} == {"22.04", "latest"}

    def test_digest_pin_has_no_tag_directive(self, tmp_path):
        ds = self._parse(tmp_path, "FROM img@sha256:abc123\n")
        assert not [d for d in ds if d.name == "from_tag"]

    def test_expose_one_directive_per_port(self, tmp_path):
        ds = self._parse(tmp_path)
        ports = {d.value for d in ds if d.name == "expose"}
        assert ports == {"22", "80"}            # /tcp suffix stripped

    def test_stage_context(self, tmp_path):
        ds = self._parse(tmp_path)
        user = next(d for d in ds if d.name == "user")
        assert user.value == "root"
        assert user.context == "stage:stage2"   # 2nd FROM, unnamed
        run = next(d for d in ds if d.name == "run")
        assert run.context == "stage:build"     # named via AS

    def test_continuation_folded(self, tmp_path):
        ds = self._parse(tmp_path)
        run = next(d for d in ds if d.name == "run")
        assert "apt-get install" in run.value   # both lines, one directive
