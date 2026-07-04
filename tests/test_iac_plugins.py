"""
tests/test_iac_plugins.py
-------------------------
IaC targets end-to-end: detection routing, deterministic curated build, and
full runtime scans of a vulnerable K8s manifest and Dockerfile — all offline
(no LLM, no network), like the rest of the runtime.
"""

from __future__ import annotations

import pytest

pytest.importorskip("yaml", reason="PyYAML not installed")

import cli.main as m  # noqa: E402  (discovers/registers plugins like the CLI)
from config_assessment.core import runtime  # noqa: E402
from config_assessment.core.db.database import Database  # noqa: E402

m._discover_plugins()

_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
"""

_DOCKERFILE_NO_USER = """\
FROM ubuntu:22.04
RUN apt-get update
EXPOSE 80
"""


def _seed_iac(db_path) -> None:
    from config_assessment.plugins.kubernetes.build_kubernetes import run_build as k8s
    from config_assessment.plugins.dockerfile.build_dockerfile import run_build as dkf
    assert k8s(str(db_path))["misconfigs"] == 10
    assert dkf(str(db_path))["misconfigs"] == 5


class TestDetection:

    def test_manifest_routes_to_kubernetes(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text(_POD)
        assert runtime._select_plugin(str(f)).metadata().name == "kubernetes"

    def test_dockerfile_routes_to_dockerfile(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text(_DOCKERFILE_NO_USER)
        assert runtime._select_plugin(str(f)).metadata().name == "dockerfile"

    def test_plain_yaml_without_k8s_markers_not_claimed(self, tmp_path):
        f = tmp_path / "values.yaml"
        f.write_text("replicas: 3\nimage: nginx\n")
        cands = [p for p in runtime._REGISTRY if p.detect(str(f))]
        assert "kubernetes" not in {p.metadata().name for p in cands}


class TestCuratedBuild:

    def test_build_is_deterministic_and_idempotent(self, tmp_path):
        db = tmp_path / "kb.db"
        _seed_iac(db)
        _seed_iac(db)   # re-run: upsert, not duplicate
        with Database(str(db)) as d:
            assert len(d.get_all_misconfigurations("kubernetes")) == 10
            assert len(d.get_all_misconfigurations("dockerfile")) == 5
            assert len(d.get_attack_chains("kubernetes")) == 1


class TestScanEndToEnd:

    def test_k8s_manifest_scores_and_fires_chain(self, tmp_path):
        db = tmp_path / "kb.db"
        _seed_iac(db)
        f = tmp_path / "pod.yaml"
        f.write_text(_POD)
        with Database(str(db)) as d:
            result = runtime.scan(str(f), d)
        found = {i.directive for i in result.issues}
        assert {"privileged", "hostNetwork"} <= found
        assert result.global_temporal_score > 7.0
        # The curated chain: privileged + hostNetwork both present AND bad.
        assert any(c.chain_id == "k8s-privileged-hostnetwork-node-takeover"
                   and c.active for c in result.chains)
        # Location fidelity: the finding points into the container's context.
        priv = next(i for i in result.issues if i.directive == "privileged")
        assert "containers[0]" in priv.source_directive.context

    def test_dockerfile_absence_rule_fires_without_user(self, tmp_path):
        db = tmp_path / "kb.db"
        _seed_iac(db)
        f = tmp_path / "Dockerfile"
        f.write_text(_DOCKERFILE_NO_USER)
        with Database(str(db)) as d:
            result = runtime.scan(str(f), d)
        absents = {i.directive for i in result.issues if i.rule_type == "absence"}
        assert "user" in absents        # root by omission
        assert "healthcheck" in absents

    def test_dockerfile_with_nonroot_user_does_not_flag_user(self, tmp_path):
        db = tmp_path / "kb.db"
        _seed_iac(db)
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nUSER app\nHEALTHCHECK CMD curl -f http://localhost/\n")
        with Database(str(db)) as d:
            result = runtime.scan(str(f), d)
        assert not any(i.directive == "user" for i in result.issues)
