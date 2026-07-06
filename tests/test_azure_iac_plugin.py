"""
tests/test_azure_iac_plugin.py
------------------------------
Azure IaC target end-to-end: detection routing, the vocabulary-mapping build
(with a fake LLM — offline), and the money test: ONE CIS control, mapped once
at build time, flagged in Terraform AND Bicep AND ARM scans deterministically.
"""

from __future__ import annotations

import json

import cli.main as m  # noqa: F401  (discovers/registers plugins like the CLI)
from config_assessment.core import runtime
from config_assessment.core.db.database import Database
from config_assessment.plugins.azure_iac.build_azure import run_build

m._discover_plugins()

_TF = '''
resource "azurerm_storage_account" "sa" {
  name                       = "mystore"
  https_traffic_only_enabled = false
}
'''

_BICEP = """
resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystore'
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
"""

_ARM = json.dumps({
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "resources": [{
        "type": "Microsoft.Storage/storageAccounts",
        "properties": {"supportsHttpsTrafficOnly": False},
    }],
})


class _FakeLLM:
    """Deterministic stand-in for qwen: maps the 'Secure transfer' control."""

    def complete(self, prompt: str, system: str = "") -> str:
        return json.dumps({
            "mappable": True,
            "terraform": {"attribute": "https_traffic_only_enabled",
                          "bad_value": "false", "good_value": "true"},
            "arm": {"attribute": "supportsHttpsTrafficOnly",
                    "bad_value": "false", "good_value": "true"},
            "ac": "L", "c": "P", "i": "P", "a": "N",
            "justification": "HTTP requests to the storage account are accepted.",
            "recommendation": "Require secure transfer (HTTPS only).",
        })

    def is_available(self) -> bool:
        return True


class _GarbageLLM:
    def complete(self, prompt: str, system: str = "") -> str:
        return "I cannot help with that."

    def is_available(self) -> bool:
        return True


def _fake_benchmark(tmp_path):
    """A text 'PDF' in the sandbox format parse_benchmark understands."""
    b = tmp_path / "CIS_Azure_Storage.pdf"
    b.write_text(
        "16.4 Ensure that 'Secure transfer required' is set to 'Enabled' (Automated)\n"
        "Profile Applicability:\n• Level 1\n"
        "Description:\nEnable data encryption in transit.\n"
        "Rationale:\nOnly secure connections should reach the account.\n"
        "Remediation:\nSet supportsHttpsTrafficOnly to true.\n"
        "Default Value:\nEnabled\n")
    return str(b)


class TestDetection:

    def test_tf_with_azurerm_routes_to_azure_iac(self, tmp_path):
        f = tmp_path / "main.tf"
        f.write_text(_TF)
        assert runtime._select_plugin(str(f)).metadata().name == "azure-iac"

    def test_bicep_routes_to_azure_iac(self, tmp_path):
        f = tmp_path / "main.bicep"
        f.write_text(_BICEP)
        assert runtime._select_plugin(str(f)).metadata().name == "azure-iac"

    def test_arm_template_routes_to_azure_iac(self, tmp_path):
        f = tmp_path / "azuredeploy.json"
        f.write_text(_ARM)
        assert runtime._select_plugin(str(f)).metadata().name == "azure-iac"

    def test_non_azure_tf_not_claimed(self, tmp_path):
        f = tmp_path / "aws.tf"
        f.write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
        from config_assessment.plugins.azure_iac import AzureIaCPlugin
        assert not AzureIaCPlugin().detect(str(f))

    def test_plain_json_not_claimed(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text('{"name": "x", "version": "1.0.0"}')
        from config_assessment.plugins.azure_iac import AzureIaCPlugin
        assert not AzureIaCPlugin().detect(str(f))


class TestVocabularyMappingBuild:

    def test_one_control_becomes_two_vocab_rules(self, tmp_path):
        db = tmp_path / "kb.db"
        out = run_build([_fake_benchmark(tmp_path)], str(db), llm=_FakeLLM())
        assert out["mapped"] == 1
        assert out["misconfigs"] == 2       # terraform + arm rows
        with Database(str(db)) as d:
            names = {r.directive for r in d.get_all_misconfigurations("azure-iac")}
        assert names == {"https_traffic_only_enabled", "supportsHttpsTrafficOnly"}

    def test_garbage_llm_output_skips_gracefully(self, tmp_path):
        db = tmp_path / "kb.db"
        out = run_build([_fake_benchmark(tmp_path)], str(db), llm=_GarbageLLM())
        assert out["misconfigs"] == 0 and out["failed"] == 1

    def test_all_n_impact_is_rejected(self, tmp_path):
        """C:N I:N A:N ⇒ base 0.0 ⇒ a rule that can never surface — observed
        with qwen2.5:7b on CIS Azure 3.1.1; the build must refuse it."""
        class _NoImpactLLM(_FakeLLM):
            def complete(self, prompt, system=""):
                d = json.loads(super().complete(prompt, system))
                d.update(c="N", i="N", a="N")
                return json.dumps(d)
        db = tmp_path / "kb.db"
        out = run_build([_fake_benchmark(tmp_path)], str(db), llm=_NoImpactLLM())
        assert out["misconfigs"] == 0 and out["failed"] == 1

    def test_unmatchable_values_are_filtered(self, tmp_path):
        """JSON blobs, prose, pipe-alternatives and templated ARM ids as
        bad_value never match a scalar — the build must drop them (observed
        with qwen2.5:14b on the full Azure benchmarks)."""
        from config_assessment.plugins.azure_iac.build_azure import _clean_vocab
        bad_shapes = [
            {"attribute": "logs", "bad_value": '[{"category":"x"}]', "good_value": "y"},
            {"attribute": "sku_name", "bad_value": "Standard_LRS|Standard_ZRS", "good_value": "Standard_GRS"},
            {"attribute": "security_rule", "bad_value": "80, 443, or range including 80", "good_value": "exclude"},
            {"attribute": "startIpAddress", "bad_value": "0.0.0.0/subscriptions/x", "good_value": ""},
            {"attribute": "rotationPolicy", "bad_value": "{}", "good_value": "{...}"},
        ]
        assert all(_clean_vocab(s) is None for s in bad_shapes)
        # …but a real scalar mapping survives
        ok = _clean_vocab({"attribute": "min_tls_version",
                           "bad_value": "TLS1_0", "good_value": "TLS1_2"})
        assert ok == ("min_tls_version", "TLS1_0", "TLS1_2")

    def test_dotted_attribute_normalised_to_leaf(self, tmp_path):
        """'properties.softDeleteEnabled' from the LLM must become the leaf
        'softDeleteEnabled' — parsers emit leaf names (parents in context)."""
        class _DottedLLM(_FakeLLM):
            def complete(self, prompt, system=""):
                d = json.loads(super().complete(prompt, system))
                d["arm"]["attribute"] = "properties.supportsHttpsTrafficOnly"
                return json.dumps(d)
        db = tmp_path / "kb.db"
        run_build([_fake_benchmark(tmp_path)], str(db), llm=_DottedLLM())
        with Database(str(db)) as d:
            names = {r.directive for r in d.get_all_misconfigurations("azure-iac")}
        assert "supportsHttpsTrafficOnly" in names
        assert "properties.supportsHttpsTrafficOnly" not in names


class TestValueCanonicalisation:
    """Off/OFF/Disabled all fold to false so a rule meets the config on one
    form — the fix for the case/synonym drift seen across benchmarks."""

    def test_canon_folds_boolean_synonyms(self):
        from config_assessment.plugins.azure_iac.canon import canon_value
        for v in ("off", "OFF", "Off", "Disabled", "false", "No"):
            assert canon_value(v) == "false"
        for v in ("on", "ON", "Enabled", "true", "Yes"):
            assert canon_value(v) == "true"

    def test_canon_leaves_meaningful_values_exact(self):
        from config_assessment.plugins.azure_iac.canon import canon_value
        for v in ("TLS1_0", "Standard_LRS", "Microsoft.Storage", "90", "P2Y"):
            assert canon_value(v) == v

    def test_rule_off_matches_config_Off_end_to_end(self, tmp_path):
        """The whole point: a rule extracted as bad='off' flags a .tf that
        writes 'Off' — impossible with a raw case-sensitive exact match."""
        class _OffLLM(_FakeLLM):
            def complete(self, prompt, system=""):
                return json.dumps({
                    "mappable": True,
                    "terraform": {"attribute": "require_secure_transport",
                                  "bad_value": "off", "good_value": "on"},
                    "arm": {"attribute": ""},
                    "ac": "M", "c": "P", "i": "P", "a": "N",
                    "justification": "Insecure transport allowed.",
                    "recommendation": "Require secure transport.",
                })
        db = tmp_path / "kb.db"
        run_build([_fake_benchmark(tmp_path)], str(db), llm=_OffLLM())
        f = tmp_path / "db.tf"
        f.write_text('resource "azurerm_postgresql_server" "db" {\n'
                     '  require_secure_transport = "Off"\n}\n')
        with Database(str(db)) as d:
            result = runtime.scan(str(f), d)
        assert any(i.directive == "require_secure_transport"
                   for i in result.issues)


class TestOneControlThreeLanguages:
    """The point of the whole design: one build, three file formats."""

    def _seeded(self, tmp_path):
        db = tmp_path / "kb.db"
        run_build([_fake_benchmark(tmp_path)], str(db), llm=_FakeLLM())
        return db

    def _scan(self, db, path):
        with Database(str(db)) as d:
            return runtime.scan(str(path), d)

    def test_terraform_flagged(self, tmp_path):
        db = self._seeded(tmp_path)
        f = tmp_path / "main.tf"
        f.write_text(_TF)
        result = self._scan(db, f)
        assert any(i.directive == "https_traffic_only_enabled"
                   for i in result.issues)
        assert result.global_temporal_score > 0

    def test_bicep_flagged_same_control(self, tmp_path):
        db = self._seeded(tmp_path)
        f = tmp_path / "main.bicep"
        f.write_text(_BICEP)
        result = self._scan(db, f)
        assert any(i.directive == "supportsHttpsTrafficOnly"
                   for i in result.issues)

    def test_arm_flagged_same_control(self, tmp_path):
        db = self._seeded(tmp_path)
        f = tmp_path / "azuredeploy.json"
        f.write_text(_ARM)
        result = self._scan(db, f)
        assert any(i.directive == "supportsHttpsTrafficOnly"
                   for i in result.issues)

    def test_scores_identical_across_arm_and_bicep(self, tmp_path):
        """Same control, same vocabulary ⇒ same deterministic score."""
        db = self._seeded(tmp_path)
        f1 = tmp_path / "main.bicep"
        f1.write_text(_BICEP)
        f2 = tmp_path / "azuredeploy.json"
        f2.write_text(_ARM)
        s1 = self._scan(db, f1).global_temporal_score
        s2 = self._scan(db, f2).global_temporal_score
        assert s1 == s2 > 0
