"""
tests/test_azure_iac_parsers.py
-------------------------------
Azure IaC parsers: Terraform/HCL, Bicep and ARM JSON all flatten to the same
Directive model, so ONE ruleset (per vocabulary) scores all three.
"""

from __future__ import annotations

from config_assessment.parsers import arm_json, bicep_flat, hcl_flat

_TF = '''\
# storage account for the app
provider "azurerm" {
  features {}
}

resource "azurerm_storage_account" "sa" {
  name                        = "mystore"
  https_traffic_only_enabled  = false   // insecure!
  min_tls_version             = "TLS1_0"
  allowed_ips                 = ["10.0.0.1", "10.0.0.2"]
  tags = {
    env = "prod"
  }
  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }
}
'''


class TestTerraform:

    def _parse(self, tmp_path, text=_TF):
        f = tmp_path / "main.tf"
        f.write_text(text)
        return hcl_flat.parse_file(str(f))

    def test_resource_context_is_type_dot_name(self, tmp_path):
        ds = self._parse(tmp_path)
        https = next(d for d in ds if d.name == "https_traffic_only_enabled")
        assert https.context == "azurerm_storage_account.sa"
        assert https.value == "false"          # inline // comment stripped
        assert https.line_number == 8

    def test_quoted_values_unquoted(self, tmp_path):
        ds = self._parse(tmp_path)
        tls = next(d for d in ds if d.name == "min_tls_version")
        assert tls.value == "TLS1_0"

    def test_nested_blocks_flatten(self, tmp_path):
        ds = self._parse(tmp_path)
        days = next(d for d in ds if d.name == "days")
        assert days.context == ("azurerm_storage_account.sa."
                                "blob_properties.delete_retention_policy")

    def test_lists_one_directive_per_item(self, tmp_path):
        ds = self._parse(tmp_path)
        ips = [d.value for d in ds if d.name == "allowed_ips"]
        assert ips == ["10.0.0.1", "10.0.0.2"]

    def test_object_values_flatten(self, tmp_path):
        ds = self._parse(tmp_path)
        env = next(d for d in ds if d.name == "env")
        assert env.value == "prod" and "tags" in env.context


_BICEP = """\
// storage
param location string = 'westeurope'

resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystore'
  location: location
  properties: {
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
  }
}
"""


class TestBicep:

    def _parse(self, tmp_path):
        f = tmp_path / "main.bicep"
        f.write_text(_BICEP)
        return bicep_flat.parse_file(str(f))

    def test_arm_vocabulary_with_resource_context(self, tmp_path):
        ds = self._parse(tmp_path)
        https = next(d for d in ds if d.name == "supportsHttpsTrafficOnly")
        assert https.value == "false"
        assert https.context == "Microsoft.Storage/storageAccounts.sa.properties"

    def test_single_quotes_stripped(self, tmp_path):
        ds = self._parse(tmp_path)
        tls = next(d for d in ds if d.name == "minimumTlsVersion")
        assert tls.value == "TLS1_0"

    def test_param_default_captured(self, tmp_path):
        ds = self._parse(tmp_path)
        loc = next(d for d in ds if d.name == "location" and d.context == "param")
        assert loc.value == "westeurope"


_ARM = """{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "parameters": {
    "adminUsername": { "type": "string", "defaultValue": "admin" }
  },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "mystore",
      "properties": {
        "supportsHttpsTrafficOnly": false,
        "minimumTlsVersion": "TLS1_0"
      }
    }
  ]
}
"""


class TestArmJson:

    def _parse(self, tmp_path):
        f = tmp_path / "azuredeploy.json"
        f.write_text(_ARM)
        return arm_json.parse_file(str(f))

    def test_same_vocabulary_as_bicep(self, tmp_path):
        ds = self._parse(tmp_path)
        https = next(d for d in ds if d.name == "supportsHttpsTrafficOnly")
        assert https.value == "false"          # json bool → "false"
        assert https.context.startswith("Microsoft.Storage/storageAccounts[0]")

    def test_line_numbers_best_effort(self, tmp_path):
        ds = self._parse(tmp_path)
        https = next(d for d in ds if d.name == "supportsHttpsTrafficOnly")
        assert https.line_number == 11

    def test_parameter_defaults_surfaced(self, tmp_path):
        ds = self._parse(tmp_path)
        admin = next(d for d in ds if d.name == "adminUsername")
        assert admin.value == "admin" and admin.context == "parameters"

    def test_invalid_json_never_crashes(self, tmp_path):
        f = tmp_path / "broken.json"
        f.write_text("{ not json")
        assert arm_json.parse_file(str(f)) == []
