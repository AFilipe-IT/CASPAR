# test_target/azure_storage_vulnerable.tf
# Terraform (provider azurerm) DELIBERADAMENTE inseguro — fixture de demonstração.
# Cada atributo abaixo corresponde a um controlo do CIS Microsoft Azure Benchmark
# que o build LLM mapeou para o vocabulário Terraform. Correr:
#   sca scan test_target/azure_storage_vulnerable.tf

provider "azurerm" {
  features {}
}

resource "azurerm_storage_account" "insecure" {
  name                = "prodstore"
  resource_group_name = "rg-prod"
  location            = "westeurope"

  # ── misconfigs (o scan deve apanhá-las) ──────────────────────────────
  https_traffic_only_enabled = false      # exige HTTPS → deve ser true
  min_tls_version            = "TLS1_0"    # TLS obsoleto → TLS1_2
  allow_blob_public_access   = true        # acesso público a blobs → false
  allow_shared_key_access    = true        # chaves partilhadas → false
  public_network_access_enabled = true     # exposto à internet → false
  secure_transfer_required   = "Off"       # (repara: 'Off' — o canon trata como false)

  blob_properties {
    versioning_enabled = false             # versionamento → true
  }
}

resource "azurerm_postgresql_server" "db" {
  name                = "prod-pg"
  resource_group_name = "rg-prod"

  ssl_min_protocol_version = "TLS1_0"      # → TLS1_2
  require_secure_transport = "off"         # → on/true
  public_network_access    = "enabled"     # → disabled
}
