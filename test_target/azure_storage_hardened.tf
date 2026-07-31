# test_target/azure_storage_hardened.tf
# Fixture CORRETAMENTE configurada para o target 'azure-iac' — os mesmos
# atributos cobertos pela suite de recall (azure_storage_vulnerable.tf) em
# valores seguros. Qualquer finding aqui é um falso positivo (precisão/F1).

provider "azurerm" {
  features {}
}

resource "azurerm_storage_account" "secure" {
  name                = "prodstore"
  resource_group_name = "rg-prod"
  location            = "westeurope"

  https_traffic_only_enabled    = true
  min_tls_version               = "TLS1_2"
  allow_blob_public_access      = false
  allow_shared_key_access       = false
  public_network_access_enabled = false
  secure_transfer_required      = "true"

  blob_properties {
    versioning_enabled = true
  }
}

resource "azurerm_postgresql_server" "db" {
  name                = "prod-pg"
  resource_group_name = "rg-prod"

  ssl_min_protocol_version = "TLS1_2"
  require_secure_transport = "on"
  public_network_access    = "disabled"
}
