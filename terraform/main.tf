# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

data "juju_model" "cache" {
  name  = var.model
  owner = var.model_owner
}

module "content_cache" {
  source = "../content-cache/terraform"

  model_uuid = data.juju_model.cache.uuid
  channel    = var.content_cache_channel
  revision   = var.content_cache_revision
  units      = var.content_cache_units
  expose     = true
}

module "content_cache_backends_config" {
  source = "../content-cache-backends-config/terraform"

  model_uuid = data.juju_model.cache.uuid
  channel    = var.backends_config_channel
  revision   = var.backends_config_revision
  config     = var.backends_config
}

resource "juju_application" "certificates" {
  name       = "content-cache-certs"
  model_uuid = data.juju_model.cache.uuid

  charm {
    name    = "self-signed-certificates"
    channel = var.certificates_channel
    base    = var.certificates_base
  }
}

resource "juju_integration" "cache_to_backends_config" {
  model_uuid = data.juju_model.cache.uuid

  application {
    name     = module.content_cache.app_name
    endpoint = module.content_cache.endpoints.cache_config
  }
  application {
    name     = module.content_cache_backends_config.app_name
    endpoint = module.content_cache_backends_config.endpoints.cache_config
  }
}

resource "juju_integration" "cache_to_certificates" {
  model_uuid = data.juju_model.cache.uuid

  application {
    name     = module.content_cache.app_name
    endpoint = module.content_cache.endpoints.certificates
  }
  application {
    name     = juju_application.certificates.name
    endpoint = "certificates"
  }
}
