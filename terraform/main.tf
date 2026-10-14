# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

resource "terraform_data" "deployed_at" {
  input = timestamp()

  lifecycle {
    ignore_changes = [input]
  }
}

data "juju_model" "cache" {
  name  = var.model
  owner = var.model_owner
}

module "content_cache" {
  source = "../content-cache/terraform"

  model_uuid = data.juju_model.cache.uuid
  channel    = local.content_cache_channel
  revision   = var.content_cache_revision
  units      = var.content_cache_units
  expose     = {}
}

module "content_cache_backends_config" {
  source = "../content-cache-backends-config/terraform"

  model_uuid = data.juju_model.cache.uuid
  channel    = local.backends_config_channel
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
    name     = module.content_cache.application.name
    endpoint = module.content_cache.provides.cache_config.endpoint
  }
  application {
    name     = module.content_cache_backends_config.application.name
    endpoint = module.content_cache_backends_config.requires.cache_config.endpoint
  }
}

resource "juju_integration" "cache_to_certificates" {
  model_uuid = data.juju_model.cache.uuid

  application {
    name     = module.content_cache.application.name
    endpoint = module.content_cache.requires.certificates.endpoint
  }
  application {
    name     = juju_application.certificates.name
    endpoint = "certificates"
  }
}
