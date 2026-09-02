# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "content_cache_backends_config" {
  name = var.app_name
  charm {
    name     = "content-cache-backends-config"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  model_uuid = var.model_uuid
  config     = var.config

  # This is a subordinate charm; it has no units of its own and is deployed
  # onto the units of the principal it is integrated with.
  units = 0

  dynamic "expose" {
    for_each = var.expose ? [1] : []
    content {}
  }
}
