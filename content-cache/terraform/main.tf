# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "content_cache" {
  name = var.app_name
  charm {
    name     = "content-cache"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  model_uuid  = var.model_uuid
  config      = var.config
  constraints = var.constraints
  units       = var.units

  dynamic "expose" {
    for_each = var.expose ? [1] : []
    content {}
  }
}
