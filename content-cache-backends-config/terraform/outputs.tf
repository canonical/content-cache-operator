# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "application" {
  description = "The deployed content-cache-backends-config juju_application object."
  value       = juju_application.content_cache_backends_config
}

output "requires" {
  description = "Map of the integration endpoints required by the content-cache-backends-config charm."
  value = {
    cache_config = {
      kind       = "endpoint"
      name       = juju_application.content_cache_backends_config.name
      endpoint   = "cache-config"
      controller = null
    }
  }
}
