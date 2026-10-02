# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.content_cache_backends_config.name
}

output "endpoints" {
  description = "Integration endpoints exposed by the content-cache-backends-config charm."
  value = {
    # Requires
    cache_config = "cache-config"
  }
}
