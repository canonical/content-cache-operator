# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.content_cache.name
}

output "endpoints" {
  description = "Integration endpoints exposed by the content-cache charm."
  value = {
    # Provides
    cache_config = "cache-config"
    cos_agent    = "cos-agent"
    # Requires
    certificates    = "certificates"
    receive_ca_cert = "receive-ca-cert"
  }
}
