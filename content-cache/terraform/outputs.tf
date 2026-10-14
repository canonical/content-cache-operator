# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "application" {
  description = "The deployed content-cache juju_application object."
  value       = juju_application.content_cache
}

output "provides" {
  description = "Map of the integration endpoints provided by the content-cache charm."
  value = {
    cache_config = {
      kind       = "endpoint"
      name       = juju_application.content_cache.name
      endpoint   = "cache-config"
      controller = null
    }
    cos_agent = {
      kind       = "endpoint"
      name       = juju_application.content_cache.name
      endpoint   = "cos-agent"
      controller = null
    }
  }
}

output "requires" {
  description = "Map of the integration endpoints required by the content-cache charm."
  value = {
    certificates = {
      kind       = "endpoint"
      name       = juju_application.content_cache.name
      endpoint   = "certificates"
      controller = null
    }
    receive_ca_cert = {
      kind       = "endpoint"
      name       = juju_application.content_cache.name
      endpoint   = "receive-ca-cert"
      controller = null
    }
  }
}
