# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "content_cache_app_name" {
  description = "Name of the deployed content-cache application."
  value       = module.content_cache.app_name
}

output "content_cache_backends_config_app_name" {
  description = "Name of the deployed content-cache-backends-config application."
  value       = module.content_cache_backends_config.app_name
}

output "certificates_app_name" {
  description = "Name of the deployed certificates provider application."
  value       = juju_application.certificates.name
}
