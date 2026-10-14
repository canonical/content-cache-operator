# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "metadata" {
  description = "Metadata of this product module's deployment."
  value = {
    version     = "1.0.0"
    deployed_at = terraform_data.deployed_at.output
    updated_at  = timestamp()
  }
}

output "models" {
  description = "Map of the key of the model and the components deployed in the model."
  value = {
    content_cache = {
      model_uuid = data.juju_model.cache.uuid
      components = {
        content_cache                 = module.content_cache.application
        content_cache_backends_config = module.content_cache_backends_config.application
        certificates                  = juju_application.certificates
      }
    }
  }
}
