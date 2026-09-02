# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# This test validates that the example composition wires together correctly
# (module sources resolve, variables pass through, and integration endpoint
# names match what each base module exposes). It uses a mocked juju provider
# so it runs in seconds without a real Juju controller. It intentionally does
# not verify runtime behaviour of the deployed charms - that is covered by
# the live-deploy tests in the content-cache and content-cache-backends-config
# base modules, and by the charms' own integration test suites.

mock_provider "juju" {
  override_data {
    target = data.juju_model.cache
    values = {
      uuid = "00000000-0000-4000-8000-000000000000"
      type = "iaas"
    }
  }
}

run "plan_composition" {
  variables {
    model = "tf-testing-content-cache-composition"
  }

  assert {
    condition     = output.content_cache_app_name == "content-cache"
    error_message = "content-cache app_name did not match expected"
  }

  assert {
    condition     = output.content_cache_backends_config_app_name == "content-cache-backends-config"
    error_message = "content-cache-backends-config app_name did not match expected"
  }

  assert {
    condition     = output.certificates_app_name == "content-cache-certs"
    error_message = "certificates app_name did not match expected"
  }

  assert {
    condition = alltrue([
      for a in juju_integration.cache_to_backends_config.application : a.endpoint == "cache-config"
    ])
    error_message = "cache-config integration did not use the expected endpoint on both sides"
  }

  assert {
    condition = contains(
      [for a in juju_integration.cache_to_backends_config.application : a.name],
      module.content_cache.app_name
      ) && contains(
      [for a in juju_integration.cache_to_backends_config.application : a.name],
      module.content_cache_backends_config.app_name
    )
    error_message = "cache-config integration did not connect content-cache and content-cache-backends-config"
  }

  assert {
    condition = alltrue([
      for a in juju_integration.cache_to_certificates.application : a.endpoint == "certificates"
    ])
    error_message = "certificates integration did not use the expected endpoint on both sides"
  }

  assert {
    condition = contains(
      [for a in juju_integration.cache_to_certificates.application : a.name],
      module.content_cache.app_name
      ) && contains(
      [for a in juju_integration.cache_to_certificates.application : a.name],
      juju_application.certificates.name
    )
    error_message = "certificates integration did not connect content-cache and content-cache-certs"
  }
}
