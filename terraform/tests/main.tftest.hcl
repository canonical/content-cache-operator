# Copyright 2026 Canonical Ltd.
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
    condition     = output.models.content_cache.components.content_cache.name == "content-cache"
    error_message = "content-cache application name did not match expected"
  }

  assert {
    condition     = output.models.content_cache.components.content_cache_backends_config.name == "content-cache-backends-config"
    error_message = "content-cache-backends-config application name did not match expected"
  }

  assert {
    condition     = output.models.content_cache.components.certificates.name == "content-cache-certs"
    error_message = "certificates application name did not match expected"
  }

  assert {
    condition     = output.metadata.version == "1.0.0"
    error_message = "metadata.version did not match expected"
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
      module.content_cache.application.name
      ) && contains(
      [for a in juju_integration.cache_to_backends_config.application : a.name],
      module.content_cache_backends_config.application.name
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
      module.content_cache.application.name
      ) && contains(
      [for a in juju_integration.cache_to_certificates.application : a.name],
      juju_application.certificates.name
    )
    error_message = "certificates integration did not connect content-cache and content-cache-certs"
  }
}

run "rejects_invalid_risk" {
  command = plan

  variables {
    model = "tf-testing-content-cache-composition"
    risk  = "candidate"
  }

  expect_failures = [
    var.risk,
  ]
}
