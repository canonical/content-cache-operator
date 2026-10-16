# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

run "setup_tests" {
  module {
    source = "./tests/setup"
  }
}

run "basic_deploy" {
  variables {
    model_uuid = run.setup_tests.model_uuid
    # renovate: depName="content-cache"
    channel  = "1/edge"
    revision = 530
  }

  assert {
    condition     = output.application.name == "content-cache"
    error_message = "content-cache application name did not match expected"
  }

  assert {
    condition     = output.provides.cache_config.endpoint == "cache-config"
    error_message = "content-cache provides.cache_config endpoint did not match expected"
  }

  assert {
    condition     = output.requires.certificates.endpoint == "certificates"
    error_message = "content-cache requires.certificates endpoint did not match expected"
  }
}

run "integration" {
  variables {
    model_uuid = run.setup_tests.model_uuid
  }

  module {
    source = "./tests/integration"
  }

  assert {
    condition     = contains(["active", "blocked", "maintenance"], data.external.content_cache_status.result.status)
    error_message = "content-cache is not in the expected status after integration."
  }
}
