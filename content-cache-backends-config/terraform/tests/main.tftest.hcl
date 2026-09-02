# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

run "setup_tests" {
  module {
    source = "./tests/setup"
  }
}

run "basic_deploy" {
  variables {
    model_uuid = run.setup_tests.model_uuid
    # renovate: depName="content-cache-backends-config"
    channel  = "latest/edge"
    revision = 52
    config = {
      backends = "127.0.0.1"
    }
  }

  assert {
    condition     = output.app_name == "content-cache-backends-config"
    error_message = "content-cache-backends-config app_name did not match expected"
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
    condition     = contains(["active", "blocked", "maintenance"], data.external.backends_config_status.result.status)
    error_message = "content-cache-backends-config is not in the expected status after integration."
  }
}
