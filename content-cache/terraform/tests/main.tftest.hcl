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
    # renovate: depName="content-cache"
    channel  = "1/edge"
    revision = 530
  }

  assert {
    condition     = output.app_name == "content-cache"
    error_message = "content-cache app_name did not match expected"
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
