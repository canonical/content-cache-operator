# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the metric of content-cache charm with COS integration."""

import json

import jubilant
import pytest

from src import nginx_manager
from src.charm import unit_name_to_instance_name
from tests.integration.helpers import (
    BACKENDS_CONFIG_NAME,
    HEALTHCHECK_INTERVAL_CONFIG_NAME,
    HEALTHCHECK_PATH_CONFIG_NAME,
    HEALTHCHECK_SSL_VERIFY_CONFIG_NAME,
    HEALTHCHECK_VALID_STATUS_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    CacheTester,
    read_file,
)

COS_AGENT_INTEGRATION_NAME = "cos-agent"


@pytest.mark.abort_on_fail
def test_metric_log(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    cache_tester: CacheTester,
    http_ok_ip: str,
) -> None:
    """
    arrange: A working application of content-cache charm integrated with config charm.
    act: Makes some requests to the content-cache.
    assert: The cache log contains the metrics.
    """
    unit_name = f"{app}/0"

    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"http://{http_ok_ip}:80"
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2000"
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    cache_tester.setup_config(config)
    cache_tester.integrate_config()
    juju.wait(lambda s: jubilant.all_active(s, app, config_app), timeout=10 * 60)

    response = cache_tester.query_cache(path="/")
    assert response.status_code == 200
    response = cache_tester.query_cache(path="/")
    assert response.status_code == 200

    content = read_file(
        juju,
        unit_name,
        nginx_manager._get_cache_log_path("8080", unit_name_to_instance_name(unit_name)),
    )
    assert content
    lines = content.split("\n")
    first_request: dict = json.loads(lines[0])
    second_request: dict = json.loads(lines[1])
    assert first_request["cache_status"] == "MISS"
    assert first_request["request_method"] == "GET"
    assert first_request["status_code"] == "200"
    assert second_request["cache_status"] == "HIT"
    assert second_request["request_method"] == "GET"
    assert second_request["status_code"] == "200"
    # The following fields are different each run.
    assert "hostname" in first_request
    assert "bytes_sent" in first_request
    assert "body_bytes_sent" in first_request
    assert "request_time" in first_request
    assert "time" in first_request
    assert "hostname" in second_request
    assert "bytes_sent" in second_request
    assert "body_bytes_sent" in second_request
    assert "request_time" in second_request
    assert "time" in second_request


@pytest.mark.abort_on_fail
def test_integrate_with_cos(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    metric_app: str,
    cache_tester: CacheTester,
    http_ok_ip: str,
) -> None:
    """
    arrange: A working application of content-cache charm integrated with config charm.
    act:
        1. Integrate with grafana-agent charm.
        2. Remove integration with grafana-agent charm.
    assert:
        1. Charms in active status.
        2. Charms in active status.
    """
    # Arrange:
    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"http://{http_ok_ip}:80"
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2000"
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    cache_tester.setup_config(config)
    cache_tester.integrate_config()
    juju.wait(lambda s: jubilant.all_active(s, app, config_app), timeout=10 * 60)
    response = cache_tester.query_cache(path="/")
    assert response.status_code == 200, "Test arrange failure"

    # 1.
    juju.integrate(
        f"{metric_app}:{COS_AGENT_INTEGRATION_NAME}",
        f"{app}:{COS_AGENT_INTEGRATION_NAME}",
    )

    juju.wait(lambda s: jubilant.all_active(s, app, config_app, metric_app), timeout=10 * 60)

    # 2.
    juju.remove_relation(
        f"{app}:{COS_AGENT_INTEGRATION_NAME}",
        f"{metric_app}:{COS_AGENT_INTEGRATION_NAME}",
    )

    juju.wait(lambda s: jubilant.all_active(s, app, config_app), timeout=10 * 60)
