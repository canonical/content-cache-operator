# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the metric of content-cache charm with COS integration."""

import json
import secrets

import pytest
from juju.application import Application
from juju.model import Model
from juju.unit import Unit

from src import nginx_manager
from src.charm import unit_name_to_instance_name
from tests.integration.helpers import (
    BACKENDS_CONFIG_NAME,
    BACKENDS_PATH_CONFIG_NAME,
    HOSTNAME_CONFIG_NAME,
    PROTOCOL_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    CacheTester,
    read_file,
)

COS_AGENT_INTEGRATION_NAME = "cos-agent"


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_metric_log(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_ip: str,
    model: Model,
) -> None:
    """
    arrange: A working application of content-cache charm integrated with config charm.
    act: Makes some requests to the content-cache.
    assert: The cache log contains the metrics.
    """
    unit: Unit = app.units[0]

    hostname = f"test.{secrets.token_hex(2)}.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = http_ok_ip
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[PROTOCOL_CONFIG_NAME] = "http"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200
    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200

    content = await read_file(
        unit, nginx_manager._get_cache_log_path(hostname, unit_name_to_instance_name(unit.name))
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
@pytest.mark.asyncio
async def test_integrate_with_cos(
    app: Application,
    config_app: Application,
    metric_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_ip: str,
    model: Model,
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
    hostname = f"test.{secrets.token_hex(2)}.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = http_ok_ip
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[PROTOCOL_CONFIG_NAME] = "http"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)
    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200, "Test arrange failure"

    # 1.
    await model.integrate(
        f"{metric_app.name}:{COS_AGENT_INTEGRATION_NAME}",
        f"{app.name}:{COS_AGENT_INTEGRATION_NAME}",
    )

    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    # 2.
    await app.remove_relation(COS_AGENT_INTEGRATION_NAME, metric_app.name, True)

    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)
