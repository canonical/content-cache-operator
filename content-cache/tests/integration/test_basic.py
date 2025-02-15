# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the content-cache charm."""

import json
import secrets
from asyncio import sleep

import pytest
from juju.application import Application
from juju.model import Model

from tests.integration.helpers import (
    BACKENDS_CONFIG_NAME,
    BACKENDS_PATH_CONFIG_NAME,
    FAIL_TIMEOUT_CONFIG_NAME,
    HEALTHCHECK_INTERVAL_CONFIG_NAME,
    HEALTHCHECK_PATH_CONFIG_NAME,
    HEALTHCHECK_SSL_VERIFY_CONFIG_NAME,
    HEALTHCHECK_VALID_STATUS_CONFIG_NAME,
    HOSTNAME_CONFIG_NAME,
    PROTOCOL_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    CacheTester,
)


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_start(
    app: Application,
) -> None:
    """
    arrange: The applications deployed.
    act: Nothing.
    assert: The applications in blocked status waiting for integration.
    """
    assert len(app.units) == 1
    unit = app.units[0]
    assert unit.workload_status_message == "Waiting for integration with config charm"


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_integrate_with_no_data(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ip: str,
    model: Model,
) -> None:
    """
    arrange: A working application of content-cache charm, with no integrations, and a test HTTP
        server.
    act:
        1. Integrate with the configuration charm.
        2. Add configuration to the configuration charm.
    assert:
        1. The application in blocked status waiting for integration.
        2. The request to the cache should succeed.
    """
    # 1.
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="blocked", timeout=10 * 60)
    assert len(app.units) == 1
    assert len(config_app.units) == 1
    unit = app.units[0]
    config_unit = config_app.units[0]
    assert unit.workload_status_message == "Waiting for integration with config charm"
    assert config_unit.workload_status_message == "Empty backends configuration found"

    # 2.
    hostname = f"test.{secrets.token_hex(2)}.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = http_ok_ip
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2123"
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROTOCOL_CONFIG_NAME] = "http"
    await cache_tester.setup_config(config)
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)
    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    # Cleanup
    await cache_tester.reset()


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_integrate_with_data(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ip: str,
    model: Model,
) -> None:
    """
    arrange: A working application of content-cache charm, with no integrations.
    act:
        1. Integrate with the configuration charm with configuration set.
        2. Wait for a while, then query again.
        3. Wait until the cache expires, then query again.
        4. Remove the configuration on the configuration charm.
        5. Remove the integration between the charms.
    assert:
        1. The request to the cache should succeed.
        2. The timestamp of the response should be the same as last request.
        3. The timestamp of the response should be refreshed.
        4. The configuration charm should be in blocked state. The content-cache charm will be
            serving according to the old configuration.
        5. The application in blocked status waiting for integration.
    """
    hostname = f"test.{secrets.token_hex(2)}.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = http_ok_ip
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2123"
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROTOCOL_CONFIG_NAME] = "http"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")
    timestamp = json.loads(response.content.decode("utf-8"))["time"]

    await sleep(3)
    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")
    assert timestamp == json.loads(response.content.decode("utf-8"))["time"]

    # The cache valid is set to 10 seconds, the total wait should exceed it.
    await sleep(11)
    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")
    assert timestamp != json.loads(response.content.decode("utf-8"))["time"]

    await cache_tester.reset_config()

    # The configuration update should fail on the configuration charm, and enter blocked state.
    # Since the integration data is not updated, the content-cache charm will continue serve the
    # site, according to the old configuration.
    await model.wait_for_idle([app.name], status="active", timeout=10 * 60)
    await model.wait_for_idle([config_app.name], status="blocked", timeout=10 * 60)
    assert len(app.units) == 1
    assert len(config_app.units) == 1
    unit = app.units[0]
    config_unit = config_app.units[0]
    assert unit.workload_status_message == ""
    assert config_unit.workload_status_message == "Empty backends configuration found"
    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_with_two_config_app(
    app: Application,
    config_app: Application,
    config_alt_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ip: str,
    model: Model,
) -> None:
    """
    arrange: A working charm with integration with two configuration charms.
    act: Make query to content cache for both configurations.
    assert: Both request should succeed.
    """
    hostname = f"test.{secrets.token_hex(2)}.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = http_ok_ip
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2123"
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROTOCOL_CONFIG_NAME] = "http"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)

    hostname_alt = f"test.{secrets.token_hex(2)}.local"
    config_alt = dict(CacheTester.BASE_CONFIG)
    config_alt[HOSTNAME_CONFIG_NAME] = hostname_alt
    config_alt[BACKENDS_CONFIG_NAME] = http_ok_ip
    config_alt[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config_alt[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config_alt[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2123"
    config_alt[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config_alt[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config_alt[PROTOCOL_CONFIG_NAME] = "http"
    config_alt[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config_alt(config_alt)

    await cache_tester.integrate_config()
    await cache_tester.integrate_config_alt()

    await model.wait_for_idle(
        [app.name, config_app.name, config_alt_app.name], status="active", timeout=10 * 60
    )

    response = await cache_tester.query_cache(path="/", hostname=hostname)
    response_alt = await cache_tester.query_cache(path="/", hostname=hostname_alt)
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")
    assert response_alt.status_code == 200
    assert http_ok_message in response_alt.content.decode("utf-8")


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_with_failover(
    app: Application,
    config_app: Application,
    cache_tester: Application,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ip: str,
    model: Model,
) -> None:
    """
    arrange: A working application of content-cache charm with configurations. The backends
        configuration has non-existence server and a fallback server.
    act: Make a request to the content-cache.
    assert: The fallback server respond with the output.
    """
    # A random IP for a non-existence server.
    fake_ip = "10.111.111.23"

    hostname = f"test.{secrets.token_hex(2)}.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = f"{fake_ip},{http_ok_ip}"
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2123"
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"

    config[PROTOCOL_CONFIG_NAME] = "http"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    config[FAIL_TIMEOUT_CONFIG_NAME] = "5s"
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    response = await cache_tester.query_cache(path="/", hostname=hostname)
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")
