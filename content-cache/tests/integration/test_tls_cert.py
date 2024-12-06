# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the content-cache charm with tls-certificates integration."""

import secrets

import pytest
from juju.application import Application
from juju.model import Model

from tests.integration.helpers import (
    BACKENDS_CONFIG_NAME,
    BACKENDS_PATH_CONFIG_NAME,
    HEALTHCHECK_INTERVAL_CONFIG_NAME,
    HEALTHCHECK_PATH_CONFIG_NAME,
    HOSTNAME_CONFIG_NAME,
    PROTOCOL_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    CacheTester,
)


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_integrate_with_data_then_cert(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ip: str,
    model: Model,
) -> None:
    """
    arrange: A working application of content-cache charm no integration.
    act: Integrate with configuration charm then TLS certificate charm.
    assert: HTTPS request should succeed.
    """
    hostname = f"test.{secrets.token_hex(2)}.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = http_ok_ip
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2123"
    config[PROTOCOL_CONFIG_NAME] = "http"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await cache_tester.integrate_cert()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    response = await cache_tester.query_cache(path="/", hostname=hostname, protocol="https")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    response = await cache_tester.query_cache(path="/", hostname=hostname, protocol="http")
    assert http_ok_message not in response.content.decode("utf-8")


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_integrate_with_cert_then_data(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ip: str,
    model: Model,
) -> None:
    """
    arrange: A working application of content-cache charm no integration.
    act: Integrate with TLS certificate charm then configuration charm.
    assert: HTTPS request should succeed.
    """
    hostname = f"test.{secrets.token_hex(2)}.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = http_ok_ip
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "2123"
    config[PROTOCOL_CONFIG_NAME] = "http"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_cert()
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    response = await cache_tester.query_cache(path="/", hostname=hostname, protocol="https")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    response = await cache_tester.query_cache(path="/", hostname=hostname, protocol="http")
    assert http_ok_message not in response.content.decode("utf-8")
