# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for the content-cache's active healthchecks."""

import asyncio
from typing import List

import pytest
import requests
from juju.application import Application
from juju.model import Model

from nginx_manager import NGINX_BACKENDS_STATUS_URL_PATH
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

HEALTHCHECK_INTERVAL = 2000


async def get_nginx_status(app: Application, path: str) -> str:
    """Fetch and returns the content of the status page

    Args:
        app: the application to connect to
        path: the past to the status page

    Returns:
        The content of the status page

    Raises:
        RuntimeError: if status cannot be fetched
    """
    unit = app.units[0]
    command = f"curl 127.0.0.1/{path}"
    task = await unit.run(command)
    result = await task.wait()

    if result.results["return-code"]:
        raise RuntimeError(f"Couldn't fetch status page on {path}: {result.results['stderr']}")

    return result.results["stdout"]


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_healthchecks_healthy(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ips: List[str],
    model: Model,
) -> None:
    """
    arrange: Two backends responding 200 on their healthchecks.
    act: Nothing.
    assert: HTTP request should succeed and two backends are reported up in the status page.
    """
    hostname = "test.healthchecks.local"
    config = dict(CacheTester.BASE_CONFIG)
    config[HOSTNAME_CONFIG_NAME] = hostname
    config[BACKENDS_CONFIG_NAME] = ",".join(http_ok_ips)
    config[BACKENDS_PATH_CONFIG_NAME] = http_ok_path
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = str(HEALTHCHECK_INTERVAL)
    config[PROTOCOL_CONFIG_NAME] = "http"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    response = await cache_tester.query_cache(path="/", hostname=hostname, protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    # Sample status page
    #
    # Nginx Worker PID: 7905
    # Upstream 88c26973-5726-4745-ab4a-d3addea80d82
    # Primary Peers
    #    10.14.1.77:80 UP
    # Backup Peers

    status = await get_nginx_status(app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 UP" in status
    assert f"{http_ok_ips[1]}:80 UP" in status

    cache_tester._reset_after_run = False


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_healthchecks_one_unhealthy(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ips: List[str],
    model: Model,
) -> None:
    """
    arrange: Two backends responding 200 on their healthchecks.
    act: Turn one backend unhealty.
    assert: HTTP request should succeed. One backend is reported UP. One backend is reported DOWN.
    """
    hostname = "test.healthchecks.local"

    requests.get(f"http://{http_ok_ips[0]}/turn-unhealthy")
    await asyncio.sleep(4 * HEALTHCHECK_INTERVAL / 1000)

    status = await get_nginx_status(app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 DOWN" in status
    assert f"{http_ok_ips[1]}:80 UP" in status

    response = await cache_tester.query_cache(path="/", hostname=hostname, protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    cache_tester._reset_after_run = False


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_healthchecks_one_recovery(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ips: List[str],
    model: Model,
) -> None:
    """
    arrange: Two backends. One responding 200 on its healthcheck, and the other 500.
    act: Bring back the faulty backend to an healthy state.
    assert: HTTP request should succeed. Two backends are reported up.
    """
    hostname = "test.healthchecks.local"

    requests.get(f"http://{http_ok_ips[0]}/turn-healthy")
    await asyncio.sleep(3 * HEALTHCHECK_INTERVAL / 1000)

    status = await get_nginx_status(app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 UP" in status
    assert f"{http_ok_ips[1]}:80 UP" in status

    response = await cache_tester.query_cache(path="/", hostname=hostname, protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    cache_tester._reset_after_run = False


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_healthchecks_all_unhealthy(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_path: str,
    http_ok_message: str,
    http_ok_ips: List[str],
    model: Model,
) -> None:
    """
    arrange: Two healthy backends.
    act: Turn both backends unhealth.
    assert: HTTP request should fail with 502. Both backends are reported DOWN.
    """
    hostname = "test.healthchecks.local"

    requests.get(f"http://{http_ok_ips[0]}/turn-unhealthy")
    requests.get(f"http://{http_ok_ips[1]}/turn-unhealthy")
    await asyncio.sleep(5 * HEALTHCHECK_INTERVAL / 1000)

    status = await get_nginx_status(app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 DOWN" in status
    assert f"{http_ok_ips[1]}:80 DOWN" in status

    response = await cache_tester.query_cache(path="/", hostname=hostname, protocol="http")
    assert response.status_code == 502
