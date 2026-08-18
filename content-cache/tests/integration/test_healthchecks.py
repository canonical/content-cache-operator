# Copyright 2025 Canonical Ltd.
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
    HEALTHCHECK_INTERVAL_CONFIG_NAME,
    HEALTHCHECK_PATH_CONFIG_NAME,
    HEALTHCHECK_SSL_VERIFY_CONFIG_NAME,
    HEALTHCHECK_VALID_STATUS_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    CacheTester,
    get_app_ip,
)

CERTIFICATE_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"
CERT_TRANSFER_PROVIDER_ENDPOINT_NAME = "send-ca-cert"

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
    http_ok_message: str,
    http_ok_ips: List[str],
    model: Model,
) -> None:
    """
    arrange: Two backends responding 200 on their healthchecks.
    act: Nothing.
    assert: HTTP request should succeed and two backends are reported up in the status page.
    """
    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = ",".join(f"http://{ip}:80" for ip in http_ok_ips)
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = str(HEALTHCHECK_INTERVAL)
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    response = await cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    # Here is a typical content for the backends_status page tested below.
    # In the test we're checking that both backends are seen as "UP"
    #
    # Nginx Worker PID: 7905
    # Upstream 88c26973-5726-4745-ab4a-d3addea80d82
    # Primary Peers
    #    10.14.1.77:80 UP
    #    10.14.1.78:80 DOWN
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
    http_ok_message: str,
    http_ok_ips: List[str],
    model: Model,
) -> None:
    """
    arrange: Two backends responding 200 on their healthchecks.
    act: Turn one backend unhealty.
    assert: HTTP request should succeed. One backend is reported UP. One backend is reported DOWN.
    """
    requests.get(f"http://{http_ok_ips[0]}/turn-unhealthy")
    await asyncio.sleep(4 * HEALTHCHECK_INTERVAL / 1000)

    status = await get_nginx_status(app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 DOWN" in status
    assert f"{http_ok_ips[1]}:80 UP" in status

    response = await cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    cache_tester._reset_after_run = False


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_healthchecks_one_recovery(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_message: str,
    http_ok_ips: List[str],
    model: Model,
) -> None:
    """
    arrange: Two backends. One responding 200 on its healthcheck, and the other 500.
    act: Bring back the faulty backend to an healthy state.
    assert: HTTP request should succeed. Two backends are reported up.
    """
    requests.get(f"http://{http_ok_ips[0]}/turn-healthy")
    await asyncio.sleep(3 * HEALTHCHECK_INTERVAL / 1000)

    status = await get_nginx_status(app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 UP" in status
    assert f"{http_ok_ips[1]}:80 UP" in status

    response = await cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_healthchecks_all_unhealthy(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_message: str,
    http_ok_ips: List[str],
    model: Model,
) -> None:
    """
    arrange: Two healthy backends.
    act: Turn both backends unhealth.
    assert: HTTP request should fail with 502. Both backends are reported DOWN.
    """
    requests.get(f"http://{http_ok_ips[0]}/turn-unhealthy")
    requests.get(f"http://{http_ok_ips[1]}/turn-unhealthy")
    await asyncio.sleep(5 * HEALTHCHECK_INTERVAL / 1000)

    status = await get_nginx_status(app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 DOWN" in status
    assert f"{http_ok_ips[1]}:80 DOWN" in status

    response = await cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 502


@pytest.mark.parametrize(
    ["valid_status", "expected_http_code"],
    [
        pytest.param("200", 502, id="unhealthy"),
        pytest.param("200, 418", 200, id="healthy"),
    ],
)
@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_healthchecks_custom_status(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_message: str,
    http_ok_ip: str,
    valid_status: str,
    expected_http_code: int,
    model: Model,
) -> None:
    """
    arrange: One backend responding 418 on its healthcheck. And valid status to match it or not.
    act: Nothing.
    assert: HTTP request should fail as 200 is not a valid status here.
    """
    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"http://{http_ok_ip}:80"
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/teapot"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = str(HEALTHCHECK_INTERVAL)
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = valid_status
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    await asyncio.sleep(5 * HEALTHCHECK_INTERVAL / 1000)

    response = await cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == expected_http_code

    if expected_http_code == 200:
        assert http_ok_message in response.content.decode("utf-8")


@pytest.mark.parametrize(
    ["use_cert_ok_app", "ssl_verify", "expected_http_code"],
    [
        # ssl_verify=false: backend cert IS signed by cert_app's CA.
        # Proxy SSL verification passes (cert trusted by CA bundle) and the health check
        # skips SSL verification (ssl_verify=false) so the backend is marked healthy → 200.
        pytest.param(True, "false", 200, id="no_ssl_verify"),
        # ssl_verify=true: backend cert is NOT signed by cert_app's CA (hardcoded
        # self-signed cert from https_ok_app). The Lua health checker uses the system cert
        # store; cert_app's CA is not installed there, so the health check marks the backend
        # as unhealthy → 502 Bad Gateway.
        pytest.param(False, "true", 502, id="ssl_verify"),
    ],
)
@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_healthchecks_ssl_verify(
    app: Application,
    config_app: Application,
    cert_app: Application,
    cache_tester: CacheTester,
    http_ok_message: str,
    https_ok_app: Application,
    https_cert_ok_app: Application,
    use_cert_ok_app: bool,
    ssl_verify: str,
    expected_http_code: int,
    model: Model,
) -> None:
    """
    arrange: An HTTPS backend — either cert_app-signed (use_cert_ok_app=True) or
        hardcoded self-signed (use_cert_ok_app=False) — with cert_app's CA provided to
        content-cache via receive-ca-cert.
    act: Configure healthcheck-ssl-verify and send a request.
    assert: ssl_verify=false with a trusted backend cert returns 200 (proxy SSL passes,
        healthcheck skips SSL).  ssl_verify=true with an untrusted backend cert returns 502
        (Lua health checker marks the backend as unhealthy).
    """
    backend_app = https_cert_ok_app if use_cert_ok_app else https_ok_app
    backend_ip = await get_app_ip(backend_app)

    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"https://{backend_ip}:443"
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = str(HEALTHCHECK_INTERVAL)
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = ssl_verify
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'

    await model.integrate(
        f"{cert_app.name}:{CERT_TRANSFER_PROVIDER_ENDPOINT_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    try:
        await cache_tester.setup_config(config)
        await cache_tester.integrate_config()
        await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

        await asyncio.sleep(5 * HEALTHCHECK_INTERVAL / 1000)

        response = await cache_tester.query_cache(path="/", protocol="http")

        # Collect diagnostic info to help debug SSL verification failures
        unit = app.units[0]
        nginx_error_task = await unit.run("tail -50 /var/log/nginx/error.log 2>/dev/null || echo '(no error log)'")
        nginx_error_result = await nginx_error_task.wait()
        ca_bundle_task = await unit.run("cat /etc/nginx/ca-bundle.pem 2>/dev/null || echo '(no ca bundle)'")
        ca_bundle_result = await ca_bundle_task.wait()
        nginx_conf_task = await unit.run("grep -r 'proxy_ssl' /etc/nginx/sites-available/ 2>/dev/null | head -20 || echo '(no nginx sites)'")
        nginx_conf_result = await nginx_conf_task.wait()
        import logging
        logger = logging.getLogger(__name__)
        logger.info("nginx error log:\n%s", nginx_error_result.results.get("stdout", ""))
        logger.info("CA bundle:\n%s", ca_bundle_result.results.get("stdout", ""))
        logger.info("nginx proxy_ssl config:\n%s", nginx_conf_result.results.get("stdout", ""))

        assert response.status_code == expected_http_code

        if expected_http_code == 200:
            assert http_ok_message in response.content.decode("utf-8")
    finally:
        # Always remove the cert integration so the next parametrised run can
        # re-add it cleanly. Without this, the second run would find the
        # relation already exists and fail before integrate_config() is called,
        # leaving content-cache stuck in "Waiting for integration with config
        # charm" state.
        await app.remove_relation(CERTIFICATE_TRANSFER_INTEGRATION_NAME, cert_app.name, True)
