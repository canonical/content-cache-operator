# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for HTTPS backend support via certificate_transfer and tls-certificates."""

import asyncio

import pytest
from helpers import (
    BACKEND_HOSTNAME_CONFIG_NAME,
    BACKENDS_CONFIG_NAME,
    HEALTHCHECK_INTERVAL_CONFIG_NAME,
    HEALTHCHECK_PATH_CONFIG_NAME,
    HEALTHCHECK_SSL_VERIFY_CONFIG_NAME,
    HEALTHCHECK_VALID_STATUS_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    CacheTester,
    get_app_ip,
    get_cache_backend,
    run_in_unit,
)
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

CERTIFICATE_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"
CERT_TRANSFER_PROVIDER_ENDPOINT_NAME = "provide-certificate-transfer"
CACHE_LEGO_CERT_PROVIDER_ENDPOINT_NAME = "certificates"
CACHE_CONFIG_INTEGRATION_NAME = "cache-config"
CERTIFICATES_INTEGRATION_NAME = "certificates"


HEALTHCHECK_INTERVAL = 2000


async def test_certificate_transfer_full_lifecycle(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    https_cert_ok_app: Application,
    http_ok_message: str,
    cache_tester,
) -> None:
    """
    arrange: Content-cache with HTTPS backend whose cert is signed by https_cert_ok_app's
        own local CA (not trusted by the system CA store). healthcheck-ssl-verify=false so
        the Lua healthchecker always marks the backend as up; only nginx proxy SSL verify
        changes.
    act: Integrate certificate-transfer (https_cert_ok_app:provide-certificate-transfer → cache:receive-ca-cert),
        then remove it.
    assert:
        - Before integration: request returns 502 — cert_app CA not in combined bundle,
          nginx proxy_ssl_verify fails.
        - After integration: request returns 200 — cert_app CA added to combined bundle,
          nginx proxy_ssl_verify passes.
        - After removal: request returns 502 — cert_app CA removed from combined bundle,
          nginx proxy_ssl_verify fails again.
    """
    backend_ip = await get_app_ip(https_cert_ok_app)

    await cache_tester.integrate_config()
    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"https://{backend_ip}:443"
    config[BACKEND_HOSTNAME_CONFIG_NAME] = "localhost"
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = str(HEALTHCHECK_INTERVAL)
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = "false"
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await model.wait_for_idle([app.name], status="active", timeout=10 * 60)
    await asyncio.sleep(5 * HEALTHCHECK_INTERVAL / 1000)

    # Phase 1: no cert-transfer — https_cert_ok_app's local CA not in bundle — proxy SSL fails.
    response = await cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 502, "Expected 502 before cert-transfer: CA not trusted"

    try:
        await model.integrate(
            f"{https_cert_ok_app.name}:{CERT_TRANSFER_PROVIDER_ENDPOINT_NAME}",
            f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        )
        await model.wait_for_idle([app.name], status="active", timeout=10 * 60)

        # Phase 2: cert-transfer integrated — local CA in bundle — proxy SSL verify passes.
        response = await cache_tester.query_cache(path="/", protocol="http")
        assert response.status_code == 200, "Expected 200 after cert-transfer: CA now trusted"
        assert http_ok_message in response.content.decode("utf-8")

        await app.remove_relation(CERTIFICATE_TRANSFER_INTEGRATION_NAME, https_cert_ok_app.name)
        await model.wait_for_idle([app.name], status="active", timeout=5 * 60)

        # Phase 3: cert-transfer removed — local CA gone from bundle — proxy SSL verify fails.
        response = await cache_tester.query_cache(path="/", protocol="http")
        assert (
            response.status_code == 502
        ), "Expected 502 after cert-transfer removal: CA untrusted"
    finally:
        if app.related_applications(CERTIFICATE_TRANSFER_INTEGRATION_NAME):
            await app.remove_relation(
                CERTIFICATE_TRANSFER_INTEGRATION_NAME, https_cert_ok_app.name
            )


@pytest.mark.abort_on_fail
async def test_tls_termination_full_lifecycle(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cache_lego_app: Application,
    cache_tester,
    http_ok_ip: str,
) -> None:
    """
    arrange: content-cache with an HTTP backend configured and cache-lego deployed.
    act: Integrate cache-lego via the certificates relation, wait for cert issuance,
        then remove the relation.
    assert:
        - After integration: content-cache reaches Active, cache-backends shows https://,
          nginx site config contains ssl directives.
        - After removal: content-cache remains Active, cache-backends reverts to http://.
    """
    await cache_tester.integrate_config()
    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"http://{http_ok_ip}:80"
    await cache_tester.setup_config(config)
    # Wait for config subordinate hooks to complete and content-cache to be Active
    # with the HTTP backend before integrating cache-lego for TLS termination.
    # Without this wait, the TLS cert may arrive before config data is delivered,
    # leaving the charm blocked on "Waiting for integration with config charm".
    await model.wait_for_idle([app.name], status="active", timeout=5 * 60)

    await model.integrate(
        f"{cache_lego_app.name}:{CACHE_LEGO_CERT_PROVIDER_ENDPOINT_NAME}",
        f"{app.name}:{CERTIFICATES_INTEGRATION_NAME}",
    )
    try:
        await model.wait_for_idle([app.name], status="active", timeout=10 * 60)
        assert app.units[0].workload_status == "active"

        unit = app.units[0]
        backends = await get_cache_backend(unit)
        assert backends.startswith(
            "https://"
        ), f"Expected https:// backend after TLS cert issuance, got: {backends}"

        _, ssl_files, _ = await run_in_unit(
            unit=unit,
            command="grep -Rl ssl /etc/nginx/sites-enabled/ 2>/dev/null || true",
        )
        assert (
            ssl_files and ssl_files.strip()
        ), "No nginx site config with 'ssl' directive found after TLS cert issuance"

        await app.remove_relation(CERTIFICATES_INTEGRATION_NAME, cache_lego_app.name)
        await model.wait_for_idle([app.name], status="active", timeout=5 * 60)
        assert app.units[0].workload_status == "active"

        backends_after = await get_cache_backend(unit)
        assert backends_after.startswith(
            "http://"
        ), f"Expected http:// backend after cert relation removal, got: {backends_after}"
    finally:
        # Ensure the certificates relation is removed even if the test fails.
        # Do NOT use block_until_done=True here — it has no timeout and can hang forever.
        if app.related_applications(CERTIFICATES_INTEGRATION_NAME):
            await app.remove_relation(CERTIFICATES_INTEGRATION_NAME, cache_lego_app.name)
