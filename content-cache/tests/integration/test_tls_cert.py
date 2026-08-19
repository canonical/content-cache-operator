# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for HTTPS backend support via certificate_transfer and tls-certificates."""

import pytest
from helpers import BACKENDS_CONFIG_NAME, CacheTester, get_cache_backend, run_in_unit
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

CERTIFICATE_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"
CERT_TRANSFER_PROVIDER_ENDPOINT_NAME = "send-ca-cert"
CACHE_LEGO_CERT_PROVIDER_ENDPOINT_NAME = "certificates"
CACHE_CONFIG_INTEGRATION_NAME = "cache-config"
CERTIFICATES_INTEGRATION_NAME = "certificates"


async def test_certificate_transfer_full_lifecycle(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cert_app: Application,
    cache_tester,
    http_ok_ip: str,
) -> None:
    """
    arrange: Content-cache with HTTPS backend configured, no certificate-transfer yet.
    act: Integrate certificate-transfer, then remove it.
    assert: Content-cache reaches Active status after integration, then returns to
        WaitingStatus after removal (CA bundle cleared).
    """
    await cache_tester.integrate_config()
    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"https://{http_ok_ip}:443"
    await cache_tester.setup_config(config)

    try:
        await model.integrate(
            f"{cert_app.name}:{CERT_TRANSFER_PROVIDER_ENDPOINT_NAME}",
            f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        )
        await model.wait_for_idle([app.name], status="active", timeout=10 * 60)
        assert app.units[0].workload_status == "active"

        await app.remove_relation(CERTIFICATE_TRANSFER_INTEGRATION_NAME, cert_app.name)
        await model.wait_for_idle([app.name], status="waiting", timeout=5 * 60)
        assert "CA certificate" in app.units[0].workload_status_message
    finally:
        # Ensure the cert relation is removed even if the test fails, so the
        # next test starts with a clean state.  Do NOT use block_until_done=True
        # here: that calls block_until() with no timeout and can hang forever if
        # the relation removal stalls.
        if app.related_applications(CERTIFICATE_TRANSFER_INTEGRATION_NAME):
            await app.remove_relation(CERTIFICATE_TRANSFER_INTEGRATION_NAME, cert_app.name)


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
