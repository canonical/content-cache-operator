# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for HTTPS backend support via certificate_transfer."""

import pytest
import pytest_asyncio
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

CERTIFICATE_TRANSFER_INTEGRATION_NAME = "certificate-transfer"
CACHE_CONFIG_INTEGRATION_NAME = "cache-config"


@pytest_asyncio.fixture(name="cert_transfer_integration_id", scope="function")
async def cert_transfer_integration_id_fixture(
    model: Model,
    app: Application,
    cert_app: Application,
) -> str:
    """Integration ID after adding certificate-transfer relation."""
    await model.integrate(
        f"{cert_app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    # Return a tag to identify this integration for cleanup
    return f"{cert_app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}"


async def test_https_backends_without_cert_sets_waiting(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cache_tester,
    http_ok_ip: str,
) -> None:
    """
    arrange: Content-cache with no certificate-transfer relation.
    act: Configure HTTPS backend URLs.
    assert: Content-cache enters WaitingStatus waiting for CA certificate.
    """
    await cache_tester.integrate_config()
    await cache_tester.configure(backends=f"https://{http_ok_ip}:443")
    await model.wait_for_idle([app.name], status="waiting", timeout=10 * 60)

    unit = app.units[0]
    assert "CA certificate" in unit.workload_status_message


async def test_https_backend_with_certificate_transfer(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cert_app: Application,
    cache_tester,
    http_ok_ip: str,
) -> None:
    """
    arrange: Content-cache with HTTPS backend configured.
    act: Integrate certificate-transfer.
    assert: Content-cache reaches Active status.
    """
    await cache_tester.integrate_config()
    await cache_tester.configure(backends=f"https://{http_ok_ip}:443")
    await model.wait_for_idle([app.name], status="waiting", timeout=10 * 60)

    await model.integrate(
        f"{cert_app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    await model.wait_for_idle([app.name], status="active", timeout=10 * 60)

    unit = app.units[0]
    assert unit.workload_status == "active"


async def test_certificate_transfer_removal_clears_trust(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cert_app: Application,
    cache_tester,
    http_ok_ip: str,
) -> None:
    """
    arrange: Content-cache active with HTTPS backend and certificate-transfer integrated.
    act: Remove the certificate-transfer relation.
    assert: Content-cache moves to WaitingStatus (CA bundle cleared).
    """
    await cache_tester.integrate_config()
    await cache_tester.configure(backends=f"https://{http_ok_ip}:443")
    await model.integrate(
        f"{cert_app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    await model.wait_for_idle([app.name], status="active", timeout=10 * 60)

    await model.remove_relation(
        f"{cert_app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    await model.wait_for_idle([app.name], status="waiting", timeout=5 * 60)

    unit = app.units[0]
    assert "CA certificate" in unit.workload_status_message
