# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for HTTPS backend support via certificate_transfer."""

import pytest
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

CERTIFICATE_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"
CERT_PROVIDER_ENDPOINT_NAME = "send-ca-cert"
CACHE_CONFIG_INTEGRATION_NAME = "cache-config"


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
    await cache_tester.configure(backends=f"https://{http_ok_ip}:443")

    await model.integrate(
        f"{cert_app.name}:{CERT_PROVIDER_ENDPOINT_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    await model.wait_for_idle([app.name], status="active", timeout=10 * 60)
    assert app.units[0].workload_status == "active"

    await app.remove_relation(
        CERTIFICATE_TRANSFER_INTEGRATION_NAME, cert_app.name, block_until_done=True
    )
    await model.wait_for_idle([app.name], status="waiting", timeout=5 * 60)
    assert "CA certificate" in app.units[0].workload_status_message


@pytest.mark.skip(reason="TLS termination not yet implemented; see ISD-296 TLS termination story")
async def test_tls_termination_with_certificates_relation(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cache_lego_app: Application,
) -> None:
    """
    arrange: Content-cache integrated with a TLS certificate provider via tls-certificates.
    act: Wait for certificate to be issued.
    assert: Content-cache reaches Active status and serves HTTPS to upstream.

    Note: This test requires the TLS termination story to be implemented in charm.py.
    The certificates relation is declared in metadata.yaml and certificates.py is
    available, but the event handlers are not yet wired up.
    """
