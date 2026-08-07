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


@pytest.mark.skip(
    reason=(
        "Requires a running Juju model with self-signed-certificates or lego deployed "
        "as cache-lego. Run manually against a live deployment: "
        "juju integrate content-cache:certificates cache-lego:certificates && "
        "juju integrate cache-lego:send-ca-cert haproxy:receive-ca-cert"
    )
)
@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_tls_termination_with_certificates_relation(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cache_lego_app: Application,
) -> None:
    """
    arrange: content-cache integrated with cache-config and cache-lego (tls-certificates).
    act: Wait for TLS cert issuance and active status.
    assert: cache-backends returns https:// URL; nginx config contains ssl directives.
    """


_SKIP_REASON_TLS = (
    "Requires a running Juju model with self-signed-certificates or lego deployed "
    "as cache-lego. Run manually against a live deployment."
)


@pytest.mark.skip(reason=_SKIP_REASON_TLS)
@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_tls_cert_relation_removal_reverts_to_http(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cache_lego_app: Application,
) -> None:
    """
    arrange: content-cache with TLS cert active (ssl in nginx config).
    act: Remove the certificates relation.
    assert: Charm returns to ActiveStatus; cache-backends returns http:// URL.
    """
