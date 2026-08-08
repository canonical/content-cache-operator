# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for HTTPS backend support via certificate_transfer and tls-certificates."""

import jubilant
import pytest

from tests.integration.helpers import (
    BACKENDS_CONFIG_NAME,
    CacheTester,
    get_cache_backends,
    run_in_unit,
)

CERTIFICATE_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"
CERT_TRANSFER_PROVIDER_ENDPOINT_NAME = "send-ca-cert"
CACHE_LEGO_CERT_PROVIDER_ENDPOINT_NAME = "certificates"
CACHE_CONFIG_INTEGRATION_NAME = "cache-config"
CERTIFICATES_INTEGRATION_NAME = "certificates"


def test_certificate_transfer_full_lifecycle(
    juju: jubilant.Juju,
    app: str,
    cert_app: str,
    cache_tester: CacheTester,
    http_ok_ip: str,
) -> None:
    """
    arrange: Content-cache with HTTPS backend configured, no certificate-transfer yet.
    act: Integrate certificate-transfer, then remove it.
    assert: Content-cache reaches Active status after integration, then returns to
        WaitingStatus after removal (CA bundle cleared).
    """
    cache_tester.integrate_config()
    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"https://{http_ok_ip}:443"
    cache_tester.setup_config(config)

    try:
        juju.integrate(
            f"{cert_app}:{CERT_TRANSFER_PROVIDER_ENDPOINT_NAME}",
            f"{app}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        )
        juju.wait(
            lambda s: s.apps[app].units[f"{app}/0"].workload_status.current == "active",
            timeout=10 * 60,
        )
        assert juju.status().apps[app].units[f"{app}/0"].workload_status.current == "active"

        juju.remove_relation(
            f"{app}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
            f"{cert_app}:{CERT_TRANSFER_PROVIDER_ENDPOINT_NAME}",
        )
        juju.wait(
            lambda s: s.apps[app].units[f"{app}/0"].workload_status.current == "waiting",
            timeout=5 * 60,
        )
        assert (
            "CA certificate" in juju.status().apps[app].units[f"{app}/0"].workload_status.message
        )
    finally:
        # Ensure the cert relation is removed even if the test fails, so the
        # next test starts with a clean state.
        try:
            juju.remove_relation(
                f"{app}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
                f"{cert_app}:{CERT_TRANSFER_PROVIDER_ENDPOINT_NAME}",
            )
        except Exception:  # noqa: BLE001
            pass


@pytest.mark.abort_on_fail
def test_tls_termination_full_lifecycle(
    juju: jubilant.Juju,
    app: str,
    cache_lego_app: str,
    cache_tester: CacheTester,
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
    cache_tester.integrate_config()
    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"http://{http_ok_ip}:80"
    cache_tester.setup_config(config)

    juju.integrate(
        f"{cache_lego_app}:{CACHE_LEGO_CERT_PROVIDER_ENDPOINT_NAME}",
        f"{app}:{CERTIFICATES_INTEGRATION_NAME}",
    )
    try:
        juju.wait(
            lambda s: s.apps[app].units[f"{app}/0"].workload_status.current == "active",
            timeout=10 * 60,
        )
        assert juju.status().apps[app].units[f"{app}/0"].workload_status.current == "active"

        unit_name = f"{app}/0"
        backends = get_cache_backends(juju, unit_name)
        assert any(
            b.startswith("https://") for b in backends
        ), f"Expected https:// backend after TLS cert issuance, got: {backends}"

        return_code, ssl_files, _ = run_in_unit(
            juju=juju,
            unit_name=unit_name,
            command="grep -rl ssl /etc/nginx/sites-enabled/ 2>/dev/null || true",
        )
        assert (
            ssl_files and ssl_files.strip()
        ), "No nginx site config with 'ssl' directive found after TLS cert issuance"

        juju.remove_relation(
            f"{app}:{CERTIFICATES_INTEGRATION_NAME}",
            f"{cache_lego_app}:{CACHE_LEGO_CERT_PROVIDER_ENDPOINT_NAME}",
        )
        juju.wait(
            lambda s: s.apps[app].units[f"{app}/0"].workload_status.current == "active",
            timeout=5 * 60,
        )
        assert juju.status().apps[app].units[f"{app}/0"].workload_status.current == "active"

        backends_after = get_cache_backends(juju, unit_name)
        assert any(
            b.startswith("http://") for b in backends_after
        ), f"Expected http:// backend after cert relation removal, got: {backends_after}"
    finally:
        # Ensure the certificates relation is removed even if the test fails.
        try:
            juju.remove_relation(
                f"{app}:{CERTIFICATES_INTEGRATION_NAME}",
                f"{cache_lego_app}:{CACHE_LEGO_CERT_PROVIDER_ENDPOINT_NAME}",
            )
        except Exception:  # noqa: BLE001
            pass
