# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for the content-cache's active healthchecks."""

import base64
import time
from pathlib import Path

import jubilant
import pytest
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate

from nginx_manager import NGINX_BACKENDS_STATUS_URL_PATH
from tests.integration.helpers import (
    BACKEND_CA_FINGERPRINT_CONFIG_NAME,
    BACKEND_HOSTNAME_CONFIG_NAME,
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
TEST_SERVER_CERTIFICATE = Path("tests/integration/scripts/certificate.pem")

HEALTHCHECK_INTERVAL = 2000


def _get_cert_fingerprint(cert_pem: str) -> str:
    """Return the SHA-256 fingerprint of a PEM-encoded certificate.

    Args:
        cert_pem: PEM-encoded certificate (cert-only, no private key).

    Returns:
        Colon-separated uppercase hex SHA-256 fingerprint.
    """
    cert = load_pem_x509_certificate(cert_pem.encode())
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def _extract_cert_pem(combined_pem: str) -> str:
    """Extract only the certificate portion from a combined cert+key PEM string.

    Args:
        combined_pem: PEM string that may contain both certificate and private key.

    Returns:
        PEM string with only the certificate block(s).
    """
    lines = combined_pem.splitlines(keepends=True)
    cert_lines: list[str] = []
    in_cert = False
    for line in lines:
        if line.startswith("-----BEGIN CERTIFICATE-----"):
            in_cert = True
        if in_cert:
            cert_lines.append(line)
        if line.startswith("-----END CERTIFICATE-----"):
            in_cert = False
    return "".join(cert_lines)


def _install_ca_cert_on_unit(juju: jubilant.Juju, unit_name: str, cert_pem: str) -> None:
    """Install a CA certificate to the system CA store on a juju unit.

    Args:
        juju: The jubilant Juju instance.
        unit_name: The unit to install the cert on (e.g. "content-cache/0").
        cert_pem: PEM-encoded CA certificate to install.
    """
    encoded = base64.b64encode(cert_pem.encode()).decode()
    juju.exec(
        f"bash -c 'echo {encoded} | base64 -d"
        " > /usr/local/share/ca-certificates/test-backend.crt"
        " && update-ca-certificates'",
        unit=unit_name,
    )


def get_nginx_status(juju: jubilant.Juju, app: str, path: str) -> str:
    """Fetch and returns the content of the status page.

    Args:
        juju: The jubilant Juju instance.
        app: The application name to connect to.
        path: The path to the status page.

    Returns:
        The content of the status page.

    Raises:
        RuntimeError: if status cannot be fetched.
    """
    unit_name = f"{app}/0"
    result = juju.exec(f"curl 127.0.0.1/{path}", unit=unit_name)
    if result.return_code:
        raise RuntimeError(f"Couldn't fetch status page on {path}: {result.stderr}")
    return result.stdout


@pytest.mark.abort_on_fail
def test_healthchecks_healthy(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    cache_tester: CacheTester,
    http_ok_message: str,
    http_ok_ips: list[str],
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
    cache_tester.setup_config(config)
    cache_tester.integrate_config()
    juju.wait(lambda s: jubilant.all_active(s, app, config_app), timeout=10 * 60)

    response = cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    status = get_nginx_status(juju, app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 UP" in status
    assert f"{http_ok_ips[1]}:80 UP" in status

    cache_tester._reset_after_run = False


@pytest.mark.abort_on_fail
def test_healthchecks_one_unhealthy(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    cache_tester: CacheTester,
    http_ok_message: str,
    http_ok_ips: list[str],
) -> None:
    """
    arrange: Two backends responding 200 on their healthchecks.
    act: Turn one backend unhealthy.
    assert: HTTP request should succeed. One backend is reported UP. One backend is reported DOWN.
    """
    requests.get(f"http://{http_ok_ips[0]}/turn-unhealthy")
    time.sleep(4 * HEALTHCHECK_INTERVAL / 1000)

    status = get_nginx_status(juju, app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 DOWN" in status
    assert f"{http_ok_ips[1]}:80 UP" in status

    response = cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")

    cache_tester._reset_after_run = False


@pytest.mark.abort_on_fail
def test_healthchecks_one_recovery(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    cache_tester: CacheTester,
    http_ok_message: str,
    http_ok_ips: list[str],
) -> None:
    """
    arrange: Two backends. One responding 200 on its healthcheck, and the other 500.
    act: Bring back the faulty backend to a healthy state.
    assert: HTTP request should succeed. Two backends are reported up.
    """
    requests.get(f"http://{http_ok_ips[0]}/turn-healthy")
    time.sleep(3 * HEALTHCHECK_INTERVAL / 1000)

    status = get_nginx_status(juju, app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 UP" in status
    assert f"{http_ok_ips[1]}:80 UP" in status

    response = cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 200
    assert http_ok_message in response.content.decode("utf-8")


@pytest.mark.abort_on_fail
def test_healthchecks_all_unhealthy(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    cache_tester: CacheTester,
    http_ok_message: str,
    http_ok_ips: list[str],
) -> None:
    """
    arrange: Two healthy backends.
    act: Turn both backends unhealthy.
    assert: HTTP request should fail with 502. Both backends are reported DOWN.
    """
    requests.get(f"http://{http_ok_ips[0]}/turn-unhealthy")
    requests.get(f"http://{http_ok_ips[1]}/turn-unhealthy")
    time.sleep(5 * HEALTHCHECK_INTERVAL / 1000)

    status = get_nginx_status(juju, app, path=NGINX_BACKENDS_STATUS_URL_PATH)
    assert f"{http_ok_ips[0]}:80 DOWN" in status
    assert f"{http_ok_ips[1]}:80 DOWN" in status

    response = cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == 502


@pytest.mark.parametrize(
    ["valid_status", "expected_http_code"],
    [
        pytest.param("200", 502, id="unhealthy"),
        pytest.param("200, 418", 200, id="healthy"),
    ],
)
@pytest.mark.abort_on_fail
def test_healthchecks_custom_status(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    cache_tester: CacheTester,
    http_ok_message: str,
    http_ok_ip: str,
    valid_status: str,
    expected_http_code: int,
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
    cache_tester.setup_config(config)
    cache_tester.integrate_config()
    juju.wait(lambda s: jubilant.all_active(s, app, config_app), timeout=10 * 60)

    time.sleep(5 * HEALTHCHECK_INTERVAL / 1000)

    response = cache_tester.query_cache(path="/", protocol="http")
    assert response.status_code == expected_http_code

    if expected_http_code == 200:
        assert http_ok_message in response.content.decode("utf-8")


@pytest.mark.parametrize(
    ["ssl_verify", "expected_http_code"],
    [
        pytest.param("false", 200, id="no_ssl_verify"),
        pytest.param("true", 200, id="ssl_verify"),
    ],
)
@pytest.mark.abort_on_fail
def test_healthchecks_ssl_verify(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    cert_app: str,
    cache_tester: CacheTester,
    http_ok_message: str,
    https_ok_app: str,
    ssl_verify: str,
    expected_http_code: int,
) -> None:
    """
    arrange: One backend responding on HTTPS. SSL verify option set.
        backend-hostname=localhost and backend-ca-fingerprint set; cert installed to
        system CA store on the content-cache unit.
    act: Nothing.
    assert: HTTP request should succeed with SSL verification enabled for the backend.
    """
    https_ok_ip = get_app_ip(juju, https_ok_app)

    # Compute fingerprint and install the test server's CA cert to the system CA store.
    combined_pem = TEST_SERVER_CERTIFICATE.read_text()
    cert_pem = _extract_cert_pem(combined_pem)
    fingerprint = _get_cert_fingerprint(cert_pem)
    _install_ca_cert_on_unit(juju, f"{app}/0", cert_pem)

    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"https://{https_ok_ip}:443"
    config[BACKEND_HOSTNAME_CONFIG_NAME] = "localhost"
    config[BACKEND_CA_FINGERPRINT_CONFIG_NAME] = fingerprint
    config[HEALTHCHECK_PATH_CONFIG_NAME] = "/health"
    config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = str(HEALTHCHECK_INTERVAL)
    config[HEALTHCHECK_SSL_VERIFY_CONFIG_NAME] = ssl_verify
    config[HEALTHCHECK_VALID_STATUS_CONFIG_NAME] = "200"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'

    juju.integrate(
        f"{cert_app}:{CERT_TRANSFER_PROVIDER_ENDPOINT_NAME}",
        f"{app}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    try:
        cache_tester.setup_config(config)
        cache_tester.integrate_config()
        juju.wait(lambda s: jubilant.all_active(s, app, config_app), timeout=10 * 60)

        time.sleep(5 * HEALTHCHECK_INTERVAL / 1000)

        response = cache_tester.query_cache(path="/", protocol="http")
        assert response.status_code == expected_http_code

        if expected_http_code == 200:
            assert http_ok_message in response.content.decode("utf-8")
    finally:
        # Always remove the cert integration so the next parametrised run can
        # re-add it cleanly. Without this, the second run would find the
        # relation already exists and fail before integrate_config() is called,
        # leaving content-cache stuck in "Waiting for integration with config
        # charm" state.
        juju.remove_relation(
            f"{app}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
            f"{cert_app}:{CERT_TRANSFER_PROVIDER_ENDPOINT_NAME}",
        )
