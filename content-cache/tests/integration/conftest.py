# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixture for integration tests."""

import asyncio
import logging
import secrets
import time
from collections.abc import Generator

import jubilant
import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import CacheTester, deploy_http_app, get_app_ip

logger = logging.getLogger(__name__)

CONFIG_CHARM_NAME = "content-cache-backends-config"
CERT_CHARM_NAME = "self-signed-certificates"
CACHE_LEGO_CHARM_NAME = "self-signed-certificates"
METRIC_CHARM_NAME = "grafana-agent"

APP_NAME = "cache"
CONFIG_APP_NAME = "config"
CONFIG_ALT_APP_NAME = "config-alt"
CERT_APP_NAME = "cert"
CACHE_LEGO_APP_NAME = "cache-lego"
METRIC_APP_NAME = "metric"


@pytest.fixture(name="charm_file", scope="module")
def charm_file_fixture(pytestconfig: pytest.Config) -> str:
    """Path to the prebuilt charm."""
    file = pytestconfig.getoption("--charm-file")
    assert file, "Please specify the --charm-file"
    return f"./{file}"


@pytest.fixture(name="config_charm_file", scope="module")
def config_charm_file_fixture(ops_test: OpsTest, pytestconfig: pytest.Config) -> str:
    """Build the configuration charm file and return the path."""
    file = pytestconfig.getoption("--config-charm-file")
    if file:
        return file
    path = asyncio.run(ops_test.build_charm("../content-cache-backends-config"))
    return str(path)


@pytest.fixture(name="juju", scope="module")
def juju_fixture() -> Generator[jubilant.Juju, None, None]:
    """A jubilant Juju instance in a temporary model for the test module."""
    with jubilant.temp_model() as juju:
        yield juju


@pytest.fixture(name="applications", scope="module")
def deploy_applications_fixture(
    juju: jubilant.Juju,
    charm_file: str,
    config_charm_file: str,
    pytestconfig: pytest.Config,
) -> dict[str, str]:
    """Deploy all applications and return a mapping of logical name to application name."""
    if pytestconfig.getoption("--no-deploy"):
        return {
            "app": APP_NAME,
            "config": CONFIG_APP_NAME,
            "config_alt": CONFIG_ALT_APP_NAME,
            "cert": CERT_APP_NAME,
            "cache_lego": CACHE_LEGO_APP_NAME,
            "metric": METRIC_APP_NAME,
        }

    juju.deploy(charm_file, APP_NAME, base="ubuntu@24.04")
    juju.deploy(config_charm_file, CONFIG_APP_NAME, base="ubuntu@24.04")
    juju.deploy(config_charm_file, CONFIG_ALT_APP_NAME, base="ubuntu@24.04")
    juju.deploy(CERT_CHARM_NAME, CERT_APP_NAME, channel="latest/edge", base="ubuntu@22.04")
    juju.deploy(
        CACHE_LEGO_CHARM_NAME, CACHE_LEGO_APP_NAME, channel="latest/edge", base="ubuntu@22.04"
    )
    juju.deploy(
        METRIC_CHARM_NAME,
        METRIC_APP_NAME,
        channel="1/stable",
        base="ubuntu@24.04",
    )
    juju.wait(
        lambda s: s.apps[APP_NAME].app_status.current in ("active", "blocked"),
        timeout=15 * 60,
    )
    juju.wait(
        lambda s: s.apps[CERT_APP_NAME].app_status.current == "active"
        and s.apps[CACHE_LEGO_APP_NAME].app_status.current == "active",
        timeout=15 * 60,
    )

    return {
        "app": APP_NAME,
        "config": CONFIG_APP_NAME,
        "config_alt": CONFIG_ALT_APP_NAME,
        "cert": CERT_APP_NAME,
        "cache_lego": CACHE_LEGO_APP_NAME,
        "metric": METRIC_APP_NAME,
    }


@pytest.fixture(name="app", scope="module")
def app_fixture(applications: dict[str, str]) -> str:
    """The content-cache application name."""
    return applications["app"]


@pytest.fixture(name="config_app", scope="module")
def config_app_fixture(applications: dict[str, str]) -> str:
    """The configuration charm application name."""
    return applications["config"]


@pytest.fixture(name="config_alt_app", scope="module")
def config_alt_app_fixture(applications: dict[str, str]) -> str:
    """The alternative configuration charm application name."""
    return applications["config_alt"]


@pytest.fixture(name="cert_app", scope="module")
def cert_app_fixture(applications: dict[str, str]) -> str:
    """The TLS certificate charm application name."""
    return applications["cert"]


@pytest.fixture(name="cache_lego_app", scope="module")
def cache_lego_app_fixture(applications: dict[str, str]) -> str:
    """The cache-side TLS certificate provider charm name."""
    return applications["cache_lego"]


@pytest.fixture(name="metric_app", scope="module")
def metric_app_fixture(applications: dict[str, str]) -> str:
    """The metric agent charm application name."""
    return applications["metric"]


@pytest.fixture(name="http_ok_message", scope="module")
def http_ok_message_fixture() -> str:
    """The message for http_ok_app."""
    return f"test-{secrets.token_urlsafe(2)}"


@pytest.fixture(name="http_ok_app", scope="module")
def http_ok_app_fixture(juju: jubilant.Juju, http_ok_message: str) -> str:
    """The test HTTP application that returns OK."""
    app_name = deploy_http_app(
        juju=juju, app_name="http-ok", path="/", status=200, message=http_ok_message
    )
    juju.wait(lambda s: s.apps[app_name].app_status.current == "active", timeout=15 * 60)
    return app_name


@pytest.fixture(name="https_ok_app", scope="module")
def https_ok_app_fixture(juju: jubilant.Juju, http_ok_message: str) -> str:
    """The test HTTPS application that returns OK."""
    app_name = deploy_http_app(
        juju=juju,
        app_name="https-ok",
        path="/",
        status=200,
        message=http_ok_message,
        https=True,
    )
    juju.wait(lambda s: s.apps[app_name].app_status.current == "active", timeout=15 * 60)
    return app_name


@pytest.fixture(name="http_ok_ip", scope="module")
def http_ok_ip_fixture(juju: jubilant.Juju, http_ok_app: str) -> str:
    """The IP of the test HTTP application."""
    return get_app_ip(juju, http_ok_app)


@pytest.fixture(name="http_ok_ips", scope="module")
def http_ok_ips_fixture(juju: jubilant.Juju, http_ok_app: str) -> list[str]:
    """The IPs of the test HTTP applications (2 units expected)."""
    status = juju.status()
    if len(status.apps[http_ok_app].units) < 2:
        juju.add_unit(http_ok_app, num_units=1)
        juju.wait(lambda s: s.apps[http_ok_app].app_status.current == "active", timeout=10 * 60)
        status = juju.status()

    return [
        unit.public_address
        for unit in status.apps[http_ok_app].units.values()
        if unit.public_address
    ]


@pytest.fixture(name="cache_tester", scope="function")
def cache_tester_fixture(
    juju: jubilant.Juju,
    app: str,
    config_app: str,
    config_alt_app: str,
) -> Generator[CacheTester, None, None]:
    """Get the cache tester."""
    tester = CacheTester(juju, app, config_app, config_alt_app)

    yield tester

    if not tester._reset_after_run:
        return

    tester.reset()

    juju.wait(
        lambda s: s.apps[app].units[f"{app}/0"].workload_status.current == "blocked",
        timeout=10 * 60,
    )
    assert (
        juju.status().apps[app].units[f"{app}/0"].workload_status.message
        == "Waiting for integration with config charm"
    )

    # Poll until subordinate units are removed before next test.
    deadline = 60
    poll_interval = 1
    elapsed = 0
    while elapsed < deadline:
        st = juju.status()
        config_units = st.apps.get(config_app, type("", (), {"units": {}})()).units
        config_alt_units = st.apps.get(config_alt_app, type("", (), {"units": {}})()).units
        if not config_units and not config_alt_units:
            break
        time.sleep(poll_interval)
        elapsed += poll_interval
