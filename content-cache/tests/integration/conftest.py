# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixture for integration tests."""


import asyncio
import logging
import secrets
from typing import AsyncIterator, List

import pytest
import pytest_asyncio
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import CacheTester, deploy_http_app, get_app_ip

logger = logging.getLogger(__name__)

CONFIG_CHARM_NAME = "content-cache-backends-config"
CERT_CHARM_NAME = "self-signed-certificates"
METRIC_CHARM_NAME = "grafana-agent"


@pytest.fixture(name="app_name", scope="module")
def app_name_fixture() -> str:
    """The application name."""
    return "cache"


@pytest.fixture(name="config_app_name", scope="module")
def config_app_name_fixture() -> str:
    """The application name for the configuration charm."""
    return "config"


@pytest.fixture(name="cert_app_name", scope="module")
def cert_app_name_fixture() -> str:
    """The application name for the TLS certificate charm."""
    return "cert"


@pytest.fixture(name="metric_app_name", scope="module")
def metric_app_name_fixture() -> str:
    """The application name of the metric export charm."""
    return "metric"


@pytest.fixture(name="charm_file", scope="module")
def charm_file_fixture(pytestconfig: pytest.Config) -> str:
    """Path to the prebuilt charm."""
    file = pytestconfig.getoption("--charm-file")
    assert file, "Please specify the --charm-file"
    return f"./{file}"


@pytest_asyncio.fixture(name="config_charm_file", scope="module")
async def config_charm_file_fixture(
    ops_test: OpsTest, pytestconfig: pytest.Config
) -> AsyncIterator[str]:
    """Build the configuration charm file and return the path."""
    file = pytestconfig.getoption("--config-charm-file")
    if file:
        yield file
        return

    path = await ops_test.build_charm("../content-cache-backends-config")
    yield str(path)


@pytest_asyncio.fixture(name="model", scope="module")
async def model_fixture(ops_test) -> AsyncIterator[Model]:
    """The juju model for testing."""
    yield ops_test.model


@pytest_asyncio.fixture(name="applications", scope="module")
async def deploy_applications_fixture(
    model: Model,
    charm_file: str,
    config_charm_file: str,
    app_name: str,
    config_app_name: str,
    cert_app_name: str,
    metric_app_name: str,
    pytestconfig: pytest.Config,
) -> AsyncIterator[dict[str, Application]]:
    """Deploy all applications in parallel."""
    if pytestconfig.getoption("--no-deploy"):
        try:
            res = {
                app_name: model.applications[app_name],
                config_app_name: model.applications[config_app_name],
                cert_app_name: model.applications[cert_app_name],
                metric_app_name: model.applications[metric_app_name],
            }
        except KeyError:
            raise RuntimeError("At least one app is missing, you cannot use --no-deploy.")
        yield res
        return

    app_deploy = model.deploy(charm_file, app_name, base="ubuntu@24.04")
    config_app_deploy = model.deploy(
        config_charm_file, config_app_name, base="ubuntu@24.04", num_units=0
    )
    cert_app_deploy = model.deploy(
        CERT_CHARM_NAME, cert_app_name, channel="latest/edge", base="ubuntu@22.04"
    )
    # The pinning to revision 319 due to a `model.deploy` issue. Ideally, the revision is not
    # pinned. The `model.deploy` is unable to resolve to a workable revision, hence hardcoding to
    # revision 319.
    metric_app_deploy = model.deploy(
        METRIC_CHARM_NAME,
        metric_app_name,
        channel="latest/edge",
        base="ubuntu@24.04",
        revision=319,
        num_units=0,
    )
    app, config_app, cert_app, metric_app = await asyncio.gather(
        app_deploy, config_app_deploy, cert_app_deploy, metric_app_deploy
    )
    await model.wait_for_idle([app.name], status="blocked", timeout=15 * 60)
    await model.wait_for_idle([cert_app.name], status="active", timeout=15 * 60)
    yield {
        app_name: app,
        config_app_name: config_app,
        cert_app_name: cert_app,
        metric_app_name: metric_app,
    }


@pytest_asyncio.fixture(name="app", scope="module")
async def app_fixture(
    app_name: str, applications: dict[str, Application]
) -> AsyncIterator[Application]:
    """The content-cache charm application for testing."""
    yield applications[app_name]


@pytest_asyncio.fixture(name="config_app", scope="module")
async def config_app_fixture(
    config_app_name: str, applications: dict[str, Application]
) -> AsyncIterator[Application]:
    """The configuration charm application for testing."""
    yield applications[config_app_name]


@pytest_asyncio.fixture(name="cert_app", scope="module")
async def cert_app_fixture(
    cert_app_name: str, applications: dict[str, Application]
) -> AsyncIterator[Application]:
    """The TLS certificate charm application for testing."""
    yield applications[cert_app_name]


@pytest_asyncio.fixture(name="metric_app", scope="module")
async def metric_app_fixture(
    metric_app_name: str, applications: dict[str, Application]
) -> AsyncIterator[Application]:
    """The metric agent charm application for testing."""
    yield applications[metric_app_name]


@pytest.fixture(name="http_ok_path", scope="module")
def http_ok_path_fixture() -> str:
    """The path for http_ok_app."""
    return f"/test-{secrets.token_urlsafe(4)}"


@pytest.fixture(name="http_ok_message", scope="module")
def http_ok_message_fixture() -> str:
    """The message for http_ok_app."""
    return f"test-{secrets.token_urlsafe(2)}"


@pytest_asyncio.fixture(name="http_ok_app", scope="module")
async def http_ok_app_fixture(
    model: Model, http_ok_path: str, http_ok_message: str, pytestconfig: pytest.Config
) -> AsyncIterator[Application]:
    """The test HTTP application that returns OK."""
    use_existing = pytestconfig.getoption("--use-existing-app", default=[])
    if use_existing and "http-ok" in use_existing:
        yield model.applications["http-ok"]
        return

    app = await deploy_http_app(
        app_name="http-ok", path=http_ok_path, status=200, message=http_ok_message, model=model
    )
    await model.wait_for_idle([app.name], status="active", timeout=15 * 60)

    yield app


@pytest_asyncio.fixture(name="http_ok_ip", scope="module")
async def http_ok_ip_fixture(http_ok_app: Application) -> str:
    """The IP to the test HTTP application that returns OK."""
    return await get_app_ip(http_ok_app)


@pytest_asyncio.fixture(name="http_ok_ips", scope="module")
async def http_ok_ips_fixture(model: Model, http_ok_app: Application) -> List[str]:
    """The IPs of the test HTTP applications (2 units expected)"""
    if len(http_ok_app.units) < 2:
        await http_ok_app.add_unit(1)
        await model.wait_for_idle([http_ok_app.name], status="active", timeout=10 * 60)

    ips = []
    for unit in http_ok_app.units:
        ips.append(await unit.get_public_address())

    return ips


@pytest_asyncio.fixture(name="cache_tester", scope="function")
async def cache_tester_fixture(
    model: Model, app: Application, config_app: Application, cert_app: Application
) -> AsyncIterator[CacheTester]:
    """Get the cache tester."""
    unit = app.units[0]
    tester = CacheTester(model, app, config_app, cert_app)

    yield tester

    if not tester._reset_after_run:
        return

    # This removes the integration and configurations.
    await tester.reset()

    await model.wait_for_idle([app.name], status="blocked", timeout=10 * 60)
    assert unit.workload_status_message == "Waiting for integration with config charm"
    # The configuration charm is removed due to being subordinate charm with no relation.
