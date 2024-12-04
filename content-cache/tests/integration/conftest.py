# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixture for integration tests."""

import logging
import secrets
from typing import AsyncIterator

import pytest
import pytest_asyncio
from juju.application import Application
from juju.model import Model

from tests.integration.helpers import CacheTester, deploy_http_app, get_app_ip

logger = logging.getLogger(__name__)

CONFIG_CHARM_NAME = "content-cache-backends-config"
CERT_CHARM_NAME = "self-signed-certificates"


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


@pytest.fixture(name="charm_file", scope="module")
def charm_file_fixture(pytestconfig: pytest.Config) -> str:
    """Path to the prebuilt charm."""
    file = pytestconfig.getoption("--charm-file")
    assert file, "Please specify the --charm-file"
    return f"./{file}"


@pytest_asyncio.fixture(name="model", scope="module")
async def model_fixture(ops_test) -> AsyncIterator[Model]:
    """The juju model for testing."""
    yield ops_test.model


@pytest_asyncio.fixture(name="app", scope="module")
async def app_fixture(
    model: Model, charm_file: str, app_name: str, pytestconfig: pytest.Config
) -> AsyncIterator[Application]:
    """The content-cache charm application for testing."""
    use_existing = pytestconfig.getoption("--use-existing-app", default=[])
    if use_existing and app_name in use_existing:
        yield model.applications[app_name]
        return

    app: Application = await model.deploy(charm_file, app_name, base="ubuntu@24.04")
    await model.wait_for_idle([app.name], status="blocked", timeout=15 * 60)
    yield app


@pytest_asyncio.fixture(name="config_app", scope="module")
async def config_app_fixture(
    model: Model, config_app_name: str, pytestconfig: pytest.Config
) -> AsyncIterator[Application]:
    """The configuration charm application for testing."""
    use_existing = pytestconfig.getoption("--use-existing-app", default=[])
    if use_existing and config_app_name in use_existing:
        yield model.applications[config_app_name]
        return

    app: Application = await model.deploy(
        CONFIG_CHARM_NAME,
        config_app_name,
        base="ubuntu@24.04",
        channel="latest/edge",
        revision=5,
    )
    yield app


@pytest_asyncio.fixture(name="cert_app", scope="module")
async def cert_app_fixture(
    model: Model, cert_app_name: str, pytestconfig: pytest.Config
) -> AsyncIterator[Application]:
    """The TLS certificate charm application for testing."""

    use_existing = pytestconfig.getoption("--use-existing-app", default=[])
    if use_existing and app.name in use_existing:
        yield model.applications[app.name]
        return

    app: Application = await model.deploy(
        CERT_CHARM_NAME, cert_app_name, base="ubuntu@22.04", channel="latest/edge"
    )
    await model.wait_for_idle([app.name], status="active", timeout=15 * 60)
    yield app


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
    return await get_app_ip(http_ok_app)


@pytest_asyncio.fixture(name="cache_tester", scope="function")
async def cache_tester_fixture(
    model: Model, app: Application, config_app: Application, cert_app: Application
) -> AsyncIterator[CacheTester]:
    unit = app.units[0]
    tester = CacheTester(model, app, config_app, cert_app)

    yield tester

    # This removes the integration and configurations.
    await tester.reset()

    await model.wait_for_idle([app.name], status="blocked", timeout=5 * 60)
    assert unit.workload_status_message == "Waiting for integration with config charm"
    # The configuration charm is removed due to being subordinate charm with no relation.
