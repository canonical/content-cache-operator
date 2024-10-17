# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixture for integration tests."""


import logging
from typing import AsyncIterator

import pytest
import pytest_asyncio
from juju.application import Application
from juju.model import Model

logger = logging.getLogger(__name__)

CONFIG_CHARM_NAME = "content-cache-backends-config"


@pytest.fixture(name="app_name", scope="module")
def app_name_fixture() -> str:
    """The application name."""
    return "cache"


@pytest.fixture(name="config_app_name", scope="module")
def config_app_name() -> str:
    """The application name for the configuration charm."""
    return "config"


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
async def app_fixture(model: Model, charm_file: str, app_name: str) -> AsyncIterator[Application]:
    """The content-cache charm application for testing."""
    logger.info("Deploying test cache application %s", app_name)
    app: Application = await model.deploy(charm_file, app_name, base="ubuntu@24.04")
    await model.wait_for_idle([app.name], status="blocked", timeout=15 * 60)
    yield app
    logger.info("Cleaning test cache application %s", app_name)
    await model.remove_application(app_name)


@pytest_asyncio.fixture(name="config_app", scope="module")
async def config_app_fixture(model: Model, config_app_name: str) -> AsyncIterator[Application]:
    """The configuration charm application for testing."""
    logger.info("Deploying test cache application %s", config_app_name)
    app: Application = await model.deploy(
        CONFIG_CHARM_NAME, config_app_name, base="ubuntu@24.04", channel="latest/edge", revision=5
    )
    yield app
    logger.info("Cleaning test cache application %s", config_app_name)
    await model.remove_application(config_app_name)
