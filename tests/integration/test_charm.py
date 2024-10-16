# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the content-cache charm."""

import pytest
from juju.application import Application
from juju.model import Model

from tests.integration.helpers import CacheTester


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_start(app: Application, config_app: Application, model: Model) -> None:
    """
    arrange: The applications deployed.
    act: Nothing.
    assert: The applications in blocked status waiting for integration.
    """
    assert len(app.units) == 1
    unit = app.units[0]
    assert unit.workload_status_message == "Waiting for integration with config charm"


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_integrate_with_no_data(
    app: Application, config_app: Application, model: Model
) -> None:
    """
    arrange: A working application of content-cache charm, with no integrations.
    act:
        1. Integrate with the configuration charm.
        2. Add configuration to the configuration charm.
    assert:
        1. The application in blocked status waiting for integration.
        2. The request to the cache should succeed.
    """
    cache_tester = CacheTester(model, app, config_app)
    await cache_tester.reset()

    # 1.
    await cache_tester.integrate()
    await model.wait_for_idle([app.name, config_app.name], status="blocked", timeout=5 * 60)
    assert len(app.units) == 1
    assert len(config_app.units) == 1
    unit = app.units[0]
    config_unit = config_app.units[0]
    assert unit.workload_status_message == "Waiting for integration with config charm"
    assert config_unit.workload_status_message == "Empty backends configuration found"

    # 2.
    await cache_tester.setup_config()
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=5 * 60)
    assert await cache_tester.test_cache()

    # Cleanup
    await cache_tester.reset()


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_charm_integrate_with_data(
    app: Application, config_app: Application, model: Model
) -> None:
    """
    arrange: A working application of content-cache charm, with no integrations.
    act:
        1. Integrate with the configuration charm with configuration set.
        2. Remove the configuration on the configuration charm.
        3. Remove the integration between the charms.
    assert:
        1. The request to the cache should succeed.
        2. The configuration charm should be in blocked state. The content-cache charm will be
            serving according to the old configuration.
        3. The application in blocked status waiting for integration.
    """
    cache_tester = CacheTester(model, app, config_app)
    await cache_tester.setup_config()
    await cache_tester.integrate()

    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=5 * 60)
    assert await cache_tester.test_cache()

    await cache_tester.reset_config()

    # The configuration update should fail on the configuration charm, and enter blocked state.
    # Since the integration data is not updated, the content-cache charm will continue serve the
    # site, according to the old configuration.
    await model.wait_for_idle([app.name], status="active", timeout=5 * 60)
    await model.wait_for_idle([config_app.name], status="blocked", timeout=5 * 60)
    assert len(app.units) == 1
    assert len(config_app.units) == 1
    unit = app.units[0]
    config_unit = config_app.units[0]
    assert unit.workload_status_message == ""
    assert config_unit.workload_status_message == "Empty backends configuration found"
    assert await cache_tester.test_cache()

    # This removes the integration and configurations.
    await cache_tester.reset()

    await model.wait_for_idle([app.name], status="blocked", timeout=5 * 60)
    assert unit.workload_status_message == "Waiting for integration with config charm"
    # The configuration charm is removed due to being subordinate charm with no relation.
