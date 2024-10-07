# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the content-cache charm."""

import ops
import pytest
from juju.application import Application
from juju.model import Model

from tests.integration.helpers import CacheTester


@pytest.mark.asyncio
async def test_charm_start(app: Application, config_app: Application, model: Model) -> None:
    """
    arrange: The applications deployed.
    act: Nothing.
    assert: The applications in blocked status waiting for integration.
    """
    assert len(app.units) == 1
    assert len(config_app.units) == 1
    unit = app.units[0]
    config_unit = config_app.units[0]
    assert unit.workload_status_message == "Waiting for integration with config charm"
    assert config_unit.workload_status_message == "Empty backends configuration found"


@pytest.mark.asyncio
async def test_charm_integrate_with_no_data(app: Application, config_app: Application, model: Model) -> None:
    """
    arrange: A working application of content-cache charm, with no integrations.
    act:
        1. Integrate with a charm that provides configuration.
        2. Add configuration to the charm that provides data.
    assert:
        1. The application in blocked status waiting for integration.
        2. The request to the cache should succeed.
    """
    await config_app.set_config({})
    cache_tester = CacheTester(model, app, config_app)

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
    await cache_tester.test_cache()
    
    # Cleanup
    await cache_tester.reset()
    
    


@pytest.mark.asyncio
async def test_charm_integrate_with_data(
    app: Application, config_app: Application, model: Model
) -> None:
    """
    arrange: A working application of content-cache charm, with no integrations.
    act: Integrate with a charm that provides configuration.
    assert: The application in blocked status waiting for integration.
    """
    cache_tester = CacheTester(model, app, config_app)
    await cache_tester.setup_config()
    await cache_tester.integrate()

    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=5 * 60)
    await cache_tester.test_cache()

    # Cleanup
    await cache_tester.reset()