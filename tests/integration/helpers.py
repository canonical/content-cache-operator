# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions and classes for integration test."""

from juju.application import Application
from juju.model import Model
from juju.unit import Unit
import requests

from state import CACHE_CONFIG_INTEGRATION_NAME

class CacheTester:
    """Test content cache."""

    TEST_CONFIG = {
        "location": "/",
        "backends": "20.27.177.113",  # A IP to github.com
        "protocol": "http",
    }
    
    def __init__(self, model: Model, app: Application, config_app: Application) -> "CacheTester":
        """Initialize the object.
        
        Args:
            model: The juju model containing the applications.
            app: The content-cache application.
            config_app: The configuration charm application.
        """
        self._model = model
        self._app = app
        self._config_app = config_app

    async def integrate(self) -> None:
        """Integrate the applications."""
        await self._model.integrate(f"{self._app.name}:{CACHE_CONFIG_INTEGRATION_NAME}", f"{self._config_app.name}:{CACHE_CONFIG_INTEGRATION_NAME}")
    
    async def setup_config(self) -> None:
        """Set up configuration."""
        await self._config_app.set_config(CacheTester.TEST_CONFIG)

    async def test_cache(self) -> bool:
        """Test the content cache with a request."""
        # Pick a unit from the content cache application for testing.
        assert self._app.units
        unit: Unit = self._app.units[0]
        
        ip = await unit.get_public_address()
        import pytest
        pytest.set_trace()
        requests.get(f'http://{ip}')
    
    async def reset(self) -> None:
        """Reset the state of the applications."""
        if self._app.related_applications():
            import pytest
            pytest.set_trace()
            await self._app.remove_relation(CACHE_CONFIG_INTEGRATION_NAME, self._config_app.name, True)
        await self._config_app.set_config({})
        