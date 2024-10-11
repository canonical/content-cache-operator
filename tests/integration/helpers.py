# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions and classes for integration test."""

import requests
from juju.application import Application
from juju.model import Model
from juju.unit import Unit

from state import CACHE_CONFIG_INTEGRATION_NAME


class CacheTester:
    """Test content cache.

    Attributes:
        TEST_CONFIG: The cache configuration for testing.
    """

    TEST_CONFIG = {
        "hostname": "test.local",
        "path": "/",
        "backends": "20.27.177.113",  # A IP to github.com
        "protocol": "http",
    }

    def __init__(self, model: Model, app: Application, config_app: Application):
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
        await self._model.integrate(
            f"{self._app.name}:{CACHE_CONFIG_INTEGRATION_NAME}",
            f"{self._config_app.name}:{CACHE_CONFIG_INTEGRATION_NAME}",
        )

    async def setup_config(self) -> None:
        """Set up configuration."""
        await self._config_app.set_config(CacheTester.TEST_CONFIG)

    async def test_cache(self) -> bool:
        """Test the content cache with a request.

        Returns:
            Whether the cache is working.
        """
        # Pick a unit from the content cache application for testing.
        assert self._app.units
        unit: Unit = self._app.units[0]
        ip = await unit.get_public_address()

        response = requests.get(
            f"http://{ip}",
            headers={"Host": "test.local"},
            allow_redirects=False,
            verify=False,
            timeout=10,
        )

        # The configuration is set to a IP for github.com.
        # This should return a 301 Moved Permanently.
        return response.status_code == 301

    async def reset(self) -> None:
        """Reset the state of the applications."""
        if self._app.related_applications():
            await self._app.remove_relation(
                CACHE_CONFIG_INTEGRATION_NAME, self._config_app.name, True
            )
        await self._config_app.set_config({})
