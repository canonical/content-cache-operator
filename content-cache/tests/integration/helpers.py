# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions and classes for integration test."""

import json
import logging
import textwrap
from pathlib import Path

import requests
from juju.application import Application
from juju.model import Model
from juju.unit import Unit

from state import CACHE_CONFIG_INTEGRATION_NAME, CERTIFICATE_INTEGRATION_NAME

logger = logging.getLogger(__name__)

TEST_SERVER_PATH = Path("tests/integration/scripts/test_server.py")

HOSTNAME_CONFIG_NAME = "hostname"
PATH_CONFIG_NAME = "path"
BACKENDS_CONFIG_NAME = "backends"
BACKENDS_PATH_CONFIG_NAME = "backends-path"
PROTOCOL_CONFIG_NAME = "protocol"
FAIL_TIMEOUT_CONFIG_NAME = "fail-timeout"
PROXY_CACHE_VALID_CONFIG_NAME = "proxy-cache-valid"


class TestSetupError(Exception):
    """Represent error in test setup."""


logger = logging.getLogger(__name__)

TEST_SERVER_PATH = Path("tests/integration/scripts/test_server.py")

HOSTNAME_CONFIG_NAME = "hostname"
PATH_CONFIG_NAME = "path"
BACKENDS_CONFIG_NAME = "backends"
BACKENDS_PATH_CONFIG_NAME = "backends-path"
PROTOCOL_CONFIG_NAME = "protocol"
FAIL_TIMEOUT_CONFIG_NAME = "fail-timeout"
PROXY_CACHE_VALID_CONFIG_NAME = "proxy-cache-valid"


class CacheTester:
    """Test content cache.

    Attributes:
        BASE_CONFIG: The base cache configuration.
    """

    BASE_CONFIG = {
        HOSTNAME_CONFIG_NAME: "",
        PATH_CONFIG_NAME: "/",
        BACKENDS_CONFIG_NAME: "",
        BACKENDS_PATH_CONFIG_NAME: "/",
        PROTOCOL_CONFIG_NAME: "https",
        FAIL_TIMEOUT_CONFIG_NAME: "30s",
        PROXY_CACHE_VALID_CONFIG_NAME: "[]",
    }

    def __init__(
        self,
        model: Model,
        app: Application,
        config_app: Application,
        cert_app: Application | None = None,
    ):
        """Initialize the object.

        Args:
            model: The juju model containing the applications.
            app: The content-cache application.
            config_app: The configuration charm application.
            cert_app: The TLS certification charm application.
        """
        self._model = model
        self._app = app
        self._config_app = config_app
        self._cert_app = cert_app

    async def integrate_config(self) -> None:
        """Integrate the configuration application."""
        await self._model.integrate(
            f"{self._config_app.name}:{CACHE_CONFIG_INTEGRATION_NAME}",
            f"{self._app.name}:{CACHE_CONFIG_INTEGRATION_NAME}",
        )

    async def integrate_cert(self) -> None:
        """Integrate the TLS certification application.

        Raises:
            TestSetupError: The TLS certificate application is not provided.
        """
        if self._cert_app is None:
            raise TestSetupError("TLS certificate application not provided")
        await self._model.integrate(
            f"{self._app.name}:{CERTIFICATE_INTEGRATION_NAME}",
            f"{self._cert_app.name}:{CERTIFICATE_INTEGRATION_NAME}",
        )

    async def setup_config(self, configuration: dict[str, str]) -> None:
        """Set up configuration.

        Args:
            configuration: The configuration for the configuration charm.
        """
        await self._config_app.set_config(configuration)

    async def query_cache(
        self, path: str, hostname: str, protocol: str = "http"
    ) -> requests.Response:
        """Test the content cache with a request.

        Args:
            path: The URL path to the content-cache.
            hostname: The hostname of the content-cache.
            protocol: The protocol to make the request.

        Returns:
            Whether the cache is working.
        """
        ip = await get_app_ip(self._app)

        response = requests.get(
            f"{protocol}://{ip}{path}",
            headers={"Host": hostname},
            allow_redirects=False,
            verify=False,
            timeout=300,
        )

        return response

    async def reset(self) -> None:
        """Reset the state of the applications."""
        if self._app.related_applications(CACHE_CONFIG_INTEGRATION_NAME):
            await self._app.remove_relation(
                CACHE_CONFIG_INTEGRATION_NAME, self._config_app.name, True
            )
        if self._app.related_applications(CERTIFICATE_INTEGRATION_NAME):
            await self._app.remove_relation(CERTIFICATE_INTEGRATION_NAME, self._app.name, True)
        await self.reset_config()

    async def reset_config(self) -> None:
        """Reset the configuration of configuration charm application."""
        await self._config_app.set_config(CacheTester.BASE_CONFIG)


async def deploy_http_app(
    app_name: str, path: str, status: int, message: str, model: Model
) -> Application:
    """Deploy a testing HTTP server application for testing.

    The testing HTTP server application is within an any charm instance.

    Args:
        app_name: The application name of the any charm.
        path: The URL path to the test server.
        status: The status code for the test response.
        message: The message in the test response.
        model: The model to deploy the any charm.

    Returns:
        The juju application with the testing HTTP server.
    """
    test_server_content = TEST_SERVER_PATH.read_text()
    any_charm_content = textwrap.dedent(
        f'''
    import os
    import subprocess
    import textwrap
    from pathlib import Path

    from any_charm_base import AnyCharmBase

    SERVICE_NAME = "test-http"
    SERVICE_PATH = Path("/etc/systemd/system/" + SERVICE_NAME + ".service")


    class AnyCharm(AnyCharmBase):
        def _on_start_(self, event):
            test_server_path = Path(os.getcwd()) / "src" / "test_server.py"
            SERVICE_PATH.write_text(
                textwrap.dedent(
                    """
                    [Unit]
                    Description=Test HTTP server
                    After=network.target

                    [Service]
                    Type=simple
                    User=root
                    ExecStart=/usr/bin/env python3 """
                    + str(test_server_path)
                    + """ --path {path} --status {status} --message {message}
                    Restart=on-failure

                    [Install]
                    WantedBy=multi-user.target
                    """
                )
            )
            subprocess.run(["systemctl", "enable", SERVICE_NAME])
            subprocess.run(["systemctl", "start", SERVICE_NAME])

            super()._on_start_(event)
    '''
    )

    src_overwrite = {
        "test_server.py": test_server_content,
        "any_charm.py": any_charm_content,
    }

    app: Application = await model.deploy(
        "any-charm",
        application_name=app_name,
        channel="beta",
        config={"src-overwrite": json.dumps(src_overwrite)},
    )

    return app


async def get_app_ip(app: Application) -> str:
    """Get the IP for a unit of the application.

    Args:
        app: The application to get the public IP.

    Returns:
        The public IP of the application.
    """
    assert app.units
    unit: Unit = app.units[0]
    return await unit.get_public_address()
