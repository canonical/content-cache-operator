# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions and classes for integration test."""

import json
import logging
import textwrap
from pathlib import Path

import requests
from juju.action import Action
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
HEALTHCHECK_INTERVAL_CONFIG_NAME = "healthcheck-interval"
HEALTHCHECK_PATH_CONFIG_NAME = "healthcheck-path"
HEALTHCHECK_SSL_VERIFY_CONFIG_NAME = "healthcheck-ssl-verify"
HEALTHCHECK_VALID_STATUS_CONFIG_NAME = "healthcheck-valid-status"
PROTOCOL_CONFIG_NAME = "protocol"
FAIL_TIMEOUT_CONFIG_NAME = "fail-timeout"
PROXY_CACHE_VALID_CONFIG_NAME = "proxy-cache-valid"


class TestSetupError(Exception):
    """Represent error in test setup."""


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
        config_alt_app: Application,
        cert_app: Application | None = None,
    ):
        """Initialize the object.

        Args:
            model: The juju model containing the applications.
            app: The content-cache application.
            config_app: The configuration charm application.
            config_alt_app: The alternative configuration charm application.
            cert_app: The TLS certification charm application.
        """
        self._model = model
        self._app = app
        self._config_app = config_app
        self._config_alt_app = config_alt_app
        self._cert_app = cert_app
        self._reset_after_run = True

    async def integrate_config(self) -> None:
        """Integrate the configuration application."""
        await self._model.integrate(
            f"{self._config_app.name}:{CACHE_CONFIG_INTEGRATION_NAME}",
            f"{self._app.name}:{CACHE_CONFIG_INTEGRATION_NAME}",
        )

    async def integrate_config_alt(self) -> None:
        """Integrate the alternative configuration application."""
        await self._model.integrate(
            f"{self._config_alt_app.name}:{CACHE_CONFIG_INTEGRATION_NAME}",
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
        """Set up configuration on the configuration charm.

        Args:
            configuration: The configuration for the configuration charm.
        """
        await self._config_app.set_config(configuration)

    async def setup_config_alt(self, configuration: dict[str, str]) -> None:
        """Set up configuration on the alternative configuration charm.

        Args:
            configuration: The configuration for the alternative configuration charm.
        """
        await self._config_alt_app.set_config(configuration)

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
        url = f"{protocol}://{ip}{path}"
        logger.info(f"Querying cache on {url} with Host: {hostname}")

        response = requests.get(
            url,
            headers={"Host": hostname},
            allow_redirects=False,
            verify=False,
            timeout=300,
        )

        return response

    async def reset(self) -> None:
        """Reset the state of the applications."""
        if self._config_app.related_applications(CACHE_CONFIG_INTEGRATION_NAME):
            await self._config_app.remove_relation(
                CACHE_CONFIG_INTEGRATION_NAME, self._app.name, True
            )
        if self._config_alt_app.related_applications(CACHE_CONFIG_INTEGRATION_NAME):
            await self._config_alt_app.remove_relation(
                CACHE_CONFIG_INTEGRATION_NAME, self._app.name, True
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
    import logging
    import os
    import subprocess
    import textwrap
    from pathlib import Path

    from any_charm_base import AnyCharmBase

    SERVICE_NAME = "test-http"
    SERVICE_PATH = Path("/etc/systemd/system/" + SERVICE_NAME + ".service")

    logger = logging.getLogger(__name__)

    class AnyCharm(AnyCharmBase):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.framework.observe(self.on.config_changed, self._on_config_changed)

        def generate_config(self):
            logger.info(f"Configuring {{SERVICE_NAME}} to answer on {path}")
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

        def _on_start_(self, event):
            self.generate_config()

            subprocess.run(["systemctl", "enable", SERVICE_NAME])
            subprocess.run(["systemctl", "start", SERVICE_NAME])

            super()._on_start_(event)

        def _on_config_changed(self, event):
            self.generate_config()
            subprocess.run(["systemctl", "daemon-reload"])
            subprocess.run(["systemctl", "restart", SERVICE_NAME])
    '''
    )

    src_overwrite = {
        "test_server.py": test_server_content,
        "any_charm.py": any_charm_content,
    }

    app: Application
    if app_name in model.applications:
        logging.info(f"Found existing {app_name} application. Reconfiguring it.")
        app = model.applications[app_name]
        await app.set_config({"src-overwrite": json.dumps(src_overwrite)})
    else:
        app = await model.deploy(
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


async def read_file(unit: Unit, path: Path) -> str:
    """Read a file on the Juju unit.

    Args:
        unit: The Juju unit to read file on.
        path: The path of the file to read.

    Returns:
        The file content.
    """
    return_code, stdout, stderr = await run_in_unit(
        unit=unit,
        command=f"if [ -f {path} ]; then cat {path}; else echo ''; fi",
    )
    assert return_code == 0, f"Failed to read file {path}: {stderr}"
    assert stdout is not None, f"Failed to read file {path} to stdout: {stderr}"
    logging.debug("File content of %s: %s", path, stdout)
    return stdout.strip()


async def run_in_unit(
    unit: Unit, command: str, timeout=None
) -> tuple[int, str | None, str | None]:
    """Run a command in the Juju unit.

    Args:
        unit:The Juju unit to run the command in.
        command: The command to run.
        timeout: The time in seconds for the command run to be consider as failure.

    Returns:
        The return code, stdout, and stderr.
    """
    run: Action = await unit.run(command, timeout)
    await run.wait()
    return (
        run.results["return-code"],
        run.results.get("stdout", None),
        run.results.get("stderr", None),
    )
