# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions and classes for integration test."""

import json
import logging
import textwrap
from pathlib import Path

import jubilant
import requests

from state import CACHE_CONFIG_INTEGRATION_NAME

logger = logging.getLogger(__name__)

TEST_SERVER_PATH = Path("tests/integration/scripts/test_server.py")
TEST_SERVER_CERTIFICATE = Path("tests/integration/scripts/certificate.pem")

BACKENDS_CONFIG_NAME = "backends"
HEALTHCHECK_INTERVAL_CONFIG_NAME = "healthcheck-interval"
HEALTHCHECK_PATH_CONFIG_NAME = "healthcheck-path"
HEALTHCHECK_SSL_VERIFY_CONFIG_NAME = "healthcheck-ssl-verify"
HEALTHCHECK_VALID_STATUS_CONFIG_NAME = "healthcheck-valid-status"
FAIL_TIMEOUT_CONFIG_NAME = "fail-timeout"
PROXY_CACHE_VALID_CONFIG_NAME = "proxy-cache-valid"


class CacheTester:
    """Test content cache.

    Attributes:
        BASE_CONFIG: The base cache configuration.
    """

    BASE_CONFIG = {
        BACKENDS_CONFIG_NAME: "",
        FAIL_TIMEOUT_CONFIG_NAME: "30s",
        PROXY_CACHE_VALID_CONFIG_NAME: "[]",
    }

    def __init__(
        self,
        juju: jubilant.Juju,
        app: str,
        config_app: str,
        config_alt_app: str,
    ):
        """Initialize the object.

        Args:
            juju: The jubilant Juju instance.
            app: The content-cache application name.
            config_app: The configuration charm application name.
            config_alt_app: The alternative configuration charm application name.
        """
        self._juju = juju
        self._app = app
        self._config_app = config_app
        self._config_alt_app = config_alt_app
        self._reset_after_run = True

    def integrate_config(self) -> None:
        """Integrate the configuration application."""
        self._juju.integrate(
            f"{self._config_app}:{CACHE_CONFIG_INTEGRATION_NAME}",
            f"{self._app}:{CACHE_CONFIG_INTEGRATION_NAME}",
        )

    def integrate_config_alt(self) -> None:
        """Integrate the alternative configuration application."""
        self._juju.integrate(
            f"{self._config_alt_app}:{CACHE_CONFIG_INTEGRATION_NAME}",
            f"{self._app}:{CACHE_CONFIG_INTEGRATION_NAME}",
        )

    def setup_config(self, configuration: dict[str, str]) -> None:
        """Set up configuration on the configuration charm.

        Args:
            configuration: The configuration for the configuration charm.
        """
        self._juju.config(self._config_app, configuration)

    def setup_config_alt(self, configuration: dict[str, str]) -> None:
        """Set up configuration on the alternative configuration charm.

        Args:
            configuration: The configuration for the alternative configuration charm.
        """
        self._juju.config(self._config_alt_app, configuration)

    def query_cache(
        self, path: str, port: int = 8080, protocol: str = "http"
    ) -> requests.Response:
        """Test the content cache with a request.

        Args:
            path: The URL path to the content-cache.
            port: The nginx listening port allocated for the relation.
            protocol: The protocol to make the request.

        Returns:
            The HTTP response from the cache.
        """
        ip = get_app_ip(self._juju, self._app)
        url = f"{protocol}://{ip}:{port}{path}"
        logger.info("Querying cache on %s", url)

        response = requests.get(
            url,
            allow_redirects=False,
            verify=False,
            timeout=300,
        )

        return response

    def reset(self) -> None:
        """Reset the state of the applications."""
        st = self._juju.status()
        if self._config_app in st.apps:
            config_app_data = st.apps[self._config_app]
            if any(
                CACHE_CONFIG_INTEGRATION_NAME in r
                for r in getattr(config_app_data, "relations", {})
            ):
                self._juju.remove_relation(
                    f"{self._config_app}:{CACHE_CONFIG_INTEGRATION_NAME}",
                    f"{self._app}:{CACHE_CONFIG_INTEGRATION_NAME}",
                )
        if self._config_alt_app in st.apps:
            config_alt_app_data = st.apps[self._config_alt_app]
            if any(
                CACHE_CONFIG_INTEGRATION_NAME in r
                for r in getattr(config_alt_app_data, "relations", {})
            ):
                self._juju.remove_relation(
                    f"{self._config_alt_app}:{CACHE_CONFIG_INTEGRATION_NAME}",
                    f"{self._app}:{CACHE_CONFIG_INTEGRATION_NAME}",
                )
        self.reset_config()

    def reset_config(self) -> None:
        """Reset the configuration of configuration charm application."""
        self._juju.config(self._config_app, CacheTester.BASE_CONFIG)


def deploy_http_app(
    juju: jubilant.Juju,
    app_name: str,
    path: str,
    status: int,
    message: str,
    https: bool = False,
) -> str:
    """Deploy a testing HTTP server application for testing.

    Args:
        juju: The jubilant Juju instance.
        app_name: The application name of the any charm.
        path: The URL path to the test server.
        status: The status code for the test response.
        message: The message in the test response.
        https: Run server in HTTPS mode on port 443.

    Returns:
        The application name.
    """
    if https:
        port = 443
        flags = "--https"
    else:
        port = 80
        flags = ""

    test_server_content = TEST_SERVER_PATH.read_text()
    certificate_content = TEST_SERVER_CERTIFICATE.read_text()
    any_charm_content = textwrap.dedent(f"""
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
                    \"\"\"
                    [Unit]
                    Description=Test HTTP server
                    After=network.target

                    [Service]
                    Type=simple
                    User=root
                    ExecStart=/usr/bin/env python3 \"\"\"
                    + str(test_server_path)
                    + \"\"\" --path {path} --status {status} --message {message} --port {port} {flags}
                    Restart=on-failure

                    [Install]
                    WantedBy=multi-user.target
                    \"\"\"
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
    """)

    src_overwrite = {
        "test_server.py": test_server_content,
        "any_charm.py": any_charm_content,
        "certificate.pem": certificate_content,
    }

    juju_status = juju.status()
    if app_name in juju_status.apps:
        logging.info("Found existing %s application. Reconfiguring it.", app_name)
        juju.config(app_name, {"src-overwrite": json.dumps(src_overwrite)})
    else:
        juju.deploy(
            "any-charm",
            app_name,
            channel="beta",
            config={"src-overwrite": json.dumps(src_overwrite)},
        )

    return app_name


def get_app_ip(juju: jubilant.Juju, app_name: str) -> str:
    """Get the IP for a unit of the application.

    Args:
        juju: The jubilant Juju instance.
        app_name: The application name to get the public IP.

    Returns:
        The public IP of the application's first unit.
    """
    status = juju.status()
    units = status.apps[app_name].units
    assert units, f"No units found for app {app_name}"
    unit = next(iter(units.values()))
    return unit.public_address


def read_file(juju: jubilant.Juju, unit_name: str, path: Path) -> str:
    """Read a file on the Juju unit.

    Args:
        juju: The jubilant Juju instance.
        unit_name: The Juju unit name to read file on.
        path: The path of the file to read.

    Returns:
        The file content.
    """
    result = juju.exec(
        f"if [ -f {path} ]; then cat {path}; else echo ''; fi",
        unit=unit_name,
    )
    assert result.return_code == 0, f"Failed to read file {path}: {result.stderr}"
    logging.debug("File content of %s: %s", path, result.stdout)
    return result.stdout.strip()


def get_cache_backends(juju: jubilant.Juju, unit_name: str) -> list[str]:
    """Get the cache-backends value from the unit's cache-config relation data.

    Args:
        juju: The jubilant Juju instance.
        unit_name: The content-cache unit name to query.

    Returns:
        The list of cache-backend URLs published on the first cache-config relation.
    """
    rel_ids_result = juju.exec("relation-ids cache-config", unit=unit_name)
    assert rel_ids_result.return_code == 0, f"Failed to get relation IDs: {rel_ids_result.stderr}"
    rel_ids = rel_ids_result.stdout.split()
    assert rel_ids, "No cache-config relations found"
    rel_id = rel_ids[0]

    result = juju.exec(
        f"relation-get -r {rel_id} cache-backends -- {unit_name}",
        unit=unit_name,
    )
    assert result.return_code == 0, f"Failed to get cache-backends: {result.stderr}"
    raw = result.stdout.strip()
    if not raw:
        return []
    return json.loads(raw)


def run_in_unit(juju: jubilant.Juju, unit_name: str, command: str) -> tuple[int, str, str]:
    """Run a command in the Juju unit.

    Args:
        juju: The jubilant Juju instance.
        unit_name: The Juju unit name to run the command in.
        command: The command to run.

    Returns:
        The return code, stdout, and stderr.
    """
    result = juju.exec(command, unit=unit_name)
    return result.return_code, result.stdout, result.stderr
