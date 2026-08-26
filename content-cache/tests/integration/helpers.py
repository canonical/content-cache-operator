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

from state import CACHE_CONFIG_INTEGRATION_NAME

logger = logging.getLogger(__name__)

TEST_SERVER_PATH = Path("tests/integration/scripts/test_server.py")
TEST_SERVER_CERTIFICATE = Path("tests/integration/scripts/certificate.pem")

BACKENDS_CONFIG_NAME = "backends"
BACKEND_HOSTNAME_CONFIG_NAME = "backend-hostname"
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
        model: Model,
        app: Application,
        config_app: Application,
        config_alt_app: Application,
    ):
        """Initialize the object.

        Args:
            model: The juju model containing the applications.
            app: The content-cache application.
            config_app: The configuration charm application.
            config_alt_app: The alternative configuration charm application.
        """
        self._model = model
        self._app = app
        self._config_app = config_app
        self._config_alt_app = config_alt_app
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
        self, path: str, port: int = 30000, protocol: str = "http"
    ) -> requests.Response:
        """Test the content cache with a request.

        Args:
            path: The URL path to the content-cache.
            port: The nginx listening port allocated for the relation.
            protocol: The protocol to make the request.

        Returns:
            Whether the cache is working.
        """
        ip = await get_app_ip(self._app)
        url = f"{protocol}://{ip}:{port}{path}"
        logger.info(f"Querying cache on {url}")

        response = requests.get(
            url,
            allow_redirects=False,
            verify=False,
            timeout=300,
        )

        return response

    async def reset(self) -> None:
        """Reset the state of the applications."""
        if self._config_app.related_applications(CACHE_CONFIG_INTEGRATION_NAME):
            # Do NOT use block_until_done=True — it calls block_until() with no timeout
            # and can hang forever if hook processing stalls.
            await self._config_app.remove_relation(CACHE_CONFIG_INTEGRATION_NAME, self._app.name)
        if self._config_alt_app.related_applications(CACHE_CONFIG_INTEGRATION_NAME):
            await self._config_alt_app.remove_relation(
                CACHE_CONFIG_INTEGRATION_NAME, self._app.name
            )
        await self.reset_config()

    async def reset_config(self) -> None:
        """Reset the configuration of configuration charm application."""
        await self._config_app.set_config(CacheTester.BASE_CONFIG)


async def deploy_http_app(
    app_name: str, path: str, status: int, message: str, model: Model, https: bool = False
) -> Application:
    """Deploy a testing HTTP server application for testing.

    The testing HTTP server application is within an any charm instance.

    Args:
        app_name: The application name of the any charm.
        path: The URL path to the test server.
        status: The status code for the test response.
        message: The message in the test response.
        model: The model to deploy the any charm.
        https: Run server in HTTPS mode on port 443.

    Returns:
        The juju application with the testing HTTP server.
    """
    if https:
        port = 443
        flags = "--https"
    else:
        port = 80
        flags = ""

    test_server_content = TEST_SERVER_PATH.read_text()
    certificate_content = TEST_SERVER_CERTIFICATE.read_text()
    any_charm_content = textwrap.dedent(f'''
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
                    + """ --path {path} --status {status} --message {message} --port {port} {flags}
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
    ''')

    src_overwrite = {
        "test_server.py": test_server_content,
        "any_charm.py": any_charm_content,
        "certificate.pem": certificate_content,
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


async def deploy_self_cert_https_app(
    app_name: str, path: str, status: int, message: str, model: Model
) -> Application:
    """Deploy a self-contained HTTPS test app that generates its own CA and server cert.

    The anyCharm generates a local CA and a server cert (signed by that CA) with
    ``DNS:localhost`` as Subject Alternative Name at install time.  No external CA charm
    is required.  The app also provides the ``send-ca-cert`` endpoint (built into
    any-charm) so callers can push the CA cert into a content-cache's combined bundle via
    ``receive-ca-cert``.

    Using ``DNS:localhost`` allows ``proxy_ssl_name=localhost`` to satisfy OpenSSL's
    ``X509_check_host()`` which matches DNS SANs (not IP SANs).

    Args:
        app_name: The application name for the any-charm deployment.
        path: URL path that the server will respond to.
        status: HTTP status code the server returns on ``path``.
        message: Response body the server returns on ``path``.
        model: The libjuju Model to deploy into.

    Returns:
        The deployed Juju Application.
    """
    test_server_content = TEST_SERVER_PATH.read_text()

    # The inner any-charm code.  Values of path/status/message are baked in by
    # the outer f-string at deploy time; other {{}}/{{var}} escapes produce
    # single-brace expressions that are evaluated inside the charm at runtime.
    any_charm_content = textwrap.dedent(f'''\
    import logging
    import os
    import subprocess
    from pathlib import Path

    import ops
    from any_charm_base import AnyCharmBase

    logger = logging.getLogger(__name__)

    SERVICE_NAME = "test-https-cert"
    SERVICE_PATH = Path("/etc/systemd/system/" + SERVICE_NAME + ".service")
    CERT_DIR = Path("/etc/test-certs")
    CA_KEY_PATH = CERT_DIR / "ca.key"
    CA_CERT_PATH = CERT_DIR / "ca.pem"
    SERVER_KEY_PATH = CERT_DIR / "server.key"
    SERVER_CERT_PATH = CERT_DIR / "server.pem"
    SAN_CONF = CERT_DIR / "san.cnf"
    EXT_CONF = CERT_DIR / "ext.cnf"


    def _generate_certs() -> None:
        """Generate a local CA and a server cert signed by it (DNS:localhost SAN)."""
        if CA_CERT_PATH.exists() and SERVER_CERT_PATH.exists():
            return
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        # Local CA
        subprocess.run(
            ["openssl", "genrsa", "-out", str(CA_KEY_PATH), "2048"],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "req", "-new", "-x509",
                "-key", str(CA_KEY_PATH),
                "-out", str(CA_CERT_PATH),
                "-days", "3650",
                "-subj", "/CN=test-local-ca",
            ],
            check=True, capture_output=True,
        )
        # Server key
        subprocess.run(
            ["openssl", "genrsa", "-out", str(SERVER_KEY_PATH), "2048"],
            check=True, capture_output=True,
        )
        # Server CSR with DNS:localhost SAN
        # OpenSSL X509_check_host() only matches DNS SANs (not IP SANs), so we must
        # use DNS:localhost to satisfy proxy_ssl_name=localhost verification.
        SAN_CONF.write_text(
            "[req]\\nreq_extensions = v3_req\\ndistinguished_name = req_dn\\n"
            "[req_dn]\\n[v3_req]\\nsubjectAltName = DNS:localhost\\n"
        )
        subprocess.run(
            [
                "openssl", "req", "-new",
                "-key", str(SERVER_KEY_PATH),
                "-out", str(CERT_DIR / "server.csr"),
                "-subj", "/CN=localhost",
                "-config", str(SAN_CONF),
            ],
            check=True, capture_output=True,
        )
        # Sign server cert with local CA
        EXT_CONF.write_text("[v3_req]\\nsubjectAltName = DNS:localhost\\n")
        subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", str(CERT_DIR / "server.csr"),
                "-CA", str(CA_CERT_PATH),
                "-CAkey", str(CA_KEY_PATH),
                "-CAcreateserial",
                "-out", str(SERVER_CERT_PATH),
                "-days", "3650",
                "-extfile", str(EXT_CONF),
                "-extensions", "v3_req",
            ],
            check=True, capture_output=True,
        )
        logger.info("Generated local CA and server cert (DNS:localhost)")


    class AnyCharm(AnyCharmBase):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.framework.observe(self.on.install, self._on_install)
            self.framework.observe(
                self.on["send-ca-cert"].relation_joined,
                self._on_send_ca_cert_joined,
            )

        def _on_install(self, event):
            _generate_certs()
            server_cert_pem = SERVER_CERT_PATH.read_text()
            self._start_server(server_cert_pem)
            self.unit.status = ops.ActiveStatus()

        def _on_send_ca_cert_joined(self, event):
            """Send the local CA cert in V0 unit-databag format (certificate_transfer)."""
            _generate_certs()
            ca_pem = CA_CERT_PATH.read_text()
            event.relation.data[self.unit]["ca"] = ca_pem
            event.relation.data[self.unit]["chain"] = "[]"

        def _start_server(self, cert_pem: str):
            """Write cert+key PEM bundle and start the systemd HTTPS service."""
            # PEM bundle: server cert followed by server key
            SERVER_CERT_PATH.write_text(cert_pem.strip() + "\\n")
            bundle = cert_pem.strip() + "\\n" + SERVER_KEY_PATH.read_text()
            (CERT_DIR / "bundle.pem").write_text(bundle)
            test_server = Path(os.getcwd()) / "src" / "test_server.py"
            SERVICE_PATH.write_text(
                "[Unit]\\n"
                "Description=Test HTTPS server (local CA cert)\\n"
                "After=network.target\\n"
                "\\n"
                "[Service]\\n"
                "Type=simple\\n"
                "User=root\\n"
                "ExecStart=/usr/bin/env python3 " + str(test_server)
                + " --path {path} --status {status} --message {message}"
                  " --port 443 --https --cert " + str(CERT_DIR / "bundle.pem") + "\\n"
                "Restart=on-failure\\n"
                "\\n"
                "[Install]\\n"
                "WantedBy=multi-user.target\\n"
            )
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)
            subprocess.run(["systemctl", "restart", SERVICE_NAME], capture_output=True)
    ''')

    src_overwrite = {
        "test_server.py": test_server_content,
        "any_charm.py": any_charm_content,
    }

    app: Application
    if app_name in model.applications:
        logging.info("Found existing %s application. Reconfiguring it.", app_name)
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


async def get_cache_backend(unit: Unit) -> str:
    """Get the cache-backend value from the unit's cache-config relation data.

    Args:
        unit: The content-cache unit to query.

    Returns:
        The cache-backend URL published on the first cache-config relation, or empty string.
    """
    return_code, rel_ids_stdout, stderr = await run_in_unit(
        unit=unit,
        command="relation-ids cache-config",
    )
    assert return_code == 0, f"Failed to get relation IDs: {stderr}"
    rel_ids = (rel_ids_stdout or "").split()
    assert rel_ids, "No cache-config relations found"
    rel_id = rel_ids[0]

    return_code, stdout, stderr = await run_in_unit(
        unit=unit,
        command=f"relation-get -r {rel_id} cache-backend -- {unit.name}",
    )
    assert return_code == 0, f"Failed to get cache-backend: {stderr}"
    return (stdout or "").strip()


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
