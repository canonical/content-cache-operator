# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage nginx instance."""

from pathlib import Path

import nginx

from state import NginxConfig
from utilities import execute_command

NGINX_SITES_ENABLED_PATH = Path("/etc/nginx/sites-enabled")
NGINX_DEFAULT_SITES_PATH = NGINX_SITES_ENABLED_PATH / "default"
CHARM_MANAGED_NGINX_CONFIG_PATH = NGINX_SITES_ENABLED_PATH / "charm-managed"


# Unit test is not valuable as the class is closely coupled with nginx.
# This should be tested with integration tests.
class NginxManager:  # pragma: no cover
    """Manages the Nginx instance."""

    def init(self) -> None:
        """Initialize the nginx server."""
        # The install, systemctl enable, and systemctl start are idempotent.
        execute_command(["sudo", "apt", "install", "nginx", "-yq"])
        execute_command(["sudo", "systemctl", "enable", "nginx"])
        execute_command(["sudo", "systemctl", "start", "nginx"])

        NGINX_DEFAULT_SITES_PATH.unlink(missing_ok=True)

    def load(self) -> None:
        """Start or reload the nginx server."""
        if self.ready_check():
            # This is reload the configuration files without interrupting service.
            execute_command(["sudo", "nginx", "-s", "reload"])
        else:
            execute_command(["sudo", "systemctl", "restart", "nginx"])

    def stop(self) -> None:
        """Stop the nginx server."""
        execute_command(["sudo", "nginx", "-s", "quit"])

    def update_config(self, configuration: NginxConfig) -> None:
        """Update the nginx configuration files.

        Args:
            configuration: The nginx locations configurations.
        """
        nginx_config = nginx.Conf()
        server_config = nginx.Server()
        for i, config in enumerate(configuration.values()):
            backend_set_name = f"backend_{i}"

            hosts = [nginx.Key("server", host) for host in config.backends]

            upstream_config = nginx.Upstream(backend_set_name, *hosts)
            nginx_config.add(upstream_config)
            server_config.add(
                nginx.Location(
                    config.location,
                    nginx.Key("proxy_pass", f"{config.protocol}://{backend_set_name}"),
                )
            )
        nginx_config.add(server_config)
        nginx.dumpf(nginx_config, CHARM_MANAGED_NGINX_CONFIG_PATH)

    def ready_check(self) -> bool:
        """Check if nginx is ready to serve requests.

        Returns:
            True if ready, else false.
        """
        return_code, _, _ = execute_command(["systemctl", "status", "nginx"])
        return return_code == 0
