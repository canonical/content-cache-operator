# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage nginx instance."""

import logging
from pathlib import Path

import nginx

from errors import NginxConfigurationAggregateError, NginxConfigurationError, NginxFileError
from state import NginxConfig, ServerConfig
from utilities import execute_command

logger = logging.getLogger(__name__)

NGINX_SITES_ENABLED_PATH = Path("/etc/nginx/sites-enabled")
NGINX_SITES_AVAILABLE_PATH = Path("/etc/nginx/sites-available")
NGINX_LOG_PATH = Path("/var/log/nginx")


# Unit test is not valuable as the class is closely coupled with nginx.
# This should be tested with integration tests.

# pragma: no cover


def initialize() -> None:
    """Initialize the nginx server."""
    logger.info("Installing and enabling nginx")
    # The install, systemctl enable, and systemctl start are idempotent.
    execute_command(["sudo", "apt", "install", "nginx", "-yq"])
    logger.info("Clean up default configuration files")
    _reset_sites_config_files()
    execute_command(["sudo", "systemctl", "enable", "nginx"])
    execute_command(["sudo", "systemctl", "start", "nginx"])


def load_config() -> None:
    """Load nginx configurations."""
    if ready_check():
        logger.info("Loading nginx configuration files")
        # This is reload the configuration files without interrupting service.
        execute_command(["sudo", "nginx", "-s", "reload"])
        return
    logger.info("Restarting nginx to load the configuration files.")
    execute_command(["sudo", "systemctl", "restart", "nginx"])


def stop() -> None:
    """Stop the nginx server."""
    logger.info("Stopping nginx")
    execute_command(["sudo", "systemctl", "stop", "nginx"])


def ready_check() -> bool:
    """Check if nginx is ready to serve requests.

    Returns:
        True if ready, else false.
    """
    # The return code is 0 for active and 3 for failed or inactive.
    return_code, _, _ = execute_command(["systemctl", "status", "nginx"])
    return return_code == 0


def update_config(configuration: NginxConfig) -> None:
    """Update the nginx configuration files.

    Raises:
        NginxConfigurationError: Error during converting configurations to nginx format.
        NginxFileError: Error during writing nginx configuration files.
    Args:
        configuration: The nginx locations configurations.
    """
    _reset_sites_config_files()

    errored_hosts: list[str] = []
    configuration_errors: list[NginxConfigurationError] = []
    for host, config in configuration.items():
        try:
            _create_server_config(host, config)
        except NginxConfigurationError as err:
            errored_hosts.append(host)
            configuration_errors.append(err)
            continue
        except NginxFileError:
            logger.info("Stop updating configuration file due to file write issues")
            raise

    if errored_hosts:
        raise NginxConfigurationAggregateError(errored_hosts, configuration_errors)


def _create_server_config(host: str, configuration: ServerConfig) -> None:
    logger.info("Creating the nginx site configuration file for hosts %s", host)
    try:
        nginx_config = nginx.Conf()
        server_config = nginx.Server(
            nginx.Key("server_name", host),
            nginx.Key("access_log", _get_access_log_path()),
            nginx.Key("error_log", _get_error_log_path()),
        )

        for path, config in configuration.items():
            host_with_path = host + path

            backends = [nginx.Key("server", ip) for ip in config.backends]
            upstream_config = nginx.Upstream(host_with_path, *backends)
            nginx_config.add(upstream_config)
            server_config.add(
                nginx.Location(
                    path,
                    nginx.Key("proxy_pass", f"{config.protocol}://{host_with_path}"),
                    nginx.Key("proxy_set_header", f'Host "{host}"'),
                )
            )

        nginx_config.add(server_config)
    except nginx.ParseError as err:
        logger.exception(
            "Unable to convert %s configuration to nginx format: %s", host, configuration
        )
        raise NginxConfigurationError(
            f"Unable to convert {host} configuration to nginx format: {configuration}"
        ) from err

    try:
        nginx.dumpf(nginx_config, _get_site_available_path(host))
        _get_site_enable_path(host).symlink_to(_get_site_available_path(host))
    except (PermissionError, FileNotFoundError) as err:
        logger.exception("Issue with configuration directories")
        raise NginxFileError("Issue with configuration directories") from err
    except (OSError, IOError) as err:
        logger.exception("File write issue with configuration file")
        raise NginxFileError("File write issue with configuration file") from err


def _reset_sites_config_files() -> None:
    """Reset the Nginx sites configuration files."""
    logger.info("Resetting the nginx sites configuration files directories")
    NGINX_SITES_AVAILABLE_PATH.mkdir(mode=755, exist_ok=True)
    NGINX_SITES_ENABLED_PATH.mkdir(mode=755, exist_ok=True)
    NGINX_SITES_AVAILABLE_PATH.chmod(mode=755)
    NGINX_SITES_ENABLED_PATH.chmod(mode=755)

    for child in NGINX_SITES_AVAILABLE_PATH.iterdir():
        child.unlink(missing_ok=True)
    for child in NGINX_SITES_ENABLED_PATH.iterdir():
        child.unlink(missing_ok=True)


def _get_site_available_path(host: str) -> Path:
    return NGINX_SITES_AVAILABLE_PATH / f"{host}.conf"


def _get_site_enable_path(host: str) -> Path:
    return NGINX_SITES_ENABLED_PATH / f"{host}.conf"


def _get_access_log_path(host: str) -> Path:
    return NGINX_LOG_PATH / f"{host}-access.log"


def _get_error_log_path(host: str) -> Path:
    return NGINX_LOG_PATH / f"{host}-error.log"
