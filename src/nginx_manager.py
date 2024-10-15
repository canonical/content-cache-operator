# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage nginx instance."""

import logging
import shutil
import uuid
from pathlib import Path

import nginx

from errors import (
    NginxConfigurationAggregateError,
    NginxConfigurationError,
    NginxFileError,
    NginxSetupError,
    NginxStopError,
)
from state import HostConfig, LocationConfig, NginxConfig
from utilities import execute_command

logger = logging.getLogger(__name__)

NGINX_SITES_ENABLED_PATH = Path("/etc/nginx/sites-enabled")
NGINX_SITES_AVAILABLE_PATH = Path("/etc/nginx/sites-available")
NGINX_LOG_PATH = Path("/var/log/nginx")


# Unit test is not valuable as the module is closely coupled with nginx.
# This should be tested with integration tests.


def initialize() -> None:  # pragma: no cover
    """Initialize the nginx server.

    Raises:
        NginxSetupError: Failure to set up nginx.
    """
    logger.info("Installing and enabling nginx")
    # The install, systemctl enable, and systemctl start are idempotent.
    return_code, _, stderr = execute_command(["sudo", "apt", "install", "nginx", "-yq"])
    if return_code != 0:
        raise NginxSetupError(f"Failed to install nginx: {stderr}")

    logger.info("Clean up default configuration files")
    _reset_sites_config_files()
    return_code, _, stderr = execute_command(["sudo", "systemctl", "enable", "nginx"])
    if return_code != 0:
        raise NginxSetupError(f"Failed to enable nginx: {stderr}")
    return_code, _, stderr = execute_command(["sudo", "systemctl", "start", "nginx"])
    if return_code != 0:
        raise NginxSetupError(f"Failed to start nginx: {stderr}")


def load_config() -> None:  # pragma: no cover
    """Load nginx configurations."""
    if ready_check():
        logger.info("Loading nginx configuration files")
        # This is reload the configuration files without interrupting service.
        execute_command(["sudo", "nginx", "-s", "reload"])
        return
    logger.info("Restarting nginx to load the configuration files.")
    execute_command(["sudo", "systemctl", "restart", "nginx"])


def stop() -> None:  # pragma: no cover
    """Stop the nginx server.

    Raises:
        NginxStopError: Failed to stop nginx.
    """
    logger.info("Stopping nginx")
    return_code, _, stderr = execute_command(["sudo", "systemctl", "stop", "nginx"])
    if return_code != 0:
        raise NginxStopError(f"Failed to stop nginx: {stderr}")


def ready_check() -> bool:  # pragma: no cover
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
        NginxConfigurationAggregateError: All failures related to creating nginx configuration.
        NginxFileError: File operation errors while updating nginx configuration files.

    Args:
        configuration: The nginx locations configurations.
    """
    # This will reset the file permissions.
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


def _reset_sites_config_files() -> None:
    """Reset the Nginx sites configuration files.

    Raises:
        NginxFileError: File operation errors while updating nginx configuration files.
    """
    logger.info("Resetting the nginx sites configuration files directories")
    try:
        if NGINX_SITES_AVAILABLE_PATH.exists():
            shutil.rmtree(NGINX_SITES_AVAILABLE_PATH)
        if NGINX_SITES_ENABLED_PATH.exists():
            shutil.rmtree(NGINX_SITES_ENABLED_PATH)
        # The default permission for nginx configuration files are 755.
        NGINX_SITES_AVAILABLE_PATH.mkdir(mode=0o755, parents=True, exist_ok=True)
        NGINX_SITES_ENABLED_PATH.mkdir(mode=0o755, parents=True, exist_ok=True)
        NGINX_SITES_AVAILABLE_PATH.chmod(mode=0o755)
        NGINX_SITES_ENABLED_PATH.chmod(mode=0o755)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to reset the sites configurations directories.")
        raise NginxFileError("Failed to reset sites configurations") from err


def _create_server_config(host: str, configuration: HostConfig) -> None:
    """Create the nginx configuration file for a virtual host.

    Args:
        host: The name of the virtual host.
        configuration: The configurations of the host.

    Raises:
        NginxConfigurationError: Failed to convert the configuration to nginx format.
    """
    logger.info("Creating the nginx site configuration file for hosts %s", host)
    try:
        nginx_config = nginx.Conf()
        server_config = nginx.Server(
            nginx.Key("server_name", host),
            nginx.Key("access_log", _get_access_log_path(host)),
            nginx.Key("error_log", _get_error_log_path(host)),
        )
        for path, config in configuration.items():
            # Each set of hostname configuration with path configuration needs a upstream.
            # Each upstream needs a unique upstream hostname.
            # Since the hostname configuration supports any valid hostname, which is up to 255 in
            # length, the upstream hostname cannot be built upon it. Therefore, UUIDv4 is used to
            # the upstream hostname.
            upstream = uuid.uuid4()
            upstream_keys = _get_upstream_config_keys(config)
            upstream_config = nginx.Upstream(upstream, *upstream_keys)
            nginx_config.add(upstream_config)

            location_keys = _get_location_config_keys(config, upstream, host)
            server_config.add(nginx.Location(path, *location_keys))
        nginx_config.add(server_config)
    except nginx.ParseError as err:
        logger.exception(
            "Unable to convert %s configuration to nginx format: %s", host, configuration
        )
        raise NginxConfigurationError(
            f"Unable to convert {host} configuration to nginx format: {configuration}"
        ) from err

    _create_and_enable_config(host, nginx_config)


def _get_upstream_config_keys(config: LocationConfig) -> tuple[nginx.Key, ...]:
    """Create the nginx keys for the upstream configuration.

    Args:
        config: The location configurations.

    Returns:
        The nginx.Key for the upstream configuration.
    """
    keys = [nginx.Key("server", ip) for ip in config.backends]
    keys.append(
        nginx.Key(
            "health_check",
            f"interval={config.health_check_interval} uri={config.health_check_path}",
        )
    )
    return keys


def _get_location_config_keys(
    config: LocationConfig, upstream: str, host: str
) -> tuple[nginx.Key, ...]:
    """Create the nginx keys for location configuration.

    Args:
        config: The location configurations.
        upstream: The upstream hostname for the backends.
        host: The hostname for this server.

    Returns:
        The nginx.Key for the Location configuration.
    """
    keys = [
        nginx.Key("proxy_pass", f"{config.protocol.value}://{upstream}{config.backends_path}"),
        nginx.Key("proxy_set_header", f'Host "{host}"'),
    ]

    for cache_valid in config.proxy_cache_valid:
        keys.append(nginx.Key("proxy_cache_valid", cache_valid))

    return keys


def _create_and_enable_config(host: str, nginx_config: nginx.Conf) -> None:
    """Store the nginx configuration and enable it.

    Nginx configuration files are usually stored in the sites-available path.
    The configurations that are enabled are usually symlink to the sites-enabled path.

    Args:
        host: The name of the host.
        nginx_config: The configuration to store as file and enable.

    Raises:
        NginxFileError: File operation errors while updating nginx configuration files.
    """
    try:
        nginx.dumpf(nginx_config, _get_sites_available_path(host))
        _get_sites_enabled_path(host).symlink_to(_get_sites_available_path(host))
    except (PermissionError, FileNotFoundError) as err:
        logger.exception("Issue with configuration directories")
        raise NginxFileError("Issue with configuration directories") from err
    except (OSError, IOError) as err:
        logger.exception("File write issue with configuration file")
        raise NginxFileError("File write issue with configuration file") from err


def _get_sites_available_path(host: str) -> Path:
    """Get the sites available configuration path to a host.

    Args:
        host: The name of the host.

    Returns:
        The path.
    """
    return NGINX_SITES_AVAILABLE_PATH / f"{host}.conf"


def _get_sites_enabled_path(host: str) -> Path:
    """Get the sites enabled configuration path to a host.

    Args:
        host: The name of the host.

    Returns:
        The path.
    """
    return NGINX_SITES_ENABLED_PATH / f"{host}.conf"


def _get_access_log_path(host: str) -> Path:
    """Get the access log path for a host.

    Args:
        host: The name of the host.

    Returns:
        The path.
    """
    return NGINX_LOG_PATH / f"{host}-access.log"


def _get_error_log_path(host: str) -> Path:
    """Get the error log path for a host.

    Args:
        host: The name of the host.

    Returns:
        The path.
    """
    return NGINX_LOG_PATH / f"{host}-error.log"
