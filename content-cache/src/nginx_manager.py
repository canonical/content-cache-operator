# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage nginx instance."""

import logging
import os
import pwd
import shutil
import uuid
from pathlib import Path
from typing import Mapping

import nginx
import requests

from errors import (
    NginxConfigurationAggregateError,
    NginxConfigurationError,
    NginxFileError,
    NginxSetupError,
    NginxStopError,
)
from state import HostConfig, LocationConfig, NginxConfig, Protocol
from utilities import execute_command

logger = logging.getLogger(__name__)

NGINX_CERTIFICATES_PATH = Path("/etc/nginx/certs")
NGINX_CONF_PATH = Path("/etc/nginx/conf.d")
NGINX_SITES_ENABLED_PATH = Path("/etc/nginx/sites-enabled")
NGINX_SITES_AVAILABLE_PATH = Path("/etc/nginx/sites-available")
NGINX_LOG_PATH = Path("/var/log/nginx")
NGINX_PROXY_CACHE_DIR_PATH = Path("/data/nginx/cache")
NGINX_USER = "www-data"

NGINX_STATUS_URL_PATH = "/nginx_status"
NGINX_HEALTH_CHECK_TIMEOUT = 300
NGINX_CACHE_LOG_FORMAT_NAME = "cache"
NGINX_CACHE_LOG_FORMAT = (
    "{"
    '"time": "$time_iso8601",'
    '"connection_number": "$connection",'
    '"hostname": "$hostname",'
    '"client_address": "$remote_addr",'
    '"request_method": "$request_method",'
    '"protocol": "$server_protocol",'
    '"status_code": "$status",'
    '"cache_status": "$upstream_cache_status",'
    '"request_time": "$request_time",'
    '"bytes_sent": "$bytes_sent",'
    '"body_bytes_sent": "$body_bytes_sent"'
    "}"
)


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
    _reset_nginx_files()
    return_code, _, stderr = execute_command(["sudo", "systemctl", "enable", "nginx"])
    if return_code != 0:
        raise NginxSetupError(f"Failed to enable nginx: {stderr}")
    return_code, _, stderr = execute_command(["sudo", "systemctl", "start", "nginx"])
    if return_code != 0:
        raise NginxSetupError(f"Failed to start nginx: {stderr}")


def stop() -> None:  # pragma: no cover
    """Stop the nginx server.

    Raises:
        NginxStopError: Failed to stop nginx.
    """
    logger.info("Stopping nginx")
    return_code, _, stderr = execute_command(["sudo", "systemctl", "stop", "nginx"])
    if return_code != 0:
        raise NginxStopError(f"Failed to stop nginx: {stderr}")


def health_check() -> bool:
    """Use nginx status page as health check.

    Returns:
        Whether the nginx is serving responses.
    """
    try:
        response = requests.get(
            f"http://localhost{NGINX_STATUS_URL_PATH}",
            allow_redirects=False,
            timeout=NGINX_HEALTH_CHECK_TIMEOUT,
        )
        response.raise_for_status()
    except requests.RequestException as err:
        logger.warning("Failed nginx health check: %s", err)
        return False
    return True


def _systemctl_status_check() -> bool:  # pragma: no cover
    """Check nginx process health.

    Returns:
        True if process is running, else false.
    """
    # The return code is 0 for active and 3 for failed or inactive.
    return_code, _, _ = execute_command(["systemctl", "status", "nginx"])
    return return_code == 0


def update_and_load_config(
    configuration: NginxConfig, hostname_to_cert: Mapping[str, Path]
) -> None:
    """Update the nginx configuration files and load them.

    Args:
        configuration: The nginx locations configurations.
        hostname_to_cert: The mapping of hostname to the TLS certificates filepath.

    Raises:
        NginxConfigurationAggregateError: All failures related to creating nginx configuration.
        NginxFileError: File operation errors while updating nginx configuration files.
    """
    # This will reset the file permissions.
    _reset_nginx_files()

    try:
        _create_http_config()
        _create_status_page_config()
    except NginxFileError:
        logger.info("Stop updating configuration file due to file write issues")
        raise

    errored_hosts: list[str] = []
    configuration_errors: list[NginxConfigurationError] = []
    for host, config in configuration.items():
        cert_path = None
        if host in hostname_to_cert:
            cert_path = hostname_to_cert[host]
        try:
            _create_server_config(host, config, cert_path)
        except NginxConfigurationError as err:
            errored_hosts.append(host)
            configuration_errors.append(err)
            continue
        except NginxFileError:
            logger.info("Stop updating configuration file due to file write issues")
            raise

    if errored_hosts:
        raise NginxConfigurationAggregateError(errored_hosts, configuration_errors)

    _load_config()


def _load_config() -> None:  # pragma: no cover
    """Load nginx configurations."""
    if _systemctl_status_check():
        logger.info("Loading nginx configuration files")
        # This is reload the configuration files without interrupting service.
        execute_command(["sudo", "nginx", "-s", "reload"])
        return

    logger.info("Restarting nginx to load the configuration files.")
    execute_command(["sudo", "systemctl", "restart", "nginx"])


def _reset_nginx_files() -> None:
    """Reset the Nginx files."""
    logger.info("Resetting the nginx conf files directories.")
    _reset_config_directory(NGINX_CONF_PATH)
    logger.info("Resetting the nginx sites configuration files directories.")
    _reset_config_directory(NGINX_SITES_AVAILABLE_PATH)
    _reset_config_directory(NGINX_SITES_ENABLED_PATH)
    logger.info("Ensure nginx cache directory is present.")
    _ensure_directory_exist_with_ownership(NGINX_PROXY_CACHE_DIR_PATH)


def _reset_config_directory(path: Path) -> None:
    """Reset a nginx configuration directory.

    Args:
        path: The path to the directory.
    """
    try:
        if path.exists():
            shutil.rmtree(path)
        # The default permission for nginx configuration files are 755.
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to reset directory %s", path)
        raise NginxFileError(f"Failed to reset directory {path}") from err


def _ensure_directory_exist_with_ownership(path: Path) -> None:
    """Ensure directory exist with nginx owning the directory.

    Args:
        path: The path to the directory.

    Raises:
        NginxFileError: File operation errors creating and/or owning the directory.
    """
    try:
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        user = pwd.getpwnam(NGINX_USER)
        os.chown(path, user.pw_uid, user.pw_gid)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to create and/or own directory %s", path)
        raise NginxFileError(f"Failed to create and/or own directory {path}") from err


def _create_http_config() -> None:
    """Create nginx HTTP configuration files."""
    logger.info("Creating the cache log format configuration")
    # The following should not throw any nginx.ParseError as it is static.
    cache_log_format_config = nginx.Conf(
        nginx.Key("log_format", f"{NGINX_CACHE_LOG_FORMAT_NAME} '{NGINX_CACHE_LOG_FORMAT}'"),
    )
    _store_http_config("cache_log_format", cache_log_format_config)


def _create_status_page_config() -> None:
    """Create the nginx configuration file for status page."""
    logger.info("Creating the nginx site configuration file for status page")
    # The following should not throw any nginx.ParseError as it is static.
    nginx_config = nginx.Conf(
        nginx.Server(
            nginx.Location(
                NGINX_STATUS_URL_PATH,
                nginx.Key("stub_status", "on"),
                nginx.Key("allow", "127.0.0.1"),
                nginx.Key("deny", "all"),
            )
        )
    )
    _store_and_enable_site_config("nginx_status", nginx_config)


def _create_server_config(
    host: str, configuration: HostConfig, certificate_path: Path | None
) -> None:
    """Create the nginx configuration file for a virtual host.

    Args:
        host: The name of the virtual host.
        configuration: The configurations of the host.
        certificate_path: The filepath to the TLS certificate for the host.

    Raises:
        NginxConfigurationError: Failed to convert the configuration to nginx format.
    """
    logger.info("Creating the nginx site configuration file for hosts %s", host)

    server_cache_dir = NGINX_PROXY_CACHE_DIR_PATH / host
    _ensure_directory_exist_with_ownership(server_cache_dir)
    try:
        nginx_config = nginx.Conf(
            nginx.Key(
                "proxy_cache_path",
                f"{server_cache_dir} use_temp_path=off levels=1:2 keys_zone={host}:10m",
            ),
        )
        server_config = nginx.Server(
            nginx.Key("proxy_cache", host),
            nginx.Key("server_name", host),
            nginx.Key("access_log", _get_access_log_path(host)),
            nginx.Key("access_log", f"{_get_cache_log_path(host)} {NGINX_CACHE_LOG_FORMAT_NAME}"),
            nginx.Key("error_log", _get_error_log_path(host)),
        )

        if certificate_path is not None:
            server_config.add(nginx.Key("listen", "443 ssl"))
            server_config.add(nginx.Key("ssl_certificate", str(certificate_path)))
            server_config.add(nginx.Key("ssl_certificate_key", str(certificate_path)))

        for path, config in configuration.items():
            # Each set of hostname configuration with path configuration needs a upstream.
            # Each upstream needs a unique upstream hostname.
            # Since the hostname configuration supports any valid hostname, which is up to 255 in
            # length, the upstream hostname cannot be built upon it. Therefore, UUIDv4 is used to
            # the upstream hostname.
            upstream = str(uuid.uuid4())
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

    _store_and_enable_site_config(host, nginx_config)


def _get_upstream_config_keys(config: LocationConfig) -> tuple[nginx.Key, ...]:
    """Create the nginx keys for the upstream configuration.

    Args:
        config: The location configurations.

    Returns:
        The nginx.Key for the upstream configuration.
    """
    port = 80
    if config.protocol == Protocol.HTTPS:
        port = 443
    keys = [
        nginx.Key("server", f"{ip}:{port} fail_timeout={config.fail_timeout}")
        for ip in config.backends
    ]
    return tuple(keys)


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

    return tuple(keys)


def _store_http_config(name: str, nginx_config: nginx.Conf) -> None:
    """Store the nginx http configuration.

    The nginx http configurations are usually stored in the conf.d path.
    The default and common nginx settings generally will load the conf.d path as HTTP
    configurations.

    Args:
        name: The name of the file.
        nginx_config: The configuration to store as file.
    """
    try:
        nginx.dumpf(nginx_config, _get_http_config_path(name))
    except (PermissionError, FileNotFoundError) as err:
        logger.exception("Issue with http configuration directories")
        raise NginxFileError("Issue with http configuration directories") from err
    except (OSError, IOError) as err:
        logger.exception("File write issue with http configuration file %s", name)
        raise NginxFileError(f"File write issue with http configuration file {name}") from err


def _store_and_enable_site_config(host: str, nginx_config: nginx.Conf) -> None:
    """Store the nginx site configuration and enable it.

    The nginx configuration files are usually stored in the sites-available path.
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
        logger.exception("Issue with site configuration directories")
        raise NginxFileError("Issue with site configuration directories") from err
    except (OSError, IOError) as err:
        logger.exception("File write issue with site configuration file for host %s", host)
        raise NginxFileError(
            f"File write issue with site configuration file for host {host}"
        ) from err


def _get_http_config_path(name: str) -> Path:
    """Get the http configuration file path.

    Args:
        name: The name of the configuration.

    Returns:
        The path.
    """
    return NGINX_CONF_PATH / f"{name}.conf"


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
    return NGINX_LOG_PATH / f"{host}.access.log"


def _get_cache_log_path(host: str) -> Path:
    """Get the cache log path for a host.

    Args:
        host: The name of the host.

    Returns:
        The path.
    """
    return NGINX_LOG_PATH / f"{host}.cache.log"


def _get_error_log_path(host: str) -> Path:
    """Get the error log path for a host.

    Args:
        host: The name of the host.

    Returns:
        The path.
    """
    return NGINX_LOG_PATH / f"{host}.error.log"
