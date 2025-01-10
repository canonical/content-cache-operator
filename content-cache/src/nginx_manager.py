# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage nginx instance."""

import logging
import os
import pwd
import shutil
import uuid
from dataclasses import dataclass
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

NGINX_BIN = "/usr/sbin/nginx"
NGINX_PACKAGE = "nginx"
NGINX_SERVICE = "nginx"
NGINX_MAIN_CONF_PATH = Path("/etc/nginx/nginx.conf")
NGINX_CERTIFICATES_PATH = Path("/etc/nginx/certs")
NGINX_CONFD_PATH = Path("/etc/nginx/conf.d")
NGINX_HEALTHCHECKS_CONF_PATH = NGINX_CONFD_PATH / "lua_healthchecks.conf"
NGINX_SITES_ENABLED_PATH = Path("/etc/nginx/sites-enabled")
NGINX_SITES_AVAILABLE_PATH = Path("/etc/nginx/sites-available")
NGINX_MODULES_ENABLED_PATH = Path("/etc/nginx/modules-enabled")
NGINX_LOG_PATH = Path("/var/log/nginx")
NGINX_PROXY_CACHE_DIR_PATH = Path("/data/nginx/cache")
NGINX_USER = "www-data"

NGINX_STATUS_URL_PATH = "/nginx_status"
NGINX_BACKENDS_STATUS_URL_PATH = "/nginx_backends_status"
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


@dataclass
class NginxLuaSection:
    """Simple class to be used by python-nginx to insert Lua code in Nginx conf.

    Attrs:
        name: The name of the Lua code section to generate (for instance: "content_by_lua_block").
        content: The content to put in this section.
        as_strings: The string to be dumped in the nginx configuration file by python-nginx.
    """

    name: str
    content: str

    @property
    def as_strings(self) -> str:
        """Return a string to be dumped in nginx conf."""
        return f"{self.name} {{{self.content}}}\n"


def initialize(instance_name: str) -> None:  # pragma: no cover
    """Initialize the nginx server.

    Args:
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.

    Raises:
        NginxSetupError: Failure to set up nginx.
    """
    logger.info("Installing and enabling nginx")
    # The install, systemctl enable, and systemctl start are idempotent.
    return_code, _, stderr = execute_command(
        ["sudo", "apt", "install", "nginx", "lua-resty-core", "-yq"]
    )
    if return_code != 0:
        raise NginxSetupError(f"Failed to install nginx: {stderr}")

    return_code, _, stderr = execute_command(
        [
            "sudo",
            "dpkg",
            "-i",
            "libnginx-mod-http-upstream_0.1_amd64.deb",
        ]
    )
    if return_code != 0:
        raise NginxSetupError(f"Failed to install nginx upstream module: {stderr}")

    return_code, _, stderr = execute_command(
        [
            "cp",
            "-f",
            "healthcheck.lua",
            "/usr/share/lua/5.1/",
        ]
    )
    if return_code != 0:
        raise NginxSetupError(f"Failed to install nginx healthcheck plugin: {stderr}")

    logger.info("Clean up default configuration files")
    _reset_nginx_files(instance_name)
    return_code, _, stderr = execute_command(["sudo", "systemctl", "enable", NGINX_SERVICE])
    if return_code != 0:
        raise NginxSetupError(f"Failed to enable nginx: {stderr}")
    return_code, _, stderr = execute_command(["sudo", "systemctl", "start", NGINX_SERVICE])
    if return_code != 0:
        raise NginxSetupError(f"Failed to start nginx: {stderr}")


def stop() -> None:  # pragma: no cover
    """Stop the nginx server.

    Raises:
        NginxStopError: Failed to stop nginx.
    """
    logger.info("Stopping nginx")
    return_code, _, stderr = execute_command(["sudo", "systemctl", "stop", NGINX_SERVICE])
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
    return_code, _, _ = execute_command(["systemctl", "status", NGINX_SERVICE])
    return return_code == 0


def update_and_load_config(
    configuration: NginxConfig,
    hostname_to_cert: Mapping[str, Path],
    instance_name: str,
) -> None:
    """Update the nginx configuration files and load them.

    Args:
        configuration: The nginx locations configurations.
        hostname_to_cert: The mapping of hostname to the TLS certificates filepath.
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.

    Raises:
        NginxConfigurationAggregateError: All failures related to creating nginx configuration.
        NginxFileError: File operation errors while updating nginx configuration files.
    """
    # This will reset the file permissions.
    _reset_nginx_files(instance_name)

    errored_hosts: list[str] = []
    configuration_errors: list[NginxConfigurationError] = []
    healthcheck_workers_lua_code = ""
    for host, config in configuration.items():
        cert_path = None
        if host in hostname_to_cert:
            cert_path = hostname_to_cert[host]
        try:
            vhost_healtcheck_worker_lua_code = _create_virtualhost_config(
                host, config, cert_path, instance_name
            )
            healthcheck_workers_lua_code += vhost_healtcheck_worker_lua_code
        except NginxConfigurationError as err:
            errored_hosts.append(host)
            configuration_errors.append(err)
            continue
        except NginxFileError:
            logger.info("Stop updating configuration file due to file write issues")
            raise

    try:
        _create_http_config(healthcheck_workers_lua_code)
        _create_status_page_config()
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
        execute_command(["sudo", NGINX_BIN, "-s", "reload"])
        return

    logger.info("Restarting nginx to load the configuration files.")
    execute_command(["sudo", "systemctl", "restart", NGINX_SERVICE])


def _reset_nginx_files(instance_name: str) -> None:
    """Reset the Nginx files.

    Args:
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.
    """
    logger.info("Resetting the nginx conf files directories.")
    _reset_config_directory(NGINX_CONFD_PATH)
    logger.info("Resetting the nginx module files directories.")
    _reset_config_directory(NGINX_MODULES_ENABLED_PATH)
    logger.info("Resetting the nginx sites configuration files directories.")
    _reset_config_directory(NGINX_SITES_AVAILABLE_PATH)
    _reset_config_directory(NGINX_SITES_ENABLED_PATH)
    logger.info("Ensure nginx cache directory is present.")
    _ensure_directory_exist_with_ownership(NGINX_PROXY_CACHE_DIR_PATH)
    logger.info("Ensure nginx log directory is present.")
    _ensure_directory_exist_with_ownership(NGINX_LOG_PATH / instance_name)


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


def _create_http_config(healthcheck_workers_lua_code: str) -> None:
    """Create nginx HTTP configuration files."""
    logger.info("Creating the cache log format configuration")
    # The following should not throw any nginx.ParseError as it is static.
    cache_log_format_config = nginx.Conf(
        nginx.Key("log_format", f"{NGINX_CACHE_LOG_FORMAT_NAME} '{NGINX_CACHE_LOG_FORMAT}'"),
    )
    _store_http_config("cache_log_format", cache_log_format_config)

    _create_healthcheck_module_config(healthcheck_workers_lua_code)


def _create_healthcheck_module_config(healthcheck_workers_lua_code: str) -> None:
    """Create the nginx configuration file to enable healthcheck module."""
    logger.info("Creating the nginx configuration files for healthcheck")

    # From: https://github.com/openresty/lua-resty-upstream-healthcheck
    load_module_config = nginx.Conf(
        nginx.Key("load_module", "modules/ndk_http_module.so"),
        nginx.Key("load_module", "modules/ngx_http_lua_module.so"),
        nginx.Key("load_module", "modules/ngx_http_lua_upstream_module.so"),
    )

    lua_variables = """local hc = require "healthcheck"
        local ok, err
        """

    healthcheck_config = nginx.Conf(
        nginx.Key("lua_package_path", "/usr/share/lua/5.1/?.lua;;"),
        nginx.Key("lua_shared_dict", "healthcheck 1m"),
        nginx.Key("lua_socket_log_errors", "off"),
        NginxLuaSection("init_worker_by_lua_block", lua_variables + healthcheck_workers_lua_code),
    )

    try:
        nginx.dumpf(load_module_config, NGINX_MODULES_ENABLED_PATH / "lua_upstream.conf")
        nginx.dumpf(healthcheck_config, NGINX_HEALTHCHECKS_CONF_PATH)
    except (PermissionError, FileNotFoundError) as err:
        logger.exception("Issue with configuration directories")
        raise NginxFileError("Issue with configuration directories") from err
    except (OSError, IOError) as err:
        logger.exception("File write issue with configuration file")
        raise NginxFileError("File write issue with configuration file") from err


def _create_status_page_config() -> None:
    """Create the nginx configuration file for status page."""
    logger.info("Creating the nginx site configuration file for status page")
    # The following should not throw any nginx.ParseError as it is static.
    nginx_config = nginx.Conf(
        nginx.Server(
            # The standard nginx status page
            nginx.Location(
                NGINX_STATUS_URL_PATH,
                nginx.Key("stub_status", "on"),
                nginx.Key("allow", "127.0.0.1"),
                nginx.Key("deny", "all"),
            ),
            # A status page specific to the active healthchecks.
            # This page will report the status of the different backends.
            nginx.Location(
                NGINX_BACKENDS_STATUS_URL_PATH,
                nginx.Key("allow", "127.0.0.1"),
                nginx.Key("deny", "all"),
                nginx.Key("default_type", "text/plain"),
                NginxLuaSection(
                    "content_by_lua_block",
                    """local hc = require "healthcheck"
                ngx.say("Nginx Worker PID: ", ngx.worker.pid())
                ngx.print(hc.status_page())
                """,
                ),
            ),
        )
    )
    _store_and_enable_site_config("nginx_status", nginx_config)


def _create_virtualhost_config(
    host: str, configuration: HostConfig, certificate_path: Path | None, instance_name: str
) -> str:
    """Create the nginx configuration file for a virtual host.

    Args:
        host: The name of the virtual host.
        configuration: The configurations of the host.
        certificate_path: The filepath to the TLS certificate for the host.
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.

    Raises:
        NginxConfigurationError: Failed to convert the configuration to nginx format.
    """
    logger.info("Creating the nginx site configuration file for hosts %s", host)

    lua_healthcheck_workers = ""
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
            nginx.Key("access_log", _get_access_log_path(host, instance_name)),
            nginx.Key(
                "access_log",
                f"{_get_cache_log_path(host, instance_name)} {NGINX_CACHE_LOG_FORMAT_NAME}",
            ),
            nginx.Key("error_log", _get_error_log_path(host, instance_name)),
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

            lua_healthcheck_workers += _get_upstream_healthchecks_worker(upstream, config)

        nginx_config.add(server_config)
    except nginx.ParseError as err:
        logger.exception(
            "Unable to convert %s configuration to nginx format: %s", host, configuration
        )
        raise NginxConfigurationError(
            f"Unable to convert {host} configuration to nginx format: {configuration}"
        ) from err

    _store_and_enable_site_config(host, nginx_config)

    return lua_healthcheck_workers


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


def _get_upstream_healthchecks_worker(upstream: str, config: LocationConfig) -> str:
    """Create the lua script to perform the healthchecks on backends.

    Args:
        upstream: The upstream name.
        config: The virtualhost config.

    Returns:
        A string with the lua script for the healthcheck workers.
    """
    return rf"""ok, err = hc.spawn_checker{{
            shm = "healthcheck",
            upstream = "{upstream}",
            type = "{config.protocol.value}",

            http_req = "GET {config.healthcheck_path} HTTP/1.0\r\nHost: {config.hostname}\r\n\r\n",

            port = {443 if config.protocol.value == "https" else 80},
            interval = {config.healthcheck_interval},
            timeout = 1000,
            fall = 3,
            rise = 2,
            valid_statuses = {{200}},
            concurrency = 10,
        }}
        if not ok then
            ngx.log(ngx.ERR, "failed to spawn health checker: ", err)
            return
        end
    """


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
    return NGINX_CONFD_PATH / f"{name}.conf"


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


def _get_access_log_path(host: str, instance_name: str) -> Path:
    """Get the access log path for a host.

    Args:
        host: The name of the host.
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.

    Returns:
        The path.
    """
    return NGINX_LOG_PATH / instance_name / f"{host}.access.log"


def _get_cache_log_path(host: str, instance_name: str) -> Path:
    """Get the cache log path for a host.

    Args:
        host: The name of the host.
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.

    Returns:
        The path.
    """
    return NGINX_LOG_PATH / instance_name / f"{host}.cache.log"


def _get_error_log_path(host: str, instance_name: str) -> Path:
    """Get the error log path for a host.

    Args:
        host: The name of the host.
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.

    Returns:
        The path.
    """
    return NGINX_LOG_PATH / instance_name / f"{host}.error.log"
