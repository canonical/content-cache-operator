# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage nginx instance."""

import base64
import logging
import os
import pwd
import shutil
from dataclasses import dataclass
from pathlib import Path

import nginx
import requests

import ca_certs
from errors import (
    NginxConfigurationAggregateError,
    NginxConfigurationError,
    NginxFileError,
    NginxSetupError,
    NginxStopError,
)
from state import LocationConfig
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

# Directory for material that must not be world-readable (unlike NGINX_CONFD_PATH and
# friends, which are reset to mode 0755 on every reconcile). Not wiped by
# _reset_nginx_files, so it is created/removed explicitly.
NGINX_SECRETS_PATH = Path("/etc/nginx/secrets")
NGINX_CLIENT_IP_SALT_LUA_MODULE = "content_cache_client_ip_salt"
NGINX_CLIENT_IP_SALT_LUA_PATH = NGINX_SECRETS_PATH / f"{NGINX_CLIENT_IP_SALT_LUA_MODULE}.lua"

NGINX_STATUS_URL_PATH = "/nginx_status"
NGINX_BACKENDS_STATUS_URL_PATH = "/nginx_backends_status"
NGINX_STATUS_PORT = 30200

NGINX_HEALTH_CHECK_TIMEOUT = 300
NGINX_MAIN_LOG_FORMAT_NAME = "content_cache_main"
# Matches nginx's built-in "combined" format, but with the client address replaced by
# $logged_client_address so it is hashed consistently with the "cache" log format
# below when client IP hashing is enabled.
NGINX_MAIN_LOG_FORMAT = (
    '$logged_client_address - $remote_user [$time_local] "$request" '
    '$status $body_bytes_sent "$http_referer" "$http_user_agent"'
)
NGINX_CACHE_LOG_FORMAT_NAME = "cache"
NGINX_CACHE_LOG_FORMAT = (
    "{"
    '"time": "$time_iso8601",'
    '"connection_number": "$connection",'
    '"hostname": "$hostname",'
    '"client_address": "$logged_client_address",'
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
class TLSConfig:
    """TLS configuration for nginx.

    Attrs:
        frontend_cert_path: Path to the combined cert+key PEM for TLS termination, or None.
    """

    frontend_cert_path: Path | None = None


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
        ["sudo", "apt", "install", "nginx", "lua-resty-core", "ca-certificates", "-yq"]
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

    return_code, _, stderr = execute_command(
        [
            "cp",
            "-f",
            "sha2.lua",
            "/usr/share/lua/5.1/",
        ]
    )
    if return_code != 0:
        raise NginxSetupError(f"Failed to install nginx sha2 module: {stderr}")

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
            f"http://localhost:{NGINX_STATUS_PORT}{NGINX_STATUS_URL_PATH}",
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
    configuration: dict[int, tuple[int, LocationConfig]],
    instance_name: str,
    frontend_cert_path: Path | None = None,
    client_ip_hash_salt: str | None = None,
) -> None:
    """Update the nginx configuration files and load them.

    Args:
        configuration: The nginx locations configurations keyed by relation ID.
            Each value is a tuple of (port, LocationConfig).
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.
        frontend_cert_path: Path to the combined cert+key PEM for TLS termination, or None.
        client_ip_hash_salt: Salt used to hash client IP addresses in logs, or None to log
            client IP addresses in plaintext.

    Raises:
        NginxConfigurationAggregateError: All failures related to creating nginx configuration.
        NginxFileError: File operation errors while updating nginx configuration files.
    """
    # This will reset the file permissions.
    _reset_nginx_files(instance_name)
    _write_client_ip_hash_salt(client_ip_hash_salt)

    tls = TLSConfig(frontend_cert_path=frontend_cert_path)
    errored_identifiers: list[str] = []
    configuration_errors: list[NginxConfigurationError] = []
    healthcheck_workers_lua_code = ""
    for _rel_id, (port, config) in configuration.items():
        identifier = str(port)
        try:
            vhost_healthcheck_worker_lua_code = _create_virtualhost_config(
                identifier,
                port,
                config,
                instance_name,
                tls,
                client_ip_hash_salt,
            )
            healthcheck_workers_lua_code += vhost_healthcheck_worker_lua_code
        except NginxConfigurationError as err:
            errored_identifiers.append(identifier)
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

    if errored_identifiers:
        raise NginxConfigurationAggregateError(errored_identifiers, configuration_errors)

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


def _write_client_ip_hash_salt(salt: str | None) -> None:
    """Write or remove the client IP hash salt Lua module.

    Unlike NGINX_CONFD_PATH and friends, NGINX_SECRETS_PATH is not wiped by
    _reset_nginx_files, since it must never be created with the world-readable 0755
    permissions those directories use. The salt itself is base64-encoded before being
    embedded in the Lua source so no escaping is needed for characters that would
    otherwise be special to the Lua string literal syntax.

    Args:
        salt: The salt string, or None to disable client IP hashing.

    Raises:
        NginxFileError: File operation errors while writing the salt file.
    """
    try:
        if salt is None:
            NGINX_CLIENT_IP_SALT_LUA_PATH.unlink(missing_ok=True)
            return
        NGINX_SECRETS_PATH.mkdir(mode=0o700, parents=True, exist_ok=True)
        user = pwd.getpwnam(NGINX_USER)
        os.chown(NGINX_SECRETS_PATH, user.pw_uid, user.pw_gid)
        encoded_salt = base64.b64encode(salt.encode("utf-8")).decode("ascii")
        NGINX_CLIENT_IP_SALT_LUA_PATH.write_text(f'return "{encoded_salt}"\n', encoding="utf-8")
        NGINX_CLIENT_IP_SALT_LUA_PATH.chmod(0o600)
        os.chown(NGINX_CLIENT_IP_SALT_LUA_PATH, user.pw_uid, user.pw_gid)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to write client IP hash salt file")
        raise NginxFileError("Failed to write client IP hash salt file") from err


def _get_logged_client_address_directive(
    client_ip_hash_salt: str | None,
) -> "nginx.Key | NginxLuaSection":
    """Build the directive that sets $logged_client_address for a server block.

    Args:
        client_ip_hash_salt: Salt used to hash client IP addresses, or None to log
            client IP addresses in plaintext.

    Returns:
        A plain "set" directive when hashing is disabled, or a Lua block computing
        the salted SHA-256 hash of the client address when enabled.
    """
    if client_ip_hash_salt is None:
        return nginx.Key("set", "$logged_client_address $remote_addr")
    lua_code = f"""local sha2 = require "sha2"
        local encoded_salt = require "{NGINX_CLIENT_IP_SALT_LUA_MODULE}"
        local salt = ngx.decode_base64(encoded_salt)
        return sha2.sha256(salt .. ngx.var.remote_addr)
        """
    return NginxLuaSection("set_by_lua_block $logged_client_address", lua_code)


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
    log_format_config = nginx.Conf(
        nginx.Key("log_format", f"{NGINX_MAIN_LOG_FORMAT_NAME} '{NGINX_MAIN_LOG_FORMAT}'"),
        nginx.Key("log_format", f"{NGINX_CACHE_LOG_FORMAT_NAME} '{NGINX_CACHE_LOG_FORMAT}'"),
    )
    _store_http_config("cache_log_format", log_format_config)

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
        # NGINX_SECRETS_PATH is searched first so that a compromised/writable
        # /usr/share/lua/5.1 cannot shadow the client IP hash salt module.
        nginx.Key("lua_package_path", f"{NGINX_SECRETS_PATH}/?.lua;/usr/share/lua/5.1/?.lua;;"),
        nginx.Key("lua_shared_dict", "healthcheck 1m"),
        nginx.Key("lua_socket_log_errors", "off"),
        # lua-resty cosockets (used by the healthcheck module for "https" type
        # checks) verify server certificates against lua_ssl_trusted_certificate,
        # a directive distinct from proxy_ssl_trusted_certificate (used for the
        # actual proxied requests). Without it, any HTTPS healthcheck with
        # ssl_verify enabled fails with "unable to get local issuer certificate",
        # even against publicly trusted certificates.
        nginx.Key("lua_ssl_trusted_certificate", str(ca_certs.CA_BUNDLE_PATH)),
        nginx.Key("lua_ssl_verify_depth", "10"),
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
            nginx.Key("listen", f"127.0.0.1:{NGINX_STATUS_PORT}"),
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


def _build_proxy_cache_path(
    cache_dir: Path,
    identifier: str,
    config: LocationConfig,
) -> str:
    """Build the proxy_cache_path directive value.

    Args:
        cache_dir: The directory to store cache files.
        identifier: The unique cache zone identifier.
        config: The location configuration with cache parameters.

    Returns:
        The proxy_cache_path value string.
    """
    # use_temp_path=off: write cache files directly to cache_dir instead of a staging area.
    # levels=1:2: use a two-level subdirectory hierarchy (1 then 2 hex chars) under cache_dir
    # to keep any single directory from holding too many cache files.
    # keys_zone=<identifier>:10m: shared memory zone (10MB) nginx uses to track cache keys
    # and metadata for this cache.
    value = f"{cache_dir} use_temp_path=off levels=1:2 keys_zone={identifier}:10m"
    # inactive: how long a cached item can go unaccessed before nginx evicts it from disk.
    value += f" inactive={config.cache_inactive}"
    if config.cache_max_size:
        # max_size: upper bound on total disk space the cache zone may use.
        value += f" max_size={config.cache_max_size}"
    return value


def _create_virtualhost_config(  # pylint: disable=too-many-locals,too-many-arguments,too-many-positional-arguments
    identifier: str,
    port: int,
    configuration: LocationConfig,
    instance_name: str,
    tls: TLSConfig | None = None,
    client_ip_hash_salt: str | None = None,
) -> str:
    """Create the nginx configuration file for a virtual host listening on a given port.

    Args:
        identifier: A unique string used to name config and log files (e.g. the port as string).
        port: The TCP port nginx should listen on for this backend.
        configuration: The configuration of the backend.
        instance_name: The name of this instance. This is to uniquely identify this instance in
            logs and metrics. The name will be used in filenames.
        tls: Optional TLS configuration for the frontend certificate.
        client_ip_hash_salt: Salt used to hash client IP addresses in logs, or None to log
            client IP addresses in plaintext.

    Raises:
        NginxConfigurationError: Failed to convert the configuration to nginx format.
    """
    logger.info("Creating the nginx site configuration file for port %s", port)
    resolved_tls = tls or TLSConfig()

    lua_healthcheck_workers = ""
    server_cache_dir = NGINX_PROXY_CACHE_DIR_PATH / identifier
    _ensure_directory_exist_with_ownership(server_cache_dir)
    try:
        nginx_config = nginx.Conf(
            nginx.Key(
                "proxy_cache_path",
                _build_proxy_cache_path(server_cache_dir, identifier, configuration),
            ),
        )
        listen_value = f"{port} ssl" if resolved_tls.frontend_cert_path else str(port)
        server_config = nginx.Server(
            nginx.Key("listen", listen_value),
            nginx.Key("proxy_cache", identifier),
            _get_logged_client_address_directive(client_ip_hash_salt),
            nginx.Key(
                "access_log",
                f"{_get_access_log_path(identifier, instance_name)} {NGINX_MAIN_LOG_FORMAT_NAME}",
            ),
            nginx.Key(
                "access_log",
                f"{_get_cache_log_path(identifier, instance_name)} {NGINX_CACHE_LOG_FORMAT_NAME}",
            ),
            nginx.Key("error_log", _get_error_log_path(identifier, instance_name)),
        )
        if resolved_tls.frontend_cert_path is not None:
            server_config.add(nginx.Key("ssl_certificate", str(resolved_tls.frontend_cert_path)))
            server_config.add(
                nginx.Key("ssl_certificate_key", str(resolved_tls.frontend_cert_path))
            )

        upstream = f"backend-{identifier}"
        upstream_keys = _get_upstream_config_keys(configuration)
        upstream_config = nginx.Upstream(upstream, *upstream_keys)
        nginx_config.add(upstream_config)

        location_keys = _get_location_config_keys(configuration, upstream)
        server_config.add(nginx.Location("/", *location_keys))

        lua_healthcheck_workers += _get_upstream_healthchecks_worker(upstream, configuration)

        nginx_config.add(server_config)
    except nginx.ParseError as err:
        logger.exception(
            "Unable to convert port %s configuration to nginx format: %s", port, configuration
        )
        raise NginxConfigurationError(
            f"Unable to convert port {port} configuration to nginx format: {configuration}"
        ) from err

    _store_and_enable_site_config(identifier, nginx_config)

    return lua_healthcheck_workers


def _get_upstream_config_keys(config: LocationConfig) -> tuple[nginx.Key, ...]:
    """Create the nginx keys for the upstream configuration.

    Args:
        config: The location configurations.

    Returns:
        The nginx.Key for the upstream configuration.
    """
    keys = [
        nginx.Key(
            "server",
            f"{url.host}:{url.port} fail_timeout={config.fail_timeout}",
        )
        for url in config.backends
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
    scheme = config.backends[0].scheme
    valid_status_str = ",".join(str(status) for status in config.healthcheck_config.valid_status)
    hc_path = config.healthcheck_config.path
    backend_hostname = config.backend_hostname
    # Include a Host header when a backend hostname is configured so the health check
    # request matches the real proxied request, allowing it to pass Host-header-based
    # network ACLs (e.g. transparent proxies) that the backend may sit behind.
    host_header = rf"\r\nHost: {backend_hostname}" if backend_hostname else ""
    # https type only: sets the SNI/hostname used during the SSL handshake, mirroring the
    # Host header above so certificate validation also targets the correct hostname.
    host_option = f'\n            host = "{backend_hostname}",' if backend_hostname else ""
    # Avoid a trailing comma after ssl_verify when no host option is being appended.
    ssl_verify_suffix = f",{host_option}" if host_option else ""
    ssl_verify_line = f"{str(config.healthcheck_config.ssl_verify).lower()}{ssl_verify_suffix}"
    # port is intentionally omitted so each peer uses its own port from the upstream block,
    # enabling per-peer healthchecks when backends use different ports.
    return rf"""ok, err = hc.spawn_checker{{
            shm = "healthcheck",
            upstream = "{upstream}",
            type = "{scheme}",

            http_req = "GET {hc_path} HTTP/1.0{host_header}\r\n\r\n",

            interval = {config.healthcheck_config.interval},
            timeout = 1000,
            fall = 3,
            rise = 2,
            valid_statuses = {{{valid_status_str}}},
            concurrency = 10,
            ssl_verify = {ssl_verify_line}
        }}
        if not ok then
            ngx.log(ngx.ERR, "failed to spawn health checker: ", err)
            return
        end
    """


def _get_location_config_keys(
    config: LocationConfig,
    upstream: str,
) -> tuple[nginx.Key, ...]:
    """Create the nginx keys for location configuration.

    Args:
        config: The location configurations.
        upstream: The upstream hostname for the backends.

    Returns:
        The nginx.Key for the Location configuration.
    """
    scheme = config.backends[0].scheme
    keys: list[nginx.Key] = [
        nginx.Key("proxy_pass", f"{scheme}://{upstream}/"),
        nginx.Key("proxy_cache_lock", "on"),
        # nginx defaults both of these to 5s, which is too short for the large files
        # (e.g. Ubuntu ISOs) this charm is designed to cache: once either bound is
        # hit, nginx will still let concurrent requests thundering-herd the backend
        # while the first fetch is still running. 300s gives large downloads a
        # realistic chance to finish before the lock is abandoned.
        nginx.Key("proxy_cache_lock_age", "300s"),
        nginx.Key("proxy_cache_lock_timeout", "300s"),
    ]

    if scheme == "https" and config.backend_hostname:
        # Use the combined CA bundle (system CAs + any operator-supplied certs
        # from receive-ca-cert) so both public and private backend CAs are trusted.
        keys.extend(
            [
                nginx.Key("proxy_set_header", f"Host {config.backend_hostname}"),
                nginx.Key("proxy_ssl_name", config.backend_hostname),
                nginx.Key("proxy_ssl_server_name", "on"),
                nginx.Key("proxy_ssl_verify", "on"),
                nginx.Key("proxy_ssl_verify_depth", "10"),
                nginx.Key("proxy_ssl_trusted_certificate", str(ca_certs.CA_BUNDLE_PATH)),
            ]
        )

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
