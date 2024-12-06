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
from charms.operator_libs_linux.v0.apt import (
    DebianRepository,
    GPGKeyError,
    PackageError,
    PackageNotFoundError,
    RepositoryMapping,
    add_package,
    import_key,
    update,
)

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

NGINX_BIN = "/usr/local/openresty/nginx/sbin/nginx"
NGINX_PACKAGE = "openresty"
NGINX_SERVICE = "openresty"
NGINX_MAIN_CONF_PATH = Path("/usr/local/openresty/nginx/conf/nginx.conf")
NGINX_CERTIFICATES_PATH = Path("/etc/nginx/certs")
NGINX_SITES_ENABLED_PATH = Path("/etc/nginx/sites-enabled")
NGINX_SITES_AVAILABLE_PATH = Path("/etc/nginx/sites-available")
NGINX_LOG_PATH = Path("/var/log/nginx")
NGINX_PROXY_CACHE_DIR_PATH = Path("/data/nginx/cache")
NGINX_USER = "www-data"

NGINX_STATUS_URL_PATH = "/nginx_status"
NGINX_BACKENDS_STATUS_URL_PATH = "/nginx_backends_status"
NGINX_BACKEND_STATUS_URL_PATH = "/nginx_backend_status"
NGINX_HEALTH_CHECK_TIMEOUT = 300

OPENRESTY_PUBLIC_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFkg3CEBCADG5Vem2p+1p6yV2jZfNsbJBPY1KYzR9weF/K3hmLODcrTaWfiD
EugHwKlAptGDGBtrMsERjUiOWUNUS8IHa+R6tzhnQePG6wO7/yGWBC4J82BkCT2x
M7zCDgldtNYkNqoBc0UfE4ln+WR/RX1DuzPM+DTBZBXLqRJVJFyFtHVJn8I5HPO2
hj51uYqHsewTyAkGzABV4gmSIETSmcU5KDisQ9Vt5OllE0ylh7+kakDFZklyBCHT
3IAuZhA18mw2qk1z5bnn/GpQ4fJi5w25lb9sqhhxta3ogwWWdJzXA+Nevb2dez8i
bpzPeFnba9q0UVD2VJ25e99DpG15aPvNt+tbABEBAAG0JU9wZW5SZXN0eSBBZG1p
biA8YWRtaW5Ab3BlbnJlc3R5LmNvbT6JATgEEwECACIFAlkg3CECGwMGCwkIBwMC
BhUIAgkKCwQWAgMBAh4BAheAAAoJEJfbdEPV7et08k0H/iIOiZmDavSKE7NSPLxS
ddRLh4+OGL3QW8JZh/+UaX1Z17G3q8kKSJwOemZBL/jIDkoMuHs1Hq0yp9vJ8BaS
5unX+FRmivwdS5yvkS9s3oA3iJbHagXw0KMnr+baDDNrUwo9MeO0m9muNF/eDoRz
FZ9SpOrgxwhz0kOOt8j+gxWk3TaQ6/JonH4rm3XtP4GMKOKQuUo6l8+pMPEfM209
nMv82kRPAxRV2TwRYToB+TithLTQytJTBytLA+ck5Ny8sGoO5PQWRyx6gj+Bhg0O
rFXfg7/sP2/FEeiDZcF2qn/VMDPvnC7ux2EQdI05MMGFY/pkjVYtLJC2Nb17Bcqj
DH25AQ0EWSDcIQEIAJOoTY0vf0mr+PGUbnv0KKtk65CTzKmICmWIAkCxZaTH+o/3
Lt9ZDtANH1ot3xVTkKg+qBuexh53jnyXyIaIfNqavH1gm+9JusrApVOad2ruODT5
XeVamz0blq37LTmJ7A4T1i8WvB0BQ3j1vh6XkVW6xq1URzVOYyhVqNNq2UIP9M9Y
wtiIIans5i11qmDtZwqxcSYoqSjgz+03M6Dn0UPB1OQdHjOPx7GwHG8+6sVyr+8A
9G8SlKWre2/qdDyZNdgxalOi5ManCwWSURJRuY7s858qFUm0/5dLMAtWWEbYEmYc
EUxbxQM2jPEaDmvvauZNup+a5DZXpRjpWcg19c0AEQEAAYkBHwQYAQIACQUCWSDc
IQIbDAAKCRCX23RD1e3rdG0dB/9EWT8sTVPOlgFAF2WVZT3bFiqiIC9Dg6Wblt/K
Id/p73gbDNTkeeTvGErAPPQwsKkbD1w2rIYoRzEJ1zVrLgaAbeH/frbQaYNu7c+3
Wm93gxBxjL9Jyrs3jq5jwR4kJ5j+a/GEPtTDqtXzZHvyCP2PWDoQWANNAQDuTpYE
LGHfDF9pmTVwuhkh2IFcH/ZBZUvcxP/w3jXqEiPti/rFN8wKSQtBgWI0pBpXGdrJ
Tl3mIE4jLbPmkxidP1yUFx9wzEVu3soXViehMua9nOeotGOKF4DgekzCnFuXNnd3
h2EiDJbMKk+QJcMPliIePZCP9JWj7n0ok9ccLg5XcNwiFEtn
=U4Wk
-----END PGP PUBLIC KEY BLOCK-----"""

# Unit test is not valuable as the module is closely coupled with nginx.
# This should be tested with integration tests.


class NginxLuaSection:  # pylint: disable=R0903
    """Simple class to insert Lua code in Nginx conf.

    Attrs:
        as_strings: a string to be dumped in the nginx configuration file
    """

    def __init__(self, name: str, content: str) -> None:
        """Initialize with section's name and content.

        Args:
            name: name of the lua section
            content: content of the lua section
        """
        self.name = name
        self.content = content

    @property
    def as_strings(self) -> str:
        """Return a string to be dumped in nginx conf."""
        return f"{self.name} {{{self.content}}}\n"


def initialize() -> None:  # pragma: no cover
    """Initialize the nginx server.

    Raises:
        NginxSetupError: Failure to set up nginx.
    """
    logger.info("Installing and enabling nginx")
    # The install, systemctl enable, and systemctl start are idempotent.
    try:
        import_key(OPENRESTY_PUBLIC_KEY)
    except GPGKeyError as e:
        raise NginxSetupError("Failed to load openresty repository key.") from e

    if os.path.exists(
        "/etc/apt/sources.list"
    ):  # FIX ME: apt libs raise an error on empty source list
        os.unlink("/etc/apt/sources.list")
    repositories = RepositoryMapping()

    if "openresty" not in repositories:
        repositories.add(
            DebianRepository(
                enabled=True,
                repotype="deb",
                uri="http://openresty.org/package/ubuntu",
                release="noble",
                groups=["main"],
            )
        )  # FIX ME
        update()

    try:
        add_package(NGINX_PACKAGE)
    except (PackageError, PackageNotFoundError) as e:
        raise NginxSetupError("Failed to install nginx.") from e

    logger.info("Clean up default configurati&on files")
    _reset_nginx_files()
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
    except requests.RequestException:
        logger.exception("Failed nginx health check.")
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
        execute_command(["sudo", NGINX_BIN, "-s", "reload"])
        return

    logger.info("Restarting nginx to load the configuration files.")
    execute_command(["sudo", "systemctl", "restart", NGINX_SERVICE])


def _reset_nginx_files() -> None:
    """Reset the Nginx files.

    Raises:
        NginxFileError: File operation errors resetting Nginx files.
    """
    try:
        logger.info("Init nginx config")
        # if not NGINX_MAIN_CONF_PATH.exists():
        _init_nginx_main_conf()
        logger.info("Resetting the nginx sites configuration files directories.")
        if NGINX_SITES_AVAILABLE_PATH.exists():
            shutil.rmtree(NGINX_SITES_AVAILABLE_PATH)
        if NGINX_SITES_ENABLED_PATH.exists():
            shutil.rmtree(NGINX_SITES_ENABLED_PATH)
        # The default permission for nginx configuration files are 755.
        NGINX_SITES_AVAILABLE_PATH.mkdir(mode=0o755, parents=True, exist_ok=True)
        NGINX_SITES_ENABLED_PATH.mkdir(mode=0o755, parents=True, exist_ok=True)
        NGINX_SITES_AVAILABLE_PATH.chmod(mode=0o755)
        NGINX_SITES_ENABLED_PATH.chmod(mode=0o755)
        logger.info("Ensure nginx cache directory is present.")
        NGINX_PROXY_CACHE_DIR_PATH.mkdir(mode=0o755, parents=True, exist_ok=True)
        user = pwd.getpwnam(NGINX_USER)
        os.chown(NGINX_PROXY_CACHE_DIR_PATH, user.pw_uid, user.pw_gid)
        logger.info("Create log path.")
        NGINX_LOG_PATH.mkdir(parents=True, exist_ok=True)
        os.chown(NGINX_LOG_PATH, user.pw_uid, user.pw_gid)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to reset the nginx files.")
        raise NginxFileError("Failed to reset nginx files") from err


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
            ),
            nginx.Location(
                NGINX_BACKENDS_STATUS_URL_PATH,
                nginx.Key("allow", "127.0.0.1"),
                nginx.Key("deny", "all"),
                nginx.Key("default_type", "text/plain"),
                NginxLuaSection(
                    "content_by_lua_block",
                    """local hc = require "resty.upstream.healthcheck"
                ngx.say("Nginx Worker PID: ", ngx.worker.pid())
                ngx.print(hc.status_page())
                """,
                ),
            ),
        )
    )
    _create_and_enable_config("nginx_status", nginx_config)


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
    try:
        nginx_config = nginx.Conf(
            nginx.Key(
                "proxy_cache_path",
                f"{NGINX_PROXY_CACHE_DIR_PATH} use_temp_path=off levels=1:2 keys_zone={host}:10m",
            ),
            # From: https://github.com/openresty/lua-resty-upstream-healthcheck
            nginx.Key("lua_shared_dict", "healthcheck 1m"),
            nginx.Key("lua_socket_log_errors", "off"),
        )
        server_config = nginx.Server(
            nginx.Key("proxy_cache", host),
            nginx.Key("server_name", host),
            nginx.Key("access_log", _get_access_log_path(host)),
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
            nginx_config.add(
                NginxLuaSection(
                    "init_worker_by_lua_block",
                    _get_upstream_healthchecks_worker(upstream, config),
                )
            )

            location_keys = _get_location_config_keys(config, upstream, host)
            server_config.add(nginx.Location(path, *location_keys))

        # local hc = require "resty.upstream.healthcheck"}
        #                       """
        #     )

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
    return rf"""local hc = require "resty.upstream.healthcheck"

        local ok, err = hc.spawn_checker{{
            shm = "healthcheck",
            upstream = "{upstream}",
            type = "{config.protocol.value}",

            http_req = "GET {config.healthcheck_path} HTTP/1.0\r\nHost: {config.hostname}\r\n\r\n",

            port = {433 if config.protocol.value == "https" else 80},
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


def _init_nginx_main_conf() -> None:
    """Generate the main nginx configuration."""
    NGINX_MAIN_CONF_PATH.write_text(
        """user www-data;
worker_processes auto;
pid /usr/local/openresty/nginx/logs/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;
events {
worker_connections 768;
}
http {
sendfile on;
tcp_nopush on;
types_hash_max_size 2048;
include /usr/local/openresty/nginx/conf/mime.types;
default_type application/octet-stream;
ssl_prefer_server_ciphers on;
access_log /var/log/nginx/access.log;
gzip on;
include /etc/nginx/conf.d/*.conf;
include /etc/nginx/sites-enabled/*;
}
"""
    )
