# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for nginx_manager module."""

import base64
from unittest.mock import MagicMock

import pytest
import requests

import ca_certs
import nginx_manager
from errors import NginxFileError
from state import LocationConfig
from tests.unit.conftest import SAMPLE_INTEGRATION_DATA

SAMPLE_HTTPS_EXTRA = {
    "backend_hostname": "test.example.com",
}


def test_reset_files_with_missing_dir(patch_nginx_manager: None):
    """
    arrange: The nginx sites config dir are missing.
    act: Reset the sites config files.
    assert: The directories exists with the right permissions.
    """
    mock_instance_name = "mock-test_0"

    nginx_manager.NGINX_SITES_ENABLED_PATH.unlink(missing_ok=True)
    nginx_manager.NGINX_SITES_AVAILABLE_PATH.unlink(missing_ok=True)

    nginx_manager._reset_nginx_files(mock_instance_name)

    assert nginx_manager.NGINX_SITES_ENABLED_PATH.exists()
    assert nginx_manager.NGINX_SITES_AVAILABLE_PATH.exists()
    assert nginx_manager.NGINX_SITES_ENABLED_PATH.stat().st_mode == 0o40755
    assert nginx_manager.NGINX_SITES_AVAILABLE_PATH.stat().st_mode == 0o40755
    # Not checking for owner, as the test is not necessary run as same user as juju charm (root).


def test_reset_files_with_existing_files(patch_nginx_manager: None):
    """
    arrange: There are existing files in nginx sites config dir.
    act: Reset the sites config files.
    assert: The directories are empty.
    """
    mock_instance_name = "mock-test_0"
    nginx_manager._reset_nginx_files(mock_instance_name)
    enable_path = nginx_manager._get_sites_enabled_path("unit-test")
    available_path = nginx_manager._get_sites_available_path("unit-test")
    enable_path.touch()
    available_path.touch()
    assert enable_path.exists(), "Test setup failure"
    assert available_path.exists(), "Test setup failure"

    nginx_manager._reset_nginx_files(mock_instance_name)

    assert not enable_path.exists()
    assert not available_path.exists()
    assert not tuple(nginx_manager.NGINX_SITES_AVAILABLE_PATH.iterdir())
    assert not tuple(nginx_manager.NGINX_SITES_ENABLED_PATH.iterdir())


def test_update_config_with_valid_config(monkeypatch, patch_nginx_manager: None):
    """
    arrange: Valid URL-format configuration data.
    act: Create configuration files from the data.
    assert: The files are created with host:port backends and correct scheme.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    mock_status_check = MagicMock()
    mock_status_check.return_value = True
    monkeypatch.setattr("nginx_manager._systemctl_status_check", mock_status_check)
    port = 8080
    sample_data = {
        1: (
            port,
            LocationConfig.from_integration_data(
                {
                    **SAMPLE_INTEGRATION_DATA,
                    **SAMPLE_HTTPS_EXTRA,
                    "backends": '["https://10.10.10.1:443", "https://10.10.10.2:443"]',
                }
            ),
        )
    }

    nginx_manager.update_and_load_config(sample_data, mock_instance_name)

    config_file_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()

    assert "server 10.10.10.1:443" in config_file_content
    assert "fail_timeout=30s" in config_file_content
    assert "server 10.10.10.2:443" in config_file_content
    assert f"listen {port}" in config_file_content
    assert "proxy_ssl_server_name on" in config_file_content
    assert "access_log" in config_file_content
    assert "error_log" in config_file_content

    healthchecks_config_file_content = nginx_manager.NGINX_HEALTHCHECKS_CONF_PATH.read_text()
    assert "GET /" in healthchecks_config_file_content
    assert (
        "port" not in healthchecks_config_file_content
    )  # per-peer ports used from upstream block
    assert "interval = 2000" in healthchecks_config_file_content
    assert "ssl_verify = false" in healthchecks_config_file_content
    assert (
        f"lua_ssl_trusted_certificate {ca_certs.CA_BUNDLE_PATH}"
        in healthchecks_config_file_content
    )
    assert "lua_ssl_verify_depth" in healthchecks_config_file_content

    status_page_config_file_content = nginx_manager._get_sites_available_path(
        "nginx_status"
    ).read_text()
    assert f"listen 127.0.0.1:{nginx_manager.NGINX_STATUS_PORT}" in status_page_config_file_content


def test_get_upstream_config_keys_http(patch_nginx_manager: None):
    """
    arrange: A LocationConfig with http backends on port 80.
    act: Call _get_upstream_config_keys.
    assert: Keys contain host:port entries with fail_timeout.
    """
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)
    keys = nginx_manager._get_upstream_config_keys(config)

    key_strings = [k.as_strings for k in keys]
    assert any("10.10.1.1:80" in s for s in key_strings)
    assert any("10.10.2.2:80" in s for s in key_strings)
    assert any("fail_timeout=30s" in s for s in key_strings)


def test_get_upstream_config_keys_https(patch_nginx_manager: None):
    """
    arrange: A LocationConfig with https backends on port 443.
    act: Call _get_upstream_config_keys.
    assert: Keys contain host:port entries.
    """
    data = {
        **SAMPLE_INTEGRATION_DATA,
        **SAMPLE_HTTPS_EXTRA,
        "backends": '["https://10.10.1.1:443"]',
    }
    config = LocationConfig.from_integration_data(data)
    keys = nginx_manager._get_upstream_config_keys(config)

    key_strings = [k.as_strings for k in keys]
    assert any("10.10.1.1:443" in s for s in key_strings)


def test_get_location_config_keys_http(patch_nginx_manager: None):
    """
    arrange: A LocationConfig with http backends.
    act: Call _get_location_config_keys.
    assert: proxy_pass uses http scheme.
    """
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)
    upstream = "test-upstream"
    keys = nginx_manager._get_location_config_keys(config, upstream)

    key_strings = [k.as_strings for k in keys]
    assert any(f"http://{upstream}/" in s for s in key_strings)


def test_get_location_config_keys_https(patch_nginx_manager: None):
    """
    arrange: A LocationConfig with https backends.
    act: Call _get_location_config_keys.
    assert: proxy_pass uses https scheme.
    """
    data = {
        **SAMPLE_INTEGRATION_DATA,
        **SAMPLE_HTTPS_EXTRA,
        "backends": '["https://10.10.1.1:443"]',
    }
    config = LocationConfig.from_integration_data(data)
    upstream = "test-upstream"
    keys = nginx_manager._get_location_config_keys(config, upstream)

    key_strings = [k.as_strings for k in keys]
    assert any(f"https://{upstream}/" in s for s in key_strings)


def test_healthcheck_worker_uses_per_peer_ports(patch_nginx_manager: None):
    """
    arrange: A LocationConfig with backends on different ports.
    act: Call _get_upstream_healthchecks_worker.
    assert: The generated lua script has no global port override, so each peer
            uses its own port from the upstream server entry.
    """
    data = {
        **SAMPLE_INTEGRATION_DATA,
        "backends": '["http://10.10.1.1:8080", "http://10.10.2.2:9090"]',
    }
    config = LocationConfig.from_integration_data(data)
    upstream = "test-upstream"

    script = nginx_manager._get_upstream_healthchecks_worker(upstream, config)

    assert "port =" not in script, "global port override must be absent for per-peer healthchecks"


def test_healthcheck_worker_without_backend_hostname_omits_host_header(
    patch_nginx_manager: None,
):
    """
    arrange: A LocationConfig without backend_hostname set.
    act: Call _get_upstream_healthchecks_worker.
    assert: The generated http_req has no Host header and no SNI host option,
            preserving prior behaviour for backends with no configured hostname.
    """
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)
    upstream = "test-upstream"

    script = nginx_manager._get_upstream_healthchecks_worker(upstream, config)

    assert "Host:" not in script
    assert "host =" not in script


def test_healthcheck_worker_with_backend_hostname_adds_host_header(
    patch_nginx_manager: None,
):
    """
    arrange: A LocationConfig with backend_hostname set for an http backend.
    act: Call _get_upstream_healthchecks_worker.
    assert: The generated http_req includes a Host header matching backend_hostname,
            so the healthcheck request can pass Host-header-based network ACLs.
    """
    data = {
        **SAMPLE_INTEGRATION_DATA,
        "backend_hostname": "origin.example.com",
    }
    config = LocationConfig.from_integration_data(data)
    upstream = "test-upstream"

    script = nginx_manager._get_upstream_healthchecks_worker(upstream, config)

    assert r"Host: origin.example.com\r\n" in script


def test_healthcheck_worker_https_with_backend_hostname_adds_sni_host_option(
    patch_nginx_manager: None,
):
    """
    arrange: A LocationConfig with https backends and backend_hostname set.
    act: Call _get_upstream_healthchecks_worker.
    assert: The generated lua script sets the "host" option (used for SNI/SSL
            handshake hostname), in addition to the Host header.
    """
    data = {
        **SAMPLE_INTEGRATION_DATA,
        **SAMPLE_HTTPS_EXTRA,
        "backends": '["https://10.10.1.1:443"]',
    }
    config = LocationConfig.from_integration_data(data)
    upstream = "test-upstream"

    script = nginx_manager._get_upstream_healthchecks_worker(upstream, config)

    assert 'host = "test.example.com"' in script
    assert r"Host: test.example.com\r\n" in script


def test_healthcheck_worker_upstream_entries_carry_ports(patch_nginx_manager: None):
    """
    arrange: A LocationConfig with backends on different ports.
    act: Call _get_upstream_config_keys.
    assert: Each server entry carries its own host:port so the healthcheck
            library can use the correct port per peer.
    """
    data = {
        **SAMPLE_INTEGRATION_DATA,
        "backends": '["http://10.10.1.1:8080", "http://10.10.2.2:9090"]',
    }
    config = LocationConfig.from_integration_data(data)

    keys = nginx_manager._get_upstream_config_keys(config)

    key_strings = [k.as_strings for k in keys]
    assert any("10.10.1.1:8080" in s for s in key_strings)
    assert any("10.10.2.2:9090" in s for s in key_strings)


def test_get_location_config_keys_https_with_backend_hostname_adds_ssl_directives(
    patch_nginx_manager: None,
):
    """
    arrange: A LocationConfig with https backends and backend_hostname set.
    act: Call _get_location_config_keys.
    assert: proxy_ssl directives using the system CA bundle are added.
    """
    data = {
        **SAMPLE_INTEGRATION_DATA,
        **SAMPLE_HTTPS_EXTRA,
        "backends": '["https://10.10.1.1:443"]',
        "healthcheck_ssl_verify": "true",
    }
    config = LocationConfig.from_integration_data(data)

    keys = nginx_manager._get_location_config_keys(config, "test-upstream")

    key_strings = [k.as_strings for k in keys]
    assert any("proxy_set_header" in s and "Host test.example.com" in s for s in key_strings)
    assert any("proxy_ssl_name" in s and "test.example.com" in s for s in key_strings)
    assert any("proxy_ssl_server_name" in s and "on" in s for s in key_strings)
    assert any("proxy_ssl_verify" in s and "on" in s for s in key_strings)
    assert any("proxy_ssl_verify_depth" in s and "10" in s for s in key_strings)
    assert any(
        "proxy_ssl_trusted_certificate" in s and str(ca_certs.CA_BUNDLE_PATH) in s
        for s in key_strings
    )
    assert any("proxy_pass" in s and "https" in s for s in key_strings)


def test_get_location_config_keys_https_without_hostname_has_no_ssl_directives(
    patch_nginx_manager: None,
):
    """
    arrange: A LocationConfig with https backends but no backend_hostname.
    act: Attempt to build the config (validator should block it).
    assert: ConfigurationError raised because backend_hostname is required for HTTPS.
    """
    from errors import ConfigurationError

    data = {
        **SAMPLE_INTEGRATION_DATA,
        "backends": '["https://10.10.1.1:443"]',
        # No backend_hostname set
    }
    with pytest.raises(ConfigurationError, match="backend-hostname is required"):
        LocationConfig.from_integration_data(data)


def test_get_location_config_keys_https_uses_combined_ca_bundle(
    patch_nginx_manager: None,
):
    """
    arrange: A LocationConfig with https backends and backend_hostname set.
    act: Call _get_location_config_keys.
    assert: proxy_ssl_trusted_certificate points to the combined CA bundle.
    """
    data = {
        **SAMPLE_INTEGRATION_DATA,
        **SAMPLE_HTTPS_EXTRA,
        "backends": '["https://10.10.1.1:443"]',
    }
    config = LocationConfig.from_integration_data(data)

    keys = nginx_manager._get_location_config_keys(config, "upstream")

    key_strings = [k.as_strings for k in keys]
    assert any("proxy_set_header" in s and "Host test.example.com" in s for s in key_strings)
    assert any("proxy_ssl_name" in s and "test.example.com" in s for s in key_strings)
    assert any("proxy_ssl_server_name" in s and "on" in s for s in key_strings)
    assert any("proxy_ssl_verify" in s and "on" in s for s in key_strings)
    assert any("proxy_ssl_verify_depth" in s and "10" in s for s in key_strings)
    assert any(
        "proxy_ssl_trusted_certificate" in s and str(ca_certs.CA_BUNDLE_PATH) in s
        for s in key_strings
    )


def test_get_location_config_keys_http_has_no_ssl_directives(patch_nginx_manager: None):
    """
    arrange: A LocationConfig with http backends.
    act: Call _get_location_config_keys.
    assert: No proxy_ssl directives added for http backends.
    """
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)

    keys = nginx_manager._get_location_config_keys(config, "upstream")

    key_strings = [k.as_strings for k in keys]
    assert not any("proxy_ssl" in s for s in key_strings)


def test_health_check(monkeypatch, patch_nginx_manager: None):
    """
    arrange: Patch the requests.get to return successful health check.
    act: Perform health check.
    assert: The health check returns true.
    """
    monkeypatch.setattr("nginx_manager.requests.get", MagicMock())
    assert nginx_manager.health_check()


def test_health_check_failure(monkeypatch, patch_nginx_manager: None):
    """
    arrange: Patch the requests.get to raise error.
    act: Perform health check.
    assert: The health check returns false.
    """
    monkeypatch.setattr(
        "nginx_manager.requests.get",
        MagicMock(side_effect=requests.exceptions.HTTPError("Mock error")),
    )
    assert not nginx_manager.health_check()


def test_file_errors(monkeypatch, patch_nginx_manager: None):
    """
    arrange: Patch nginx.dumpf to raise file errors.
    act: Run _create_and_enable_config.
    assert: NginxFileError raised.
    """
    monkeypatch.setattr("nginx_manager.nginx.dumpf", MagicMock(side_effect=OSError("Mock error")))

    with pytest.raises(NginxFileError):
        nginx_manager._store_and_enable_site_config("mock-host", {})

    monkeypatch.setattr(
        "nginx_manager.nginx.dumpf", MagicMock(side_effect=PermissionError("Mock error"))
    )

    with pytest.raises(NginxFileError):
        nginx_manager._store_and_enable_site_config("mock-host", {})


def test_update_config_with_cache_cert_adds_ssl_directives(
    monkeypatch, patch_nginx_manager: None, tmp_path
):
    """
    arrange: Valid config and a frontend_cert_path pointing to a PEM file.
    act: Call update_and_load_config with frontend_cert_path set.
    assert: The nginx site config contains ssl listen, ssl_certificate, ssl_certificate_key.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    cert_file = tmp_path / "cache.pem"
    cert_file.write_text("cert-content")
    port = 8080
    sample_data = {
        1: (
            port,
            LocationConfig.from_integration_data(
                {**SAMPLE_INTEGRATION_DATA, "backends": '["http://10.10.10.1:80"]'}
            ),
        )
    }

    nginx_manager.update_and_load_config(
        sample_data, mock_instance_name, frontend_cert_path=cert_file
    )

    config_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()
    assert f"listen {port} ssl" in config_content
    assert f"ssl_certificate {cert_file}" in config_content
    assert f"ssl_certificate_key {cert_file}" in config_content


def test_update_config_without_cache_cert_no_ssl_directives(
    monkeypatch, patch_nginx_manager: None
):
    """
    arrange: Valid config, no cache_cert_path.
    act: Call update_and_load_config without cache_cert_path.
    assert: The nginx site config does not contain ssl directives.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    port = 8080
    sample_data = {
        1: (
            port,
            LocationConfig.from_integration_data(
                {**SAMPLE_INTEGRATION_DATA, "backends": '["http://10.10.10.1:80"]'}
            ),
        )
    }

    nginx_manager.update_and_load_config(sample_data, mock_instance_name)

    config_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()
    assert "ssl" not in config_content


def test_proxy_cache_path_includes_inactive(monkeypatch, patch_nginx_manager: None):
    """
    arrange: Configuration with cache_inactive set.
    act: Generate nginx site config.
    assert: proxy_cache_path directive contains inactive= parameter.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    port = 8080
    sample_data = {
        1: (
            port,
            LocationConfig.from_integration_data(
                {
                    **SAMPLE_INTEGRATION_DATA,
                    "backends": '["http://10.10.10.1:80"]',
                    "cache_inactive": "1h",
                }
            ),
        )
    }

    nginx_manager.update_and_load_config(sample_data, mock_instance_name)

    config_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()
    assert "inactive=1h" in config_content


def test_proxy_cache_path_includes_max_size(monkeypatch, patch_nginx_manager: None):
    """
    arrange: Configuration with cache_max_size set.
    act: Generate nginx site config.
    assert: proxy_cache_path directive contains max_size= parameter.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    port = 8080
    sample_data = {
        1: (
            port,
            LocationConfig.from_integration_data(
                {
                    **SAMPLE_INTEGRATION_DATA,
                    "backends": '["http://10.10.10.1:80"]',
                    "cache_max_size": "2g",
                }
            ),
        )
    }

    nginx_manager.update_and_load_config(sample_data, mock_instance_name)

    config_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()
    assert "max_size=2g" in config_content


def test_proxy_cache_path_no_max_size_when_empty(monkeypatch, patch_nginx_manager: None):
    """
    arrange: Configuration with empty cache_max_size.
    act: Generate nginx site config.
    assert: proxy_cache_path directive does not contain max_size= parameter.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    port = 8080
    sample_data = {
        1: (
            port,
            LocationConfig.from_integration_data(
                {**SAMPLE_INTEGRATION_DATA, "backends": '["http://10.10.10.1:80"]'}
            ),
        )
    }

    nginx_manager.update_and_load_config(sample_data, mock_instance_name)

    config_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()
    assert "max_size" not in config_content


def test_location_contains_proxy_cache_lock(monkeypatch, patch_nginx_manager: None):
    """
    arrange: Valid configuration.
    act: Generate nginx site config.
    assert: Location block contains proxy_cache_lock on.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    port = 8080
    sample_data = {
        1: (
            port,
            LocationConfig.from_integration_data(
                {**SAMPLE_INTEGRATION_DATA, "backends": '["http://10.10.10.1:80"]'}
            ),
        )
    }

    nginx_manager.update_and_load_config(sample_data, mock_instance_name)

    config_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()
    assert "proxy_cache_lock on" in config_content
    assert "proxy_cache_lock_age 300s" in config_content
    assert "proxy_cache_lock_timeout 300s" in config_content


def test_get_logged_client_address_directive_disabled():
    """
    arrange: No client IP hash salt.
    act: Call _get_logged_client_address_directive.
    assert: Returns a plain "set" directive using $remote_addr.
    """
    directive = nginx_manager._get_logged_client_address_directive(None)

    assert isinstance(directive, nginx_manager.nginx.Key)
    assert directive.name == "set"
    assert directive.value == "$logged_client_address $remote_addr"


def test_get_logged_client_address_directive_enabled():
    """
    arrange: A configured client IP hash salt.
    act: Call _get_logged_client_address_directive.
    assert: Returns a Lua block hashing the client address with the salt module.
    """
    directive = nginx_manager._get_logged_client_address_directive("some-salt")

    assert isinstance(directive, nginx_manager.NginxLuaSection)
    assert directive.name == "set_by_lua_block $logged_client_address"
    assert 'require "sha2"' in directive.content
    assert f'require "{nginx_manager.NGINX_CLIENT_IP_SALT_LUA_MODULE}"' in directive.content
    assert "sha2.sha256(salt .. ngx.var.remote_addr)" in directive.content


def test_write_client_ip_hash_salt_writes_file(patch_nginx_manager: None):
    """
    arrange: A salt value.
    act: Call _write_client_ip_hash_salt.
    assert: The Lua module file is written base64-encoded with restrictive permissions.
    """
    nginx_manager._write_client_ip_hash_salt("some-salt")

    content = nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.read_text(encoding="utf-8")
    assert content.startswith('return "')
    prefix_len = len('return "')
    encoded = content.strip()[prefix_len:-1]
    assert base64.b64decode(encoded).decode("utf-8") == "some-salt"
    mode = nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.stat().st_mode & 0o777
    assert mode == 0o640
    dir_mode = nginx_manager.NGINX_SECRETS_PATH.stat().st_mode & 0o777
    assert dir_mode == 0o750


def test_write_client_ip_hash_salt_removes_file_when_none(patch_nginx_manager: None):
    """
    arrange: An existing salt Lua module file.
    act: Call _write_client_ip_hash_salt with None.
    assert: The Lua module file is removed.
    """
    nginx_manager._write_client_ip_hash_salt("some-salt")
    assert nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists()

    nginx_manager._write_client_ip_hash_salt(None)

    assert not nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists()


def test_update_config_logs_plaintext_client_address_by_default(
    monkeypatch, patch_nginx_manager: None
):
    """
    arrange: Valid configuration, no client IP hash salt.
    act: Generate nginx site config.
    assert: The server block sets $logged_client_address from $remote_addr directly.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    port = 8080
    sample_data = {1: (port, LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA))}

    nginx_manager.update_and_load_config(sample_data, mock_instance_name)

    config_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()
    assert "set $logged_client_address $remote_addr;" in config_content
    assert nginx_manager.NGINX_MAIN_LOG_FORMAT_NAME in config_content
    assert "$logged_client_address" in config_content


def test_update_config_disabling_salt_removes_module_only_after_reload(
    monkeypatch, patch_nginx_manager: None
):
    """
    arrange: A previously written salt module, and a mock reload command that records
        whether the module still exists at the moment it is invoked.
    act: Call update_and_load_config with client_ip_hash_salt=None.
    assert: The module still exists when the reload command runs, and is only removed
        afterwards, so a still-active hashed configuration never loses the module out from
        under it mid-reload.
    """
    nginx_manager._write_client_ip_hash_salt("old-salt")
    assert nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists()
    module_existed_during_reload = []

    def _record_and_succeed(_cmd):
        """Record whether the salt module exists, then report the command as successful.

        Args:
            _cmd: The command that would have been executed (unused).

        Returns:
            A tuple mimicking a successful execute_command call.
        """
        module_existed_during_reload.append(nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists())
        return 0, "", ""

    fake_execute_command = MagicMock(side_effect=_record_and_succeed)
    monkeypatch.setattr("nginx_manager.execute_command", fake_execute_command)
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    mock_instance_name = "mock-test_0"
    port = 8080
    sample_data = {1: (port, LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA))}

    nginx_manager.update_and_load_config(sample_data, mock_instance_name, client_ip_hash_salt=None)

    assert module_existed_during_reload == [True]
    assert not nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists()


def test_update_config_logs_hashed_client_address_when_salt_configured(
    monkeypatch, patch_nginx_manager: None
):
    """
    arrange: Valid configuration with a client IP hash salt.
    act: Generate nginx site config.
    assert: The server block hashes the client address via a Lua block and the salt
        module is written to disk.
    """
    mock_instance_name = "mock-test_0"
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    port = 8080
    sample_data = {1: (port, LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA))}

    nginx_manager.update_and_load_config(
        sample_data, mock_instance_name, client_ip_hash_salt="some-salt"
    )

    config_content = nginx_manager._get_sites_enabled_path(str(port)).read_text()
    assert "set_by_lua_block $logged_client_address" in config_content
    assert nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists()


def test_update_config_enabling_salt_writes_module_only_after_reload(
    monkeypatch, patch_nginx_manager: None
):
    """
    arrange: No pre-existing salt module, and a mock reload command that records whether
        the new module already exists at the moment it is invoked.
    act: Call update_and_load_config with a new client_ip_hash_salt.
    assert: The module does not exist yet when the reload command runs, and is only written
        afterwards, so a still-active old configuration is never paired with a new,
        not-yet-applied salt.
    """
    assert not nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists()
    module_existed_during_reload = []

    def _record_and_succeed(_cmd):
        """Record whether the salt module exists, then report the command as successful.

        Args:
            _cmd: The command that would have been executed (unused).

        Returns:
            A tuple mimicking a successful execute_command call.
        """
        module_existed_during_reload.append(nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists())
        return 0, "", ""

    fake_execute_command = MagicMock(side_effect=_record_and_succeed)
    monkeypatch.setattr("nginx_manager.execute_command", fake_execute_command)
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    mock_instance_name = "mock-test_0"
    port = 8080
    sample_data = {1: (port, LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA))}

    nginx_manager.update_and_load_config(
        sample_data, mock_instance_name, client_ip_hash_salt="new-salt"
    )

    assert module_existed_during_reload == [False]
    assert nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.exists()


def test_update_config_failure_does_not_commit_salt_change(monkeypatch, patch_nginx_manager: None):
    """
    arrange: A pre-existing salt module for the old salt, and a vhost config generator that
        raises NginxConfigurationError (simulating a failure partway through generation).
    act: Call update_and_load_config with a new client_ip_hash_salt.
    assert: NginxConfigurationAggregateError propagates and the old salt module is left
        untouched, since nginx was never told to reload with the new configuration.
    """
    nginx_manager._write_client_ip_hash_salt("old-salt")
    old_content = nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.read_text(encoding="utf-8")
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    monkeypatch.setattr("nginx_manager._systemctl_status_check", MagicMock(return_value=True))
    monkeypatch.setattr(
        "nginx_manager._create_virtualhost_config",
        MagicMock(side_effect=nginx_manager.NginxConfigurationError("mock error")),
    )
    mock_instance_name = "mock-test_0"
    port = 8080
    sample_data = {1: (port, LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA))}

    with pytest.raises(nginx_manager.NginxConfigurationAggregateError):
        nginx_manager.update_and_load_config(
            sample_data, mock_instance_name, client_ip_hash_salt="new-salt"
        )

    assert nginx_manager.NGINX_CLIENT_IP_SALT_LUA_PATH.read_text(encoding="utf-8") == old_content
