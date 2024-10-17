# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for nginx_manager module."""

from ipaddress import IPv4Address
from unittest.mock import MagicMock

import nginx_manager
from state import LocationConfig


def test_reset_files_with_missing_dir(patch_nginx_manager_path: None):
    """
    arrange: The nginx sites config dir are missing.
    act: Reset the sites config files.
    assert: The directories exists with the right permissions.
    """
    nginx_manager.NGINX_SITES_ENABLED_PATH.unlink(missing_ok=True)
    nginx_manager.NGINX_SITES_AVAILABLE_PATH.unlink(missing_ok=True)

    nginx_manager._reset_sites_config_files()

    assert nginx_manager.NGINX_SITES_ENABLED_PATH.exists()
    assert nginx_manager.NGINX_SITES_AVAILABLE_PATH.exists()
    assert nginx_manager.NGINX_SITES_ENABLED_PATH.stat().st_mode == 0o40755
    assert nginx_manager.NGINX_SITES_AVAILABLE_PATH.stat().st_mode == 0o40755
    # Not checking for owner, as the test is not necessary run as same user as juju charm (root).


def test_reset_file_with_existing_files(patch_nginx_manager_path: None):
    """
    arrange: There are existing files in nginx sites config dir.
    act: Reset the sites config files.
    assert: The directories are empty.
    """
    nginx_manager._reset_sites_config_files()
    enable_path = nginx_manager._get_sites_enabled_path("unit-test")
    available_path = nginx_manager._get_sites_available_path("unit-test")
    enable_path.touch()
    available_path.touch()
    assert enable_path.exists(), "Test setup failure"
    assert available_path.exists(), "Test setup failure"

    nginx_manager._reset_sites_config_files()

    assert not enable_path.exists()
    assert not available_path.exists()
    assert not tuple(nginx_manager.NGINX_SITES_AVAILABLE_PATH.iterdir())
    assert not tuple(nginx_manager.NGINX_SITES_ENABLED_PATH.iterdir())


def test_update_config_with_valid_config(monkeypatch, patch_nginx_manager_path: None):
    """
    arrange: Valid configuration data.
    act: Create configuration files from the data.
    assert: The files are created and has the configurations.
    """
    monkeypatch.setattr("nginx_manager.execute_command", MagicMock())
    mock_ready_check = MagicMock()
    mock_ready_check.return_value = True
    monkeypatch.setattr("nginx_manager.ready_check", mock_ready_check)
    hostname = "example.com"
    sample_data = {
        hostname: {
            "/path": LocationConfig(
                hostname=hostname,
                path="/path",
                backends=(IPv4Address("10.10.10.2"), IPv4Address("10.10.10.1")),
                protocol="https",
                health_check_path="/health",
                health_check_interval=300,
                backends_path="/backend",
                proxy_cache_valid=("200 302 30m", "404 1m"),
            )
        }
    }

    nginx_manager.update_and_load_config(sample_data)

    config_file_content = nginx_manager._get_sites_enabled_path(hostname).read_text()

    assert "server 10.10.10.1" in config_file_content
    assert "server 10.10.10.2" in config_file_content
    assert "location /path" in config_file_content
    assert "health_check interval=300 uri=/health" in config_file_content
    assert "server_name example.com" in config_file_content
    assert "access_log" in config_file_content
    assert "error_log" in config_file_content
    assert "proxy_cache_valid 200 302 30m" in config_file_content
    assert "proxy_cache_valid 404 1m" in config_file_content
    assert "proxy_pass https://" in config_file_content
    assert "/backend" in config_file_content