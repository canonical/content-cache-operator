# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for unit tests."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from state import (
    BACKENDS_FIELD_NAME,
    CACHE_INACTIVE_FIELD_NAME,
    CACHE_MAX_SIZE_FIELD_NAME,
    FAIL_TIMEOUT_FIELD_NAME,
    HEALTHCHECK_INTERVAL_FIELD_NAME,
    HEALTHCHECK_PATH_FIELD_NAME,
    HEALTHCHECK_SSL_VERIFY_FIELD_NAME,
    HEALTHCHECK_VALID_STATUS_FIELD_NAME,
    PROXY_CACHE_VALID_FIELD_NAME,
)

SAMPLE_INTEGRATION_DATA = {
    BACKENDS_FIELD_NAME: '["http://10.10.1.1:80", "http://10.10.2.2:80"]',
    FAIL_TIMEOUT_FIELD_NAME: "30s",
    HEALTHCHECK_INTERVAL_FIELD_NAME: "2000",
    HEALTHCHECK_PATH_FIELD_NAME: "/",
    HEALTHCHECK_SSL_VERIFY_FIELD_NAME: "false",
    HEALTHCHECK_VALID_STATUS_FIELD_NAME: "[200]",
    PROXY_CACHE_VALID_FIELD_NAME: '["200 302 1h", "404 1m"]',
    CACHE_INACTIVE_FIELD_NAME: "10m",
    CACHE_MAX_SIZE_FIELD_NAME: "",
}


@pytest.fixture(name="patch_ca_certs", scope="function", autouse=True)
def patch_ca_certs_fixture(monkeypatch, tmp_path: Path) -> None:
    """Patch the ca_certs module to use a temporary directory."""
    certs_dir = tmp_path / "certs"
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", certs_dir)
    monkeypatch.setattr("ca_certs.CA_BUNDLE_PATH", certs_dir / "ca-bundle.pem")


@pytest.fixture(name="patch_nginx_manager", scope="function")
def patch_nginx_manager_fixture(monkeypatch, tmp_path: Path) -> None:
    """Patch the nginx_manager module."""
    monkeypatch.setattr("nginx_manager.NGINX_CONFD_PATH", tmp_path / "conf.d")
    monkeypatch.setattr(
        "nginx_manager.NGINX_HEALTHCHECKS_CONF_PATH", tmp_path / "conf.d" / "lua_healthchecks.conf"
    )
    monkeypatch.setattr("nginx_manager.NGINX_SITES_ENABLED_PATH", tmp_path / "sites-enabled")
    monkeypatch.setattr("nginx_manager.NGINX_MODULES_ENABLED_PATH", tmp_path / "modules-enabled")
    monkeypatch.setattr("nginx_manager.NGINX_SITES_AVAILABLE_PATH", tmp_path / "sites-available")
    monkeypatch.setattr("nginx_manager.NGINX_LOG_PATH", tmp_path / "logs")
    monkeypatch.setattr("nginx_manager.NGINX_PROXY_CACHE_DIR_PATH", tmp_path / "cache")
    monkeypatch.setattr("nginx_manager.os.chown", MagicMock())


@pytest.fixture(name="mock_nginx_manager", scope="function")
def mock_nginx_manager_fixture(monkeypatch) -> MagicMock:
    """Mock the nginx_manager module for charm module."""
    mock_nginx_manager = MagicMock()
    mock_nginx_manager.initialize = MagicMock()
    mock_nginx_manager.stop = MagicMock()
    mock_nginx_manager.update_and_load_config = MagicMock()
    mock_nginx_manager.health_check = MagicMock()
    mock_nginx_manager.health_check.return_value = True

    monkeypatch.setattr("charm.nginx_manager.initialize", mock_nginx_manager.initialize)
    monkeypatch.setattr("charm.nginx_manager.stop", mock_nginx_manager.stop)
    monkeypatch.setattr(
        "charm.nginx_manager.update_and_load_config", mock_nginx_manager.update_and_load_config
    )
    monkeypatch.setattr("charm.nginx_manager.health_check", mock_nginx_manager.health_check)
    monkeypatch.setattr(
        "charm.get_cache_backend_url", MagicMock(return_value="http://10.0.0.1:8080")
    )
    return mock_nginx_manager
