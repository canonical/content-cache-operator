# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for unit tests."""

from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock

import pytest
from ops.testing import Harness

from charm import ContentCacheCharm
from state import (
    BACKENDS_FIELD_NAME,
    BACKENDS_PATH_FIELD_NAME,
    FAIL_TIMEOUT_FIELD_NAME,
    HEALTHCHECK_INTERVAL_FIELD_NAME,
    HEALTHCHECK_PATH_FIELD_NAME,
    HOSTNAME_FIELD_NAME,
    PATH_FIELD_NAME,
    PROTOCOL_FIELD_NAME,
    PROXY_CACHE_VALID_FIELD_NAME,
)

SAMPLE_INTEGRATION_DATA = {
    HOSTNAME_FIELD_NAME: "example.com",
    PATH_FIELD_NAME: "/",
    BACKENDS_FIELD_NAME: '["10.10.1.1", "10.10.2.2"]',
    PROTOCOL_FIELD_NAME: "https",
    FAIL_TIMEOUT_FIELD_NAME: "30s",
    BACKENDS_PATH_FIELD_NAME: "/",
    HEALTHCHECK_PATH_FIELD_NAME: "/",
    HEALTHCHECK_INTERVAL_FIELD_NAME: "2000",
    PROXY_CACHE_VALID_FIELD_NAME: '["200 302 1h", "404 1m"]',
}


@pytest.fixture(name="patch_nginx_manager", scope="function")
def patch_nginx_manager_fixture(monkeypatch, tmp_path: Path) -> None:
    """Patch the nginx_manager module."""
    monkeypatch.setattr("nginx_manager.NGINX_MAIN_CONF_PATH", tmp_path / "nginx.conf")
    monkeypatch.setattr("nginx_manager.NGINX_CONFD_PATH", tmp_path / "conf.d")
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
    return mock_nginx_manager


@pytest.fixture(name="harness", scope="function")
def harness_fixture(monkeypatch, mock_nginx_manager: MagicMock) -> Iterator[Harness]:
    """The ops testing harness fixture.

    The mock_nginx_manager is to ensure the nginx_manager module is patched.
    """
    harness = Harness(ContentCacheCharm)
    harness.begin_with_initial_hooks()
    yield harness
    harness.cleanup()


@pytest.fixture(name="charm", scope="function")
def charm_fixture(harness: Harness) -> ContentCacheCharm:
    """The charm fixture."""
    return harness.charm
