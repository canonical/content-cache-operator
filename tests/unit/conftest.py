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
    BACKENDS_CONFIG_NAME,
    BACKENDS_PATH_CONFIG_NAME,
    HEALTH_CHECK_INTERVAL_CONFIG_NAME,
    HEALTH_CHECK_PATH_CONFIG_NAME,
    HOSTNAME_CONFIG_NAME,
    PATH_CONFIG_NAME,
    PROTOCOL_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
)

SAMPLE_INTEGRATION_DATA = {
    HOSTNAME_CONFIG_NAME: "example.com",
    PATH_CONFIG_NAME: "/",
    BACKENDS_CONFIG_NAME: '["10.10.1.1", "10.10.2.2"]',
    PROTOCOL_CONFIG_NAME: "https",
    HEALTH_CHECK_PATH_CONFIG_NAME: "/",
    HEALTH_CHECK_INTERVAL_CONFIG_NAME: "30",
    BACKENDS_PATH_CONFIG_NAME: "/",
    PROXY_CACHE_VALID_CONFIG_NAME: '["200 302 1h", "404 1m"]',
}


@pytest.fixture(name="patch_nginx_manager_path", scope="function")
def patch_nginx_manager_path_fixture(monkeypatch, tmp_path: Path) -> None:
    """Patch the Path used by nginx_manager module."""
    monkeypatch.setattr("nginx_manager.NGINX_SITES_ENABLED_PATH", tmp_path / "sites-enabled")
    monkeypatch.setattr("nginx_manager.NGINX_SITES_AVAILABLE_PATH", tmp_path / "sites-available")


@pytest.fixture(name="mock_nginx_manager", scope="function")
def mock_nginx_manager_fixture(monkeypatch) -> MagicMock:
    """Mock the nginx_manager module for charm module."""
    mock_nginx_manager = MagicMock()
    mock_nginx_manager.initialize = MagicMock()
    mock_nginx_manager.load_config = MagicMock()
    mock_nginx_manager.stop = MagicMock()
    mock_nginx_manager.update_config = MagicMock()
    mock_nginx_manager.ready_check = MagicMock()
    mock_nginx_manager.ready_check.return_value = True

    monkeypatch.setattr("charm.nginx_manager.initialize", mock_nginx_manager.initialize)
    monkeypatch.setattr("charm.nginx_manager.load_config", mock_nginx_manager.load_config)
    monkeypatch.setattr("charm.nginx_manager.stop", mock_nginx_manager.stop)
    monkeypatch.setattr("charm.nginx_manager.update_config", mock_nginx_manager.update_config)
    monkeypatch.setattr("charm.nginx_manager.ready_check", mock_nginx_manager.ready_check)
    return mock_nginx_manager


@pytest.fixture(name="harness", scope="function")
def harness_fixture(mock_nginx_manager: MagicMock) -> Iterator[Harness]:
    """The ops testing harness fixture."""
    harness = Harness(ContentCacheCharm)
    harness.begin_with_initial_hooks()
    yield harness
    harness.cleanup()


@pytest.fixture(name="charm", scope="function")
def charm_fixture(harness: Harness) -> ContentCacheCharm:
    """The charm fixture"""
    return harness.charm
