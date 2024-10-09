# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Fixtures for unit tests."""

from typing import Iterator
from unittest.mock import MagicMock

import pytest
from ops.testing import Harness

from charm import ContentCacheCharm
from state import (
    BACKENDS_CONFIG_NAME,
    HOSTNAME_CONFIG_NAME,
    PATH_CONFIG_NAME,
    PROTOCOL_CONFIG_NAME,
)

SAMPLE_INTEGRATION_DATA = {
    HOSTNAME_CONFIG_NAME: "example.com",
    PATH_CONFIG_NAME: "/",
    BACKENDS_CONFIG_NAME: '["10.10.1.1", "10.10.2.2"]',
    PROTOCOL_CONFIG_NAME: "https",
}


@pytest.fixture(name="nginx_manager", scope="function")
def nginx_manager_fixture() -> MagicMock:
    mock_manager = MagicMock()
    mock_manager.init = MagicMock()
    mock_manager.load = MagicMock()
    mock_manager.stop = MagicMock()
    mock_manager.update_config = MagicMock()
    mock_manager.ready_check = MagicMock()
    mock_manager.ready_check.return_value = True
    mock_constructor = MagicMock()
    mock_constructor.return_value = mock_manager
    return mock_constructor


@pytest.fixture(name="harness", scope="function")
def harness_fixture(monkeypatch, nginx_manager: MagicMock) -> Iterator[Harness]:
    """The ops testing harness fixture."""
    monkeypatch.setattr("charm.NginxManager", nginx_manager)

    harness = Harness(ContentCacheCharm)
    harness.begin_with_initial_hooks()
    yield harness
    harness.cleanup()


@pytest.fixture(name="charm", scope="function")
def charm_fixture(harness: Harness) -> ContentCacheCharm:
    """The charm fixture"""
    return harness.charm
