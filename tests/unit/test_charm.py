# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the charm."""

from ipaddress import IPv4Address
from unittest.mock import MagicMock

import ops
import pytest
from ops.testing import Harness

import state
from charm import (
    CACHE_CONFIG_INTEGRATION_NAME,
    NGINX_NOT_READY_MESSAGE,
    WAIT_FOR_CONFIG_MESSAGE,
    ContentCacheCharm,
)


def test_start_no_relation(charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: None.
    assert: Waiting for integration to join. Nginx init called.
    """
    assert charm.unit.status == ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)
    charm._nginx.init.assert_called_once()


def test_stop_nginx(charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: Emit stop event.
    assert: Nginx stop called.
    """
    charm._on_stop(MagicMock())
    charm._nginx.stop.assert_called_once()


def test_update_status_no_relation(charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: Emit update status.
    assert: Charm waiting for integration.
    """
    charm._on_update_status(MagicMock())
    assert charm.unit.status == ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)


@pytest.mark.parametrize(
    ["ready", "status"],
    [
        pytest.param(False, ops.MaintenanceStatus(NGINX_NOT_READY_MESSAGE)),
        pytest.param(True, ops.ActiveStatus()),
    ],
)
def test_update_status_with_integration(
    charm: ContentCacheCharm, harness: Harness, ready: bool, status: ops.StatusBase
):
    """
    arrange: Charm is integrated, and nginx is not ready.
    act: Emit update status.
    assert: Charm waiting for integration.
    """
    charm._nginx.ready_check.return_value = ready
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data={
            "location": "example.com",
            "backends": '["10.10.1.1", "10.1.1.2"]',
            "protocol": "https",
        },
    )

    charm._on_update_status(MagicMock())
    assert charm.unit.status == status


def test_add_integration(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: Add a config integration.
    assert: Charm in active. The data is parsed correctly.
    """
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data={
            "location": "example.com",
            "backends": '["10.10.1.1", "10.1.1.2"]',
            "protocol": "https",
        },
    )
    assert charm.unit.status == ops.ActiveStatus()

    # Test the integration data is correct
    config = state.get_nginx_config(charm)
    assert len(config) == 1
    assert "example.com" in config
    location_config = config["example.com"]
    assert location_config.location == "example.com"
    assert location_config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.1.1.2"))
    assert location_config.protocol == "https"


def test_remove_integration(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: A working charm with a config integration.
    act: Remove the integration.
    assert: Charm in active. No data.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data={
            "location": "example.com",
            "backends": '["10.10.1.1", "10.1.1.2"]',
            "protocol": "https",
        },
    )
    assert charm.unit.status == ops.ActiveStatus()

    harness.remove_relation(relation_id)
    assert charm.unit.status == ops.BlockedStatus("Waiting for integration with config charm")

    # Test no data
    config = state.get_nginx_config(charm)
    assert not config


def test_invalid_integration_data(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: Add a config integration with invalid data.
    assert: Charm in block state.
    """
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data={
            "location": "example.com",
            "backends": '["10.10.1.1", "10.1.1.2"]',
            "protocol": "invalid",
        },
    )
    assert charm.unit.status == ops.BlockedStatus(
        "Faulty data from integration 0: Config error: [\"protocol = invalid: Input should be 'http' or 'https'\"]"
    )


def test_empty_integration_data(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: Add a config integration with no data.
    assert: The configuration parsed from integration is empty.

    It seems harness does not fire relation-changed if calling add_relation or 
    update_relation_data with empty dict. Therefore the test checks for the configuration parsed 
    manually. 
    """
    harness.add_relation( CACHE_CONFIG_INTEGRATION_NAME, remote_app="config", app_data={})
    
    config = state.get_nginx_config(charm)
    assert not config
