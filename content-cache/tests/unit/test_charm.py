# Copyright 2025 Canonical Ltd.
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
from errors import NginxConfigurationAggregateError, NginxConfigurationError, NginxFileError
from tests.unit.conftest import SAMPLE_INTEGRATION_DATA


def test_start_no_relation(charm: ContentCacheCharm, mock_nginx_manager: MagicMock):
    """
    arrange: A working charm.
    act: None.
    assert: Waiting for integration to join. Method to initialize nginx called.
    """
    assert charm.unit.status == ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)
    mock_nginx_manager.initialize.assert_called_once()


def test_stop_nginx(charm: ContentCacheCharm, mock_nginx_manager: MagicMock):
    """
    arrange: A working charm. Reset the mocks.
    act: Emit stop event.
    assert: Method to stop nginx called.
    """
    mock_nginx_manager.stop.reset_mock()

    charm._on_stop(MagicMock())

    mock_nginx_manager.stop.assert_called_once()


def test_update_status_no_relation(charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: Emit update status.
    assert: Charm waiting for integration.
    """
    charm._on_update_status(MagicMock())
    assert charm.unit.status == ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)


@pytest.mark.parametrize(
    ["health", "status"],
    [
        pytest.param(False, ops.MaintenanceStatus(NGINX_NOT_READY_MESSAGE)),
        pytest.param(True, ops.ActiveStatus()),
    ],
)
def test_update_status_with_integration(
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
    harness: Harness,
    health: bool,
    status: ops.StatusBase,
):
    """
    arrange: Charm is integrated, and nginx is not ready.
    act: Emit update status.
    assert: Charm waiting for integration.
    """
    mock_nginx_manager.health_check.return_value = health
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    charm._on_update_status(MagicMock())
    assert charm.unit.status == status


def test_add_integration(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: Add a config integration.
    assert: Charm in active. The data is parsed correctly.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    assert charm.unit.status == ops.ActiveStatus()

    # Test the integration data is correct
    config = state.get_nginx_config(charm)
    assert len(config) == 1
    assert relation_id in config
    location_config = config[relation_id]
    assert location_config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert location_config.protocol.value == "https"
    assert location_config.fail_timeout == "30s"
    assert location_config.healthcheck_config.path == "/"
    assert location_config.healthcheck_config.interval == 2000
    assert location_config.proxy_cache_valid == ("200 302 1h", "404 1m")


def test_remove_integration(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: A working charm with a config integration.
    act: Remove the integration.
    assert: Charm in active. No data.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    assert charm.unit.status == ops.ActiveStatus()

    harness.remove_relation(relation_id)
    assert charm.unit.status == ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)

    # Test no data
    config = state.get_nginx_config(charm)
    assert not config


def test_invalid_integration_data(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: A working charm.
    act: Add a config integration with invalid data.
    assert: Charm in block state.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[state.PROTOCOL_FIELD_NAME] = "invalid"
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=data,
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
    harness.add_relation(CACHE_CONFIG_INTEGRATION_NAME, remote_app="config", app_data={})

    config = state.get_nginx_config(charm)
    assert not config


def test_nginx_file_error(monkeypatch, harness: Harness, charm: ContentCacheCharm):
    """
    arrange: The update_and_load_config to raise the NginxFileError.
    act: Add configuration integration.
    assert: The error is re-raised.
    """
    monkeypatch.setattr(
        "nginx_manager.update_and_load_config",
        MagicMock(side_effect=NginxFileError("Mock error")),
    )

    with pytest.raises(NginxFileError):
        harness.add_relation(
            CACHE_CONFIG_INTEGRATION_NAME,
            remote_app="config",
            app_data=SAMPLE_INTEGRATION_DATA,
        )


def test_nginx_config_error(
    monkeypatch, harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: The update_and_load_config to raise the NginxConfigurationAggregateError.
    act: Add configuration integration and load the nginx config.
    assert: The charm status reflects the errors raised
    """
    monkeypatch.setattr(
        "charm.nginx_manager.update_and_load_config",
        MagicMock(
            side_effect=NginxConfigurationAggregateError(
                ("mock host",), (NginxConfigurationError("Mock errors"),)
            )
        ),
    )

    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    charm._load_nginx_config()
    assert charm.unit.status == ops.ActiveStatus("Error for host: ('mock host',)")



# ============================
# Story 1 TDD: New behavior tests (should FAIL until production code is updated)
# ============================

def test_get_nginx_config_returns_flat_per_relation_dict(
    harness: Harness, charm: ContentCacheCharm
):
    """
    arrange: Charm with a cache-config integration.
    act: Get nginx config.
    assert: Returns flat dict keyed by relation_id (int), not nested by hostname.
    """
    from ipaddress import IPv4Address
    from state import LocationConfig, get_nginx_config

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    config = get_nginx_config(charm)

    assert relation_id in config
    assert isinstance(config[relation_id], LocationConfig)
    assert config[relation_id].backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))


def test_unique_port_allocated_per_relation(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: Charm with two different cache-config integrations.
    act: Add both integrations and query their ports.
    assert: Each relation gets a unique port in the expected range.
    """
    rel_id_1 = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config1",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    rel_id_2 = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config2",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    port_1 = charm._get_port_for_relation(rel_id_1)
    port_2 = charm._get_port_for_relation(rel_id_2)

    assert port_1 != port_2
    assert port_1 >= 8080
    assert port_2 >= 8080


def test_port_stable_for_same_relation(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: Charm with a cache-config integration.
    act: Query the port for the same relation twice.
    assert: Same port is returned both times (stable allocation).
    """
    rel_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    port_first = charm._get_port_for_relation(rel_id)
    port_second = charm._get_port_for_relation(rel_id)

    assert port_first == port_second
