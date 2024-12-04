# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the charm."""

from typing import Mapping
from unittest.mock import MagicMock

import ops
import pytest
from ops.testing import Harness

import state
from charm import CACHE_CONFIG_INTEGRATION_NAME, ContentCacheBackendsConfigCharm

# Test might need to access private methods.
# pylint: disable=protected-access

JujuConfigValue = str | int | float | bool
JujuConfigKey = str
JujuConfig = Mapping[JujuConfigKey, JujuConfigValue]


SAMPLE_CONFIG: JujuConfig = {
    state.HOSTNAME_CONFIG_NAME: "example.com",
    state.PATH_CONFIG_NAME: "/",
    state.BACKENDS_CONFIG_NAME: "10.10.1.1,10.1.1.2",
    state.PROTOCOL_CONFIG_NAME: "https",
    state.FAIL_TIMEOUT_CONFIG_NAME: "30s",
    state.BACKENDS_PATH_CONFIG_NAME: "/",
    state.PROXY_CACHE_VALID_CONFIG_NAME: '["200 302 1h", "404 1m"]',
}


def test_start(charm: ContentCacheBackendsConfigCharm):
    """
    arrange: A working charm.
    act: The charm started.
    assert: Charm in block state.
    """
    assert charm.unit.status == ops.BlockedStatus("Waiting for integration")


def test_config_no_integration(charm: ContentCacheBackendsConfigCharm, harness: Harness):
    """
    arrange: Charm with no integration.
    act: Update the configuration with valid values.
    assert: The charm in active status.
    """
    harness.update_config(SAMPLE_CONFIG)

    assert charm.unit.status == ops.BlockedStatus("Waiting for integration")


@pytest.mark.parametrize(
    "event",
    [
        pytest.param("_on_config_changed", id="config_changed"),
        pytest.param("_on_cache_config_relation_changed", id="config_relation_changed"),
    ],
)
def test_integration_config_missing(charm: ContentCacheBackendsConfigCharm, event: str):
    """
    arrange: Charm with no integration.
    act: Trigger events.
    assert: Charm in block state.
    """
    mock_event = MagicMock()
    getattr(charm, event)(mock_event)

    assert isinstance(charm.unit.status, ops.BlockedStatus)


@pytest.mark.parametrize(
    "event",
    [
        pytest.param("_on_config_changed", id="config_changed"),
        pytest.param("_on_cache_config_relation_changed", id="config_relation_changed"),
    ],
)
def test_integration_data_not_leader(
    charm: ContentCacheBackendsConfigCharm, harness: Harness, event: str
):
    """
    arrange: Follow unit with configurations and integration.
    act: Trigger events.
    assert: The integration has no data.
    """
    harness.set_leader(False)
    harness.update_config(SAMPLE_CONFIG)

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="content-cache",
    )
    harness.add_relation_unit(relation_id, remote_unit_name="content-cache/0")

    mock_event = MagicMock()
    getattr(charm, event)(mock_event)

    data = harness.get_relation_data(relation_id, app_or_unit=charm.app.name)
    assert charm.unit.status == ops.ActiveStatus()
    assert data == {}


@pytest.mark.parametrize(
    "event",
    [
        pytest.param("_on_config_changed", id="config_changed"),
        pytest.param("_on_cache_config_relation_changed", id="config_relation_changed"),
    ],
)
def test_integration_data(charm: ContentCacheBackendsConfigCharm, harness: Harness, event: str):
    """
    arrange: Leader unit with configurations and integration.
    act: Trigger events.
    assert: The configuration is in the databag.
    """
    harness.update_config(SAMPLE_CONFIG)

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="content-cache",
    )
    harness.add_relation_unit(relation_id, remote_unit_name="content-cache/0")

    mock_event = MagicMock()
    getattr(charm, event)(mock_event)

    data = harness.get_relation_data(relation_id, app_or_unit=charm.app.name)
    assert charm.unit.status == ops.ActiveStatus()
    assert data == {
        "hostname": "example.com",
        "path": "/",
        "backends": '["10.10.1.1", "10.1.1.2"]',
        "protocol": "https",
        "backends_path": "/",
        "fail_timeout": "30s",
        "proxy_cache_valid": '["200 302 1h", "404 1m"]',
    }


def test_integration_with_invalid_config(charm: ContentCacheBackendsConfigCharm, harness: Harness):
    """
    arrange: Leader unit with integration.
    act: Update the configuration to invalid value.
    assert: The unit is in blocked status.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="content-cache",
    )
    harness.add_relation_unit(relation_id, remote_unit_name="content-cache/0")

    harness.update_config({state.BACKENDS_CONFIG_NAME: ""})

    assert charm.unit.status == ops.BlockedStatus("Empty backends configuration found")


@pytest.mark.parametrize(
    "is_leader",
    [
        pytest.param(True, id="leader"),
        pytest.param(False, id="follower"),
    ],
)
def test_integration_removed(
    harness: Harness, charm: ContentCacheBackendsConfigCharm, is_leader: bool
):
    """
    arrange: Unit with integration.
    act: Remove integration.
    assert: Block status
    """
    harness.set_leader(is_leader)
    harness.update_config(SAMPLE_CONFIG)

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="content-cache",
    )
    harness.add_relation_unit(relation_id, remote_unit_name="content-cache/0")
    # When integrating applications the relation changed should fire.
    # https://juju.is/docs/sdk/relation-name-relation-changed-event#heading--emission-sequence
    # However, the harness does not fire relation changed on empty data, so it is manually
    # triggered here.
    charm._on_cache_config_relation_changed(MagicMock())

    assert charm.unit.status == ops.ActiveStatus()

    harness.remove_relation(relation_id)

    if is_leader:
        assert charm.unit.status == ops.BlockedStatus("Waiting for integration")
        return
    # follower unit is always active.
    assert charm.unit.status == ops.ActiveStatus()
