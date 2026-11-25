# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the charm."""

from typing import Mapping
from unittest.mock import MagicMock

import ops
import pytest
from ops.testing import Harness

import state
from charm import (
    CACHE_CONFIG_INTEGRATION_NAME,
    INVALID_CACHE_CONFIG_MESSAGE,
    ContentCacheBackendsConfigCharm,
)

# Test might need to access private methods.
# pylint: disable=protected-access

JujuConfigValue = str | int | float | bool
JujuConfigKey = str
JujuConfig = Mapping[JujuConfigKey, JujuConfigValue]


SAMPLE_CONFIG: JujuConfig = {
    state.BACKENDS_CONFIG_NAME: "http://10.10.1.1:80,http://10.1.1.2:80",
    state.FAIL_TIMEOUT_CONFIG_NAME: "30s",
    state.HEALTHCHECK_PATH_CONFIG_NAME: "/health",
    state.HEALTHCHECK_INTERVAL_CONFIG_NAME: 2000,
    state.PROXY_CACHE_VALID_CONFIG_NAME: '["200 302 1h", "404 1m"]',
    state.CACHE_INACTIVE_CONFIG_NAME: "10m",
    state.CACHE_MAX_SIZE_CONFIG_NAME: "",
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


def test_config_changed_republishes_configuration(
    charm: ContentCacheBackendsConfigCharm, harness: Harness
):
    """
    arrange: Leader unit with configuration and integration.
    act: Change a configuration value after the initial publication.
    assert: The updated configuration is published.
    """
    harness.update_config(SAMPLE_CONFIG)

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="content-cache",
    )
    harness.add_relation_unit(relation_id, remote_unit_name="content-cache/0")

    data = harness.get_relation_data(relation_id, app_or_unit=charm.app.name)
    assert data["fail_timeout"] == "30s"

    harness.update_config({**SAMPLE_CONFIG, state.FAIL_TIMEOUT_CONFIG_NAME: "1h"})

    data = harness.get_relation_data(relation_id, app_or_unit=charm.app.name)
    assert data["fail_timeout"] == "1h"
    assert charm.unit.status == ops.ActiveStatus()


def test_relation_created_publishes_configuration(
    charm: ContentCacheBackendsConfigCharm, harness: Harness
):
    """
    arrange: Leader unit with configurations and no integration.
    act: Add the integration relation.
    assert: The configuration is published without another config change.
    """
    harness.update_config(SAMPLE_CONFIG)

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="content-cache",
    )

    data = harness.get_relation_data(relation_id, app_or_unit=charm.app.name)
    assert data["fail_timeout"] == "30s"


def test_leader_elected_publishes_configuration(
    charm: ContentCacheBackendsConfigCharm, harness: Harness
):
    """
    arrange: Follower unit with configurations and integration.
    act: The unit becomes leader.
    assert: The configuration is published.
    """
    harness.set_leader(False)
    harness.update_config(SAMPLE_CONFIG)

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="content-cache",
    )
    harness.add_relation_unit(relation_id, remote_unit_name="content-cache/0")

    assert harness.get_relation_data(relation_id, app_or_unit=charm.app.name) == {}

    harness.set_leader(True)

    data = harness.get_relation_data(relation_id, app_or_unit=charm.app.name)
    assert data["fail_timeout"] == "30s"


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


def test_integration_with_invalid_library_config(
    charm: ContentCacheBackendsConfigCharm, harness: Harness
):
    """
    arrange: Leader unit with integration and an otherwise valid configuration.
    act: Update a value the shared library rejects.
    assert: The unit is blocked with the short cache-config status message.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="content-cache",
    )
    harness.add_relation_unit(relation_id, remote_unit_name="content-cache/0")

    harness.update_config({**SAMPLE_CONFIG, state.FAIL_TIMEOUT_CONFIG_NAME: "0s"})

    assert charm.unit.status == ops.BlockedStatus(INVALID_CACHE_CONFIG_MESSAGE)


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
