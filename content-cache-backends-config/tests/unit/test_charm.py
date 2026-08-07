# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the charm using ops-scenario."""

import json
from typing import cast

import pytest
import scenario

import state
from charm import CACHE_CONFIG_INTEGRATION_NAME

SAMPLE_CONFIG: dict[str, str | int | float | bool] = {
    state.BACKENDS_CONFIG_NAME: "http://10.10.1.1:80,http://10.1.1.2:80",
    state.FAIL_TIMEOUT_CONFIG_NAME: "30s",
    state.HEALTHCHECK_PATH_CONFIG_NAME: "/health",
    state.HEALTHCHECK_INTERVAL_CONFIG_NAME: 2000,
    state.PROXY_CACHE_VALID_CONFIG_NAME: '["200 302 1h", "404 1m"]',
    state.CACHE_INACTIVE_CONFIG_NAME: "10m",
    state.CACHE_MAX_SIZE_CONFIG_NAME: "",
}


@pytest.fixture(name="cache_config_relation")
def cache_config_relation_fixture() -> scenario.SubordinateRelation:
    """A cache-config subordinate relation fixture."""
    return scenario.SubordinateRelation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="content-cache",
    )


def test_start_leader_no_relation(ctx: scenario.Context):
    """
    arrange: A working leader charm with no integration.
    act: The charm started.
    assert: Charm in block state.
    """
    out = ctx.run(ctx.on.start(), scenario.State(leader=True))
    assert out.unit_status == scenario.BlockedStatus("Waiting for integration")


def test_start_follower(ctx: scenario.Context):
    """
    arrange: A working follower charm.
    act: The charm started.
    assert: Follower unit is active.
    """
    out = ctx.run(ctx.on.start(), scenario.State(leader=False))
    assert out.unit_status == scenario.ActiveStatus()


def test_config_no_integration(ctx: scenario.Context):
    """
    arrange: Leader charm with no integration.
    act: Update the configuration with valid values.
    assert: The charm remains in blocked status (no relation).
    """
    out = ctx.run(ctx.on.config_changed(), scenario.State(leader=True, config=SAMPLE_CONFIG))
    assert out.unit_status == scenario.BlockedStatus("Waiting for integration")


def test_integration_config_missing(
    ctx: scenario.Context,
    cache_config_relation: scenario.SubordinateRelation,
):
    """
    arrange: Charm with integration but no config.
    act: Trigger config_changed.
    assert: Charm in block state.
    """
    out = ctx.run(
        ctx.on.config_changed(),
        scenario.State(leader=True, relations={cache_config_relation}),
    )
    assert isinstance(out.unit_status, scenario.BlockedStatus)


def test_integration_data_not_leader(
    ctx: scenario.Context,
    cache_config_relation: scenario.SubordinateRelation,
):
    """
    arrange: Follow unit with configurations and integration.
    act: Trigger config_changed.
    assert: The integration has no data (follower doesn't write).
    """
    out = ctx.run(
        ctx.on.config_changed(),
        scenario.State(
            leader=False,
            config=SAMPLE_CONFIG,
            relations={cache_config_relation},
        ),
    )
    assert out.unit_status == scenario.ActiveStatus()
    out_rel = out.get_relations(CACHE_CONFIG_INTEGRATION_NAME)[0]
    assert out_rel.local_app_data == {}


def test_integration_data_via_config_changed(
    ctx: scenario.Context,
    cache_config_relation: scenario.SubordinateRelation,
):
    """
    arrange: Leader unit with configurations and integration.
    act: Trigger config_changed.
    assert: The configuration is in the databag.
    """
    out = ctx.run(
        ctx.on.config_changed(),
        scenario.State(
            leader=True,
            config=SAMPLE_CONFIG,
            relations={cache_config_relation},
        ),
    )
    assert out.unit_status == scenario.ActiveStatus()
    out_rel = out.get_relations(CACHE_CONFIG_INTEGRATION_NAME)[0]
    data = cast(dict[str, str], out_rel.local_app_data)

    backends = json.loads(data["backends"])
    assert len(backends) == 2
    assert any("10.10.1.1" in b for b in backends)
    assert any("10.1.1.2" in b for b in backends)
    assert all(b.startswith("http://") for b in backends)
    assert "protocol" not in data
    assert data["healthcheck_interval"] == "2000"
    assert data["healthcheck_path"] == "/health"
    assert data["healthcheck_ssl_verify"] == "true"
    assert data["healthcheck_valid_status"] == "[200]"
    assert data["fail_timeout"] == "30s"
    assert data["proxy_cache_valid"] == '["200 302 1h", "404 1m"]'
    assert data[state.CACHE_INACTIVE_FIELD_NAME] == "10m"
    assert data.get(state.CACHE_MAX_SIZE_FIELD_NAME, "") == ""


def test_integration_data_via_relation_changed(
    ctx: scenario.Context,
    cache_config_relation: scenario.SubordinateRelation,
):
    """
    arrange: Leader unit with configurations and integration.
    act: Trigger relation-changed.
    assert: The configuration is in the databag.
    """
    out = ctx.run(
        ctx.on.relation_changed(cache_config_relation),
        scenario.State(
            leader=True,
            config=SAMPLE_CONFIG,
            relations={cache_config_relation},
        ),
    )
    assert out.unit_status == scenario.ActiveStatus()
    out_rel = out.get_relations(CACHE_CONFIG_INTEGRATION_NAME)[0]
    data = cast(dict[str, str], out_rel.local_app_data)
    assert json.loads(data["backends"])
    assert data[state.CACHE_INACTIVE_FIELD_NAME] == "10m"


def test_integration_with_invalid_config(
    ctx: scenario.Context,
    cache_config_relation: scenario.SubordinateRelation,
):
    """
    arrange: Leader unit with integration.
    act: Update the configuration to invalid value.
    assert: The unit is in blocked status.
    """
    bad_config: dict[str, str | int | float | bool] = dict(SAMPLE_CONFIG)
    bad_config[state.BACKENDS_CONFIG_NAME] = ""
    out = ctx.run(
        ctx.on.config_changed(),
        scenario.State(leader=True, config=bad_config, relations={cache_config_relation}),
    )
    assert out.unit_status == scenario.BlockedStatus("Empty backends configuration found")


@pytest.mark.parametrize(
    "is_leader",
    [
        pytest.param(True, id="leader"),
        pytest.param(False, id="follower"),
    ],
)
def test_integration_removed(
    ctx: scenario.Context,
    cache_config_relation: scenario.SubordinateRelation,
    is_leader: bool,
):
    """
    arrange: Unit with integration.
    act: Remove integration.
    assert: Block status (leader) or Active status (follower).
    """
    out = ctx.run(
        ctx.on.relation_broken(cache_config_relation),
        scenario.State(leader=is_leader, config=SAMPLE_CONFIG, relations={cache_config_relation}),
    )
    if is_leader:
        assert out.unit_status == scenario.BlockedStatus("Waiting for integration")
    else:
        assert out.unit_status == scenario.ActiveStatus()
