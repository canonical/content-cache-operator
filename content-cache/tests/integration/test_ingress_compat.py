# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for ingress-configurator compatibility.

The pinned ingress-configurator revision vendors the pre-shared-library cache-config
module. This test checks that it interoperates with this repository's content-cache in
both directions:

* ingress-configurator reads and validates the ``cache-backend`` published by
  content-cache.
* content-cache reads and validates the cache configuration published by
  ingress-configurator.

No real haproxy or origin backend is needed: ``any-charm`` provides the haproxy-route
endpoint ingress-configurator publishes its requirements to, and the backend address is
never contacted because only relation data is checked.
"""

import json
import platform
from typing import Any
from urllib.parse import urlparse

import pytest
import pytest_asyncio
import yaml
from juju.application import Application
from juju.model import Model
from juju.unit import Unit

from tests.integration.helpers import run_in_unit

CACHE_APP_NAME = "cache"
CONFIG_APP_NAME = "config"
INGRESS_APP_NAME = "ingress"
MOCK_HAPROXY_APP_NAME = "haproxy"

HAPROXY_ROUTE_MOCK_CHARM_NAME = "any-charm"
HAPROXY_ROUTE_MOCK_CHANNEL = "latest/beta"
INGRESS_CHARM_NAME = "ingress-configurator"
INGRESS_CHANNEL = "latest/edge"
# ingress-configurator revisions still using the vendored cache-config module. Revision
# numbers are per architecture.
INGRESS_REVISIONS = {"x86_64": 162, "aarch64": 163}

BACKEND_ADDRESS = "10.0.0.1"
BACKEND_PORT = 80


def _json_field(value: Any) -> Any:
    """Decode a databag field that holds JSON, tolerating YAML pre-parsing.

    Args:
        value: The field value, either still JSON text or already decoded by YAML.

    Returns:
        The decoded value.
    """
    if isinstance(value, str):
        return json.loads(value)
    return value


async def _relation_app_data(unit: Unit, endpoint: str, remote_app: str) -> dict[str, Any]:
    """Read the application databag a remote app publishes over a relation.

    Args:
        unit: The unit to run ``relation-get`` on.
        endpoint: The relation endpoint name on that unit.
        remote_app: The remote application name owning the databag.

    Returns:
        The decoded application databag.
    """
    return_code, stdout, stderr = await run_in_unit(
        unit=unit,
        command=f"relation-get --app -r $(relation-ids {endpoint}) - {remote_app}",
    )
    assert return_code == 0, f"Failed to read {endpoint} application data: {stderr}"
    data = yaml.safe_load(stdout or "")
    assert isinstance(data, dict), f"Unexpected {endpoint} application data: {stdout}"
    return data


async def _relation_unit_data(unit: Unit, endpoint: str, remote_unit: str) -> dict[str, Any]:
    """Read a remote unit's databag over a relation.

    Args:
        unit: The unit to run ``relation-get`` on.
        endpoint: The relation endpoint name on that unit.
        remote_unit: The remote unit name owning the databag.

    Returns:
        The decoded unit databag.
    """
    return_code, stdout, stderr = await run_in_unit(
        unit=unit,
        command=f"relation-get -r $(relation-ids {endpoint}) - {remote_unit}",
    )
    assert return_code == 0, f"Failed to read {endpoint} unit data: {stderr}"
    data = yaml.safe_load(stdout or "")
    assert isinstance(data, dict), f"Unexpected {endpoint} unit data: {stdout}"
    return data


@pytest_asyncio.fixture(name="cache_app", scope="module")
async def cache_app_fixture(model: Model, charm_file: str) -> Application:
    """Deploy the content-cache charm built from this repository."""
    return await model.deploy(charm_file, CACHE_APP_NAME, base="ubuntu@24.04")


@pytest_asyncio.fixture(name="config_app", scope="module")
async def config_app_fixture(model: Model, config_charm_file: str) -> Application:
    """Deploy the configuration charm with a dummy backend."""
    return await model.deploy(
        config_charm_file,
        CONFIG_APP_NAME,
        base="ubuntu@24.04",
        config={"backends": f"http://{BACKEND_ADDRESS}:{BACKEND_PORT}"},
    )


@pytest_asyncio.fixture(name="ingress_app", scope="module")
async def ingress_app_fixture(model: Model) -> Application:
    """Deploy the pinned ingress-configurator revision."""
    if (revision := INGRESS_REVISIONS.get(platform.machine())) is None:
        pytest.skip(f"No pinned ingress-configurator revision for {platform.machine()}.")
    return await model.deploy(
        INGRESS_CHARM_NAME,
        INGRESS_APP_NAME,
        channel=INGRESS_CHANNEL,
        revision=revision,
        base="ubuntu@24.04",
        config={
            "backend-addresses": BACKEND_ADDRESS,
            "backend-ports": str(BACKEND_PORT),
        },
    )


@pytest_asyncio.fixture(name="mock_haproxy_app", scope="module")
async def mock_haproxy_app_fixture(model: Model) -> Application:
    """Deploy a mock haproxy-route provider."""
    return await model.deploy(
        HAPROXY_ROUTE_MOCK_CHARM_NAME,
        MOCK_HAPROXY_APP_NAME,
        channel=HAPROXY_ROUTE_MOCK_CHANNEL,
        base="ubuntu@24.04",
    )


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_ingress_configurator_integrates_with_content_cache(
    model: Model,
    cache_app: Application,
    config_app: Application,
    ingress_app: Application,
    mock_haproxy_app: Application,
) -> None:
    """
    arrange: The content-cache, configuration, ingress-configurator, and mock
        haproxy-route applications deployed.
    act: Integrate content-cache with the configuration charm and ingress-configurator,
        and ingress-configurator with the mock haproxy-route provider.
    assert:
        1. Both content-cache and ingress-configurator become active, which requires each
           side to parse the other's cache-config data.
        2. ingress-configurator publishes the cache configuration content-cache can read.
        3. ingress-configurator forwards the cache backend published by content-cache to
           haproxy-route.
    """
    await model.integrate(f"{CONFIG_APP_NAME}:cache-config", f"{CACHE_APP_NAME}:cache-config")
    await model.integrate(f"{CACHE_APP_NAME}:cache-config", f"{INGRESS_APP_NAME}:cache-config")
    await model.integrate(
        f"{INGRESS_APP_NAME}:haproxy-route",
        f"{MOCK_HAPROXY_APP_NAME}:provide-haproxy-route",
    )
    # 1.
    await model.wait_for_idle(
        [cache_app.name, config_app.name, ingress_app.name],
        status="active",
        timeout=30 * 60,
    )
    assert ingress_app.units[0].workload_status_message == "Ready"

    # 2.
    ingress_data = await _relation_app_data(cache_app.units[0], "cache-config", INGRESS_APP_NAME)
    assert _json_field(ingress_data["backends"]) == [f"http://{BACKEND_ADDRESS}:{BACKEND_PORT}"]
    assert str(ingress_data["fail_timeout"]) == "30s"
    assert str(ingress_data["healthcheck_interval"]) == "10000"
    assert str(ingress_data["healthcheck_path"]) == "/"
    assert _json_field(ingress_data["healthcheck_valid_status"]) == [200]
    assert str(ingress_data["healthcheck_ssl_verify"]).lower() == "true"
    assert _json_field(ingress_data["proxy_cache_valid"]) == []
    assert str(ingress_data["cache_inactive"]) == "10m"

    # 3.
    cache_backend_data = await _relation_unit_data(
        ingress_app.units[0], "cache-config", cache_app.units[0].name
    )
    cache_backend = urlparse(str(cache_backend_data["cache-backend"]))
    haproxy_data = await _relation_app_data(
        mock_haproxy_app.units[0], "provide-haproxy-route", INGRESS_APP_NAME
    )
    assert _json_field(haproxy_data["hosts"]) == [cache_backend.hostname]
    assert _json_field(haproxy_data["ports"]) == [cache_backend.port]
    assert str(haproxy_data["protocol"]) == cache_backend.scheme
