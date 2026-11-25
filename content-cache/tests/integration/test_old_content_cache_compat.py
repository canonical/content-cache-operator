# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for a new requirer with an old content-cache provider.

The pinned content-cache revision predates the shared cache-config library and parses
requirer data directly from the relation. This test deploys the new
content-cache-backends-config charm, which uses the shared library, against that revision
to prove the wire format is still compatible.
"""

import platform

import pytest
import pytest_asyncio
import requests
from juju.application import Application
from juju.model import Model

from tests.integration.helpers import (
    BACKENDS_CONFIG_NAME,
    CACHE_INACTIVE_CONFIG_NAME,
    CACHE_MAX_SIZE_CONFIG_NAME,
    FAIL_TIMEOUT_CONFIG_NAME,
    HEALTHCHECK_INTERVAL_CONFIG_NAME,
    HEALTHCHECK_PATH_CONFIG_NAME,
    HEALTHCHECK_SSL_VERIFY_CONFIG_NAME,
    HEALTHCHECK_VALID_STATUS_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    get_app_ip,
)

CACHE_APP_NAME = "cache"
CONFIG_APP_NAME = "config"

OLD_CACHE_CHARM_NAME = "content-cache"
OLD_CACHE_CHANNEL = "1/edge"
# content-cache revision published before the shared cache-config library. The 1/edge
# track only publishes amd64 builds.
OLD_CACHE_REVISIONS = {"x86_64": 547}

CACHE_PORT = 30000


@pytest_asyncio.fixture(name="old_cache_app", scope="module")
async def old_cache_app_fixture(model: Model) -> Application:
    """Deploy the content-cache revision from before the shared library."""
    if (revision := OLD_CACHE_REVISIONS.get(platform.machine())) is None:
        pytest.skip(f"No pinned content-cache revision for {platform.machine()}.")
    return await model.deploy(
        OLD_CACHE_CHARM_NAME,
        CACHE_APP_NAME,
        channel=OLD_CACHE_CHANNEL,
        revision=revision,
        base="ubuntu@24.04",
    )


@pytest_asyncio.fixture(name="config_app", scope="module")
async def config_app_fixture(model: Model, config_charm_file: str) -> Application:
    """Deploy the new configuration charm built from this repository."""
    return await model.deploy(config_charm_file, CONFIG_APP_NAME, base="ubuntu@24.04", num_units=0)


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_new_config_charm_integrates_with_old_content_cache(
    model: Model,
    old_cache_app: Application,
    config_app: Application,
    http_ok_ip: str,
    http_ok_message: str,
) -> None:
    """
    arrange: The old content-cache revision, the new configuration charm, and a test HTTP
        backend.
    act: Integrate the new configuration charm with the old content-cache, then configure
        the backend and healthcheck.
    assert: The old content-cache becomes active and serves content through the cache.
    """
    await model.integrate(f"{CONFIG_APP_NAME}:cache-config", f"{CACHE_APP_NAME}:cache-config")
    await config_app.set_config(
        {
            BACKENDS_CONFIG_NAME: f"http://{http_ok_ip}:80",
            FAIL_TIMEOUT_CONFIG_NAME: "30s",
            CACHE_INACTIVE_CONFIG_NAME: "1h",
            CACHE_MAX_SIZE_CONFIG_NAME: "1g",
            HEALTHCHECK_INTERVAL_CONFIG_NAME: "2123",
            HEALTHCHECK_PATH_CONFIG_NAME: "/",
            HEALTHCHECK_SSL_VERIFY_CONFIG_NAME: "false",
            HEALTHCHECK_VALID_STATUS_CONFIG_NAME: "200",
            PROXY_CACHE_VALID_CONFIG_NAME: '["200 1h"]',
        }
    )
    await model.wait_for_idle(
        [old_cache_app.name, config_app.name],
        status="active",
        timeout=30 * 60,
    )

    cache_ip = await get_app_ip(old_cache_app)
    response = requests.get(f"http://{cache_ip}:{CACHE_PORT}/", timeout=300)
    assert response.status_code == 200
    assert http_ok_message in response.text
