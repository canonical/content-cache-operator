# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for client IP hashing in content-cache logs."""

import hashlib
import json

import pytest
from juju.application import Application
from juju.model import Model
from juju.unit import Unit

from src import nginx_manager
from src.charm import unit_name_to_instance_name
from tests.integration.helpers import (
    BACKENDS_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    CacheTester,
    read_file,
)

CLIENT_IP_HASH_SALT_CONFIG_NAME = "client-ip-hash-salt"


@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_client_ip_hash_salt(
    app: Application,
    config_app: Application,
    cache_tester: CacheTester,
    http_ok_ip: str,
    model: Model,
) -> None:
    """
    arrange: A working application of content-cache charm integrated with config charm, with
        client-ip-hash-salt configured to a secret.
    act: Make a request to the content-cache.
    assert: The access and cache logs contain the salted SHA-256 digest of the client address,
        and not the plaintext client address.
    """
    unit: Unit = app.units[0]

    salt = "some-test-salt"
    secret_uri = await model.add_secret("client-ip-hash-salt", [f"salt={salt}"])
    await model.grant_secret("client-ip-hash-salt", app.name)

    config = dict(CacheTester.BASE_CONFIG)
    config[BACKENDS_CONFIG_NAME] = f"http://{http_ok_ip}:80"
    config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 10s"]'
    await cache_tester.setup_config(config)
    await cache_tester.integrate_config()
    await app.set_config({CLIENT_IP_HASH_SALT_CONFIG_NAME: secret_uri})
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)

    response = await cache_tester.query_cache(path="/")
    assert response.status_code == 200

    client_ip = await unit.get_public_address()
    expected_digest = hashlib.sha256((salt + client_ip).encode("utf-8")).hexdigest()

    instance_name = unit_name_to_instance_name(unit.name)
    access_log = await read_file(unit, nginx_manager._get_access_log_path("30000", instance_name))
    assert access_log
    assert expected_digest in access_log
    assert client_ip not in access_log

    cache_log = await read_file(unit, nginx_manager._get_cache_log_path("30000", instance_name))
    assert cache_log
    cache_entry: dict = json.loads(cache_log.split("\n")[0])
    assert cache_entry["client_address"] == expected_digest
    assert client_ip not in cache_log

    # Clean up so subsequent tests are not affected by client IP hashing being enabled.
    await app.reset_config([CLIENT_IP_HASH_SALT_CONFIG_NAME])
    await model.wait_for_idle([app.name, config_app.name], status="active", timeout=10 * 60)
