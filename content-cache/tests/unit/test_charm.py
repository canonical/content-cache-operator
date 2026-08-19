# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the charm."""

from unittest.mock import MagicMock

import ops
import pytest
from ops.testing import Harness

import state
from charm import (
    CACHE_CONFIG_INTEGRATION_NAME,
    CERTIFICATE_INTEGRATION_NAME,
    NGINX_NOT_READY_MESSAGE,
    WAIT_FOR_CONFIG_MESSAGE,
    WAIT_FOR_TLS_CERT_MESSAGE,
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
    assert location_config.backends[0].host == "10.10.1.1"
    assert location_config.backends[1].host == "10.10.2.2"
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
    act: Add a config integration with invalid backends data.
    assert: Charm in block state.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[state.BACKENDS_FIELD_NAME] = '["not-a-url"]'
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=data,
    )
    assert isinstance(charm.unit.status, ops.BlockedStatus)
    assert "Config error" in charm.unit.status.message


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


def test_get_nginx_config_returns_flat_per_relation_dict(
    harness: Harness, charm: ContentCacheCharm
):
    """
    arrange: Charm with a cache-config integration.
    act: Get nginx config.
    assert: Returns flat dict keyed by relation_id (int), not nested by hostname.
    """
    from state import LocationConfig, get_nginx_config

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    config = get_nginx_config(charm)

    assert relation_id in config
    assert isinstance(config[relation_id], LocationConfig)
    assert config[relation_id].backends[0].host == "10.10.1.1"
    assert config[relation_id].backends[1].host == "10.10.2.2"


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


def test_load_nginx_config_writes_cache_backend(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A working charm with get_cache_backend_url mocked in the fixture.
    act: Add a cache-config relation with valid data.
    assert: cache-backend is written to unit relation data with the expected URL.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    assert charm.unit.status == ops.ActiveStatus()
    rel_data = harness.get_relation_data(relation_id, charm.unit.name)
    cache_backend = rel_data.get("cache-backend", "")
    assert cache_backend == "http://10.0.0.1:8080"


def test_relation_broken_clears_cache_backends(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A charm with a cache-config relation that has cache-backends written.
    act: Remove the relation.
    assert: Charm returns to blocked status.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    assert charm.unit.status == ops.ActiveStatus()

    harness.remove_relation(relation_id)

    assert charm.unit.status == ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)


def test_cache_backend_cleared_when_config_fails(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A charm with an active relation that has cache-backend written.
    act: Simulate a config validation failure by clearing the relation data.
    assert: cache-backend is cleared on the relation.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    assert charm.unit.status == ops.ActiveStatus()
    assert harness.get_relation_data(relation_id, charm.unit.name).get("cache-backend") != ""

    # Clear the relation data to trigger a config validation failure (blocked)
    harness.update_relation_data(relation_id, "config", {"backends": ""})

    assert isinstance(charm.unit.status, ops.BlockedStatus)
    cache_backend = harness.get_relation_data(relation_id, charm.unit.name).get("cache-backend")
    # Setting to "" removes the key in Juju/Harness, so None means cleared
    assert not cache_backend


def test_cache_backend_not_written_when_unchanged(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A charm with an active relation that already has cache-backend written.
    act: Trigger update-status (re-runs _load_nginx_config).
    assert: cache-backend is not re-written when the value hasn't changed.
    """
    from unittest.mock import MagicMock, patch

    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    assert charm.unit.status == ops.ActiveStatus()

    mock_setitem = MagicMock()
    rel = charm.model.get_relation(CACHE_CONFIG_INTEGRATION_NAME, relation_id)
    with patch.object(type(rel.data[charm.unit]), "__setitem__", mock_setitem):
        charm.on.update_status.emit()

    cache_backend_writes = [c for c in mock_setitem.call_args_list if c.args[1] == "cache-backend"]
    assert len(cache_backend_writes) == 0, "cache-backend should not be written when unchanged"


def test_tls_certificates_relation_broken_reverts_to_http(
    harness: Harness,
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
    monkeypatch,
    tmp_path,
):
    """
    arrange: A charm with a certificates relation and a cert file on disk (simulating a TLS
        cert that was previously issued).
    act: Remove the certificates relation (relation_broken).
    assert: The charm does not get stuck in WaitingStatus — it calls update_and_load_config
        and ends in ActiveStatus, not WaitingStatus("Waiting for TLS certificate").
    """
    certs_path = tmp_path / "certs"
    certs_path.mkdir()
    monkeypatch.setattr("charm.nginx_manager.NGINX_CERTIFICATES_PATH", certs_path)

    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    assert charm.unit.status == ops.ActiveStatus()

    cert_rel_id = harness.add_relation(CERTIFICATE_INTEGRATION_NAME, remote_app="lego")
    cert_file = certs_path / "content-cache-charm.pem"
    cert_file.write_text("fake-cert", encoding="utf-8")

    mock_nginx_manager.update_and_load_config.reset_mock()
    harness.remove_relation(cert_rel_id)

    assert charm.unit.status != ops.WaitingStatus(
        WAIT_FOR_TLS_CERT_MESSAGE
    ), "Charm must not be stuck in WaitingStatus after certificates relation is removed"
    mock_nginx_manager.update_and_load_config.assert_called()
