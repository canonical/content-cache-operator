# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the charm."""

import json
from unittest.mock import MagicMock

import ops
import pytest
from ops.testing import Harness

import state
from charm import (
    CACHE_CONFIG_INTEGRATION_NAME,
    CERTIFICATE_INTEGRATION_NAME,
    NGINX_NOT_READY_MESSAGE,
    NGINX_PORT_RANGE_START,
    PEER_RELATION_NAME,
    PORT_MAP_FIELD,
    WAIT_FOR_CONFIG_MESSAGE,
    WAIT_FOR_TLS_CERT_MESSAGE,
    ContentCacheCharm,
)
from errors import NginxConfigurationAggregateError, NginxConfigurationError, NginxFileError
from tests.unit.conftest import SAMPLE_INTEGRATION_DATA

SAMPLE_HTTPS_EXTRA = {
    "backend_hostname": "test.example.com",
}


def _peer_port_map(harness: Harness, charm: ContentCacheCharm) -> dict:
    """Read the port_map JSON from the peer app databag."""
    peer_rel = harness.model.get_relation(PEER_RELATION_NAME)
    assert peer_rel is not None
    peer_rel_id = peer_rel.id
    raw = harness.get_relation_data(peer_rel_id, charm.app.name).get(PORT_MAP_FIELD, "")
    return json.loads(raw) if raw else {}


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


def test_unique_port_allocated_per_relation(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A leader charm with two different cache-config integrations.
    act: Add both integrations (each triggers reconcile).
    assert: Each relation gets a unique port in the peer databag, in range.
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

    port_map = _peer_port_map(harness, charm)
    port_1 = port_map[str(rel_id_1)]
    port_2 = port_map[str(rel_id_2)]

    assert port_1 != port_2
    assert port_1 >= NGINX_PORT_RANGE_START
    assert port_2 >= NGINX_PORT_RANGE_START


def test_port_allocation_order_is_deterministic(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A leader charm with no ports allocated yet.
    act: Allocate ports for several relations that all become valid in one reconcile,
        passing their ids in a deliberately unsorted order.
    assert: Ports are assigned by ascending relation id, regardless of input/set
        iteration order, so allocation is reproducible.
    """
    relation_ids = {30, 10, 20}

    port_map = charm._ensure_ports(relation_ids, relation_ids)

    ports_by_id = {rid: port_map[str(rid)] for rid in relation_ids}
    assert ports_by_id[10] < ports_by_id[20] < ports_by_id[30]


def test_port_stable_for_same_relation(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A leader charm with a cache-config integration.
    act: Reconcile twice (add relation, then update-status).
    assert: The same port is retained for that relation.
    """
    rel_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    port_first = _peer_port_map(harness, charm)[str(rel_id)]

    harness.charm.on.update_status.emit()

    port_second = _peer_port_map(harness, charm)[str(rel_id)]
    assert port_first == port_second


def test_follower_uses_shared_port_from_peer_databag(
    follower_harness: Harness, mock_nginx_manager: MagicMock
):
    """
    arrange: A non-leader charm with a peer databag pre-seeded with a port for a relation.
    act: Add a cache-config relation with valid data (triggers reconcile).
    assert: The follower configures nginx with the shared port and does not mutate the map.
    """
    harness = follower_harness
    charm = harness.charm
    peer_rel = harness.model.get_relation(PEER_RELATION_NAME)
    assert peer_rel is not None
    peer_rel_id = peer_rel.id

    rel_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    shared_port = NGINX_PORT_RANGE_START + 5
    harness.update_relation_data(
        peer_rel_id, charm.app.name, {PORT_MAP_FIELD: json.dumps({str(rel_id): shared_port})}
    )
    harness.charm.on.update_status.emit()

    args, _ = mock_nginx_manager.update_and_load_config.call_args
    ported_config = args[0]
    assert ported_config[rel_id][0] == shared_port
    raw = harness.get_relation_data(peer_rel_id, charm.app.name).get(PORT_MAP_FIELD, "")
    assert json.loads(raw) == {str(rel_id): shared_port}


def test_follower_waits_when_port_not_yet_assigned(
    follower_harness: Harness, mock_nginx_manager: MagicMock
):
    """
    arrange: A non-leader charm with an empty peer databag.
    act: Add a cache-config relation with valid data.
    assert: The unit is in WaitingStatus and writes no cache-backend.
    """
    harness = follower_harness
    charm = harness.charm
    rel_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    assert isinstance(charm.unit.status, ops.WaitingStatus)
    assert not harness.get_relation_data(rel_id, charm.unit.name).get("cache-backend")


def test_leader_change_preserves_existing_ports(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A leader charm with a relation and an allocated port.
    act: Add a second relation (later reconcile).
    assert: The first relation keeps its port; the second gets a different one.
    """
    rel_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    original_port = _peer_port_map(harness, charm)[str(rel_id)]

    rel_id_2 = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config2",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    port_map = _peer_port_map(harness, charm)
    assert port_map[str(rel_id)] == original_port
    assert port_map[str(rel_id_2)] != original_port


def test_waiting_when_peer_relation_absent(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A leader charm whose peer relation has been removed.
    act: Add a cache-config relation with valid data.
    assert: The unit waits for port assignment and does not crash.
    """
    peer_rel = harness.model.get_relation(PEER_RELATION_NAME)
    assert peer_rel is not None
    peer_rel_id = peer_rel.id
    harness.remove_relation(peer_rel_id)

    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    assert isinstance(charm.unit.status, ops.WaitingStatus)


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


def test_relation_broken_prunes_peer_port_map(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A leader charm with a cache-config relation that has a port allocated.
    act: Remove the relation.
    assert: The port is removed from the peer databag map and the charm blocks.
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    assert str(relation_id) in _peer_port_map(harness, charm)

    harness.remove_relation(relation_id)

    assert str(relation_id) not in _peer_port_map(harness, charm)
    assert charm.unit.status == ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)


def test_relation_broken_excludes_stale_config_for_departing_relation(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A leader charm with a port already allocated for a relation, then release it
        as `_on_cache_config_relation_broken` would.
    act: Resolve the ported config with a stale ``nginx_config`` entry that still contains
        the departing relation, as can happen when remote data for the breaking relation
        is still visible.
    assert: The departing relation is excluded from both port allocation and the returned
        config (i.e. its port is not re-added to the peer map and it is not republished).
    """
    relation_id = harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    assert str(relation_id) in _peer_port_map(harness, charm)

    charm._release_port(relation_id)
    assert str(relation_id) not in _peer_port_map(harness, charm)

    stale_nginx_config = {relation_id: MagicMock()}
    resolved = charm._resolve_ported_config(stale_nginx_config, broken_relation_id=relation_id)

    assert resolved is not None
    ported_config, awaiting_port = resolved
    assert relation_id not in ported_config
    assert awaiting_port is False
    assert str(relation_id) not in _peer_port_map(harness, charm)


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
    certs_path.mkdir(exist_ok=True)
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


def test_https_backends_without_hostname_sets_blocked(harness: Harness, charm: ContentCacheCharm):
    """
    arrange: A charm with HTTPS backends but no backend_hostname.
    act: Add the config relation.
    assert: The charm enters BlockedStatus.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[state.BACKENDS_FIELD_NAME] = '["https://10.10.1.1:443"]'

    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=data,
    )

    assert isinstance(charm.unit.status, ops.BlockedStatus)
    assert "backend-hostname is required" in charm.unit.status.message


def test_https_backend_with_hostname_stays_active(
    harness: Harness,
    charm: ContentCacheCharm,
):
    """
    arrange: HTTPS backend with backend_hostname set.
    act: Add the config relation.
    assert: The charm stays active (system CA bundle is used automatically).
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[state.BACKENDS_FIELD_NAME] = '["https://10.10.1.1:443"]'
    data.update(SAMPLE_HTTPS_EXTRA)

    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=data,
    )

    assert charm.unit.status == ops.ActiveStatus()


def test_config_changed_client_ip_hash_salt(
    monkeypatch: pytest.MonkeyPatch,
    harness: Harness,
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A working charm with a cache-config relation and a valid client-ip-hash-salt.
    act: Configure client-ip-hash-salt and run config-changed.
    assert: nginx_manager.update_and_load_config is called with the resolved salt.
    """
    monkeypatch.setattr("nginx_manager.NGINX_BIN", "/bin/sh")
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    secret_id = harness.add_user_secret({"salt": "some-salt"})
    harness.grant_secret(secret_id, charm.app)

    harness.update_config({"client-ip-hash-salt": secret_id})

    assert charm.unit.status == ops.ActiveStatus()
    assert (
        mock_nginx_manager.update_and_load_config.call_args.kwargs["client_ip_hash_salt"]
        == "some-salt"
    )


def test_config_changed_client_ip_hash_salt_removed(
    monkeypatch: pytest.MonkeyPatch,
    harness: Harness,
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A working charm with a client-ip-hash-salt previously configured.
    act: Remove the client-ip-hash-salt config.
    assert: nginx_manager.update_and_load_config is called with client_ip_hash_salt=None.
    """
    monkeypatch.setattr("nginx_manager.NGINX_BIN", "/bin/sh")
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    secret_id = harness.add_user_secret({"salt": "some-salt"})
    harness.grant_secret(secret_id, charm.app)
    harness.update_config({"client-ip-hash-salt": secret_id})

    harness.update_config(unset=["client-ip-hash-salt"])

    assert charm.unit.status == ops.ActiveStatus()
    assert (
        mock_nginx_manager.update_and_load_config.call_args.kwargs["client_ip_hash_salt"] is None
    )


def test_early_return_still_removes_stale_salt_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
    harness: Harness,
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A charm with no cache-config integration (so reconciliation exits before reaching
        update_and_load_config) and client-ip-hash-salt not configured.
    act: Trigger a reconcile.
    assert: nginx_manager.remove_client_ip_hash_salt is called even though
        update_and_load_config is never reached.
    """
    monkeypatch.setattr("nginx_manager.NGINX_BIN", "/bin/sh")
    mock_nginx_manager.remove_client_ip_hash_salt.reset_mock()

    charm._load_nginx_config()

    mock_nginx_manager.remove_client_ip_hash_salt.assert_called_once()
    mock_nginx_manager.update_and_load_config.assert_not_called()


def test_config_changed_client_ip_hash_salt_rejects_inaccessible_secret(
    monkeypatch: pytest.MonkeyPatch,
    harness: Harness,
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A working charm with a cache-config relation.
    act: Configure client-ip-hash-salt to point at a secret ID that does not exist.
    assert: The unit is blocked and nginx config is not reloaded.
    """
    monkeypatch.setattr("nginx_manager.NGINX_BIN", "/bin/sh")
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    # Not granted to this charm, so it exists but is inaccessible.
    secret_id = harness.add_user_secret({"salt": "some-salt"})
    mock_nginx_manager.update_and_load_config.reset_mock()

    harness.update_config({"client-ip-hash-salt": secret_id})

    assert isinstance(charm.unit.status, ops.BlockedStatus)
    assert "does not exist or cannot be accessed" in charm.unit.status.message
    mock_nginx_manager.update_and_load_config.assert_not_called()


def test_config_changed_client_ip_hash_salt_rejects_blank_value(
    monkeypatch: pytest.MonkeyPatch,
    harness: Harness,
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A working charm with a cache-config relation and a secret missing a salt value.
    act: Configure client-ip-hash-salt to point at that secret.
    assert: The unit is blocked and nginx config is not reloaded.
    """
    monkeypatch.setattr("nginx_manager.NGINX_BIN", "/bin/sh")
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    secret_id = harness.add_user_secret({"salt": "   "})
    harness.grant_secret(secret_id, charm.app)
    mock_nginx_manager.update_and_load_config.reset_mock()

    harness.update_config({"client-ip-hash-salt": secret_id})

    assert isinstance(charm.unit.status, ops.BlockedStatus)
    assert "non-empty 'salt' value" in charm.unit.status.message
    mock_nginx_manager.update_and_load_config.assert_not_called()


def test_secret_changed_triggers_reload(
    monkeypatch: pytest.MonkeyPatch,
    harness: Harness,
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A working charm with client-ip-hash-salt configured.
    act: Update the secret content and emit secret-changed.
    assert: nginx_manager.update_and_load_config is called with the new salt value.
    """
    monkeypatch.setattr("nginx_manager.NGINX_BIN", "/bin/sh")
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    secret_id = harness.add_user_secret({"salt": "some-salt"})
    harness.grant_secret(secret_id, charm.app)
    harness.update_config({"client-ip-hash-salt": secret_id})

    harness.set_secret_content(secret_id, {"salt": "new-salt"})

    assert charm.unit.status == ops.ActiveStatus()
    assert (
        mock_nginx_manager.update_and_load_config.call_args.kwargs["client_ip_hash_salt"]
        == "new-salt"
    )


def test_unrelated_secret_changed_does_not_trigger_reload(
    monkeypatch: pytest.MonkeyPatch,
    harness: Harness,
    charm: ContentCacheCharm,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A working charm with client-ip-hash-salt configured.
    act: Update the content of a different, unrelated secret.
    assert: nginx_manager.update_and_load_config is not called again.
    """
    monkeypatch.setattr("nginx_manager.NGINX_BIN", "/bin/sh")
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    secret_id = harness.add_user_secret({"salt": "some-salt"})
    harness.grant_secret(secret_id, charm.app)
    harness.update_config({"client-ip-hash-salt": secret_id})

    unrelated_secret_id = harness.add_user_secret({"unrelated": "value"})
    harness.grant_secret(unrelated_secret_id, charm.app)
    mock_nginx_manager.update_and_load_config.reset_mock()

    harness.set_secret_content(unrelated_secret_id, {"unrelated": "new-value"})

    mock_nginx_manager.update_and_load_config.assert_not_called()
