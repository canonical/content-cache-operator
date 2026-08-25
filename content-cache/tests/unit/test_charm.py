# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the charm using ops-scenario."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import ops
import pytest
import scenario
from scenario.errors import UncaughtCharmError

from charm import (
    CACHE_CONFIG_INTEGRATION_NAME,
    NGINX_NOT_READY_MESSAGE,
    WAIT_FOR_CONFIG_MESSAGE,
    ContentCacheCharm,
)
from errors import (
    CACertificateFileError,
    NginxConfigurationAggregateError,
    NginxConfigurationError,
    NginxFileError,
    TLSCertificateFileError,
)
from state import BACKENDS_FIELD_NAME
from tests.unit.conftest import SAMPLE_INTEGRATION_DATA

CERT_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"
CERTIFICATE_INTEGRATION_NAME = "certificates"
SAMPLE_CA_CERT = "-----BEGIN CERTIFICATE-----\nMIIFake\n-----END CERTIFICATE-----"
SAMPLE_FINGERPRINT = "96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6"
SAMPLE_HTTPS_EXTRA = {
    "backend_hostname": "test.example.com",
    "backend_ca_fingerprint": SAMPLE_FINGERPRINT,
}


@pytest.fixture(name="ctx")
def context_fixture(mock_nginx_manager: MagicMock) -> scenario.Context:
    """A scenario Context for ContentCacheCharm with nginx mocked."""
    return scenario.Context(ContentCacheCharm)


@pytest.fixture(name="cache_config_relation")
def cache_config_relation_fixture() -> scenario.Relation:
    """A cache-config relation with sample valid data."""
    return scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config",
        remote_app_data=SAMPLE_INTEGRATION_DATA,
    )


def test_start_no_relation(ctx: scenario.Context, mock_nginx_manager: MagicMock):
    """
    arrange: A working charm.
    act: None.
    assert: Waiting for integration to join. Method to initialize nginx called.
    """
    out = ctx.run(ctx.on.start(), scenario.State())
    assert out.unit_status == scenario.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)
    mock_nginx_manager.initialize.assert_called_once()


def test_stop_nginx(ctx: scenario.Context, mock_nginx_manager: MagicMock):
    """
    arrange: A working charm. Reset the mocks.
    act: Emit stop event.
    assert: Method to stop nginx called.
    """
    mock_nginx_manager.stop.reset_mock()
    ctx.run(ctx.on.stop(), scenario.State())
    mock_nginx_manager.stop.assert_called_once()


def test_update_status_no_relation(ctx: scenario.Context):
    """
    arrange: A working charm.
    act: Emit update status.
    assert: Charm waiting for integration.
    """
    out = ctx.run(ctx.on.update_status(), scenario.State())
    assert out.unit_status == scenario.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)


@pytest.mark.parametrize(
    ["health", "status"],
    [
        pytest.param(False, scenario.MaintenanceStatus(NGINX_NOT_READY_MESSAGE)),
        pytest.param(True, scenario.ActiveStatus()),
    ],
)
def test_update_status_with_integration(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
    mock_nginx_manager: MagicMock,
    health: bool,
    status: ops.StatusBase,
):
    """
    arrange: Charm is integrated, and nginx health varies.
    act: Emit update status.
    assert: Charm status reflects nginx health.
    """
    mock_nginx_manager.health_check.return_value = health
    out = ctx.run(
        ctx.on.update_status(),
        scenario.State(relations={cache_config_relation}),
    )
    assert out.unit_status == status


def test_add_integration(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
):
    """
    arrange: A working charm.
    act: Fire relation-changed with valid integration data.
    assert: Charm in active status.
    """
    out = ctx.run(
        ctx.on.relation_changed(cache_config_relation),
        scenario.State(relations={cache_config_relation}),
    )
    assert out.unit_status == scenario.ActiveStatus()


def test_remove_integration(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
):
    """
    arrange: A working charm with a config integration.
    act: Fire relation-broken.
    assert: Charm in blocked status.
    """
    out = ctx.run(
        ctx.on.relation_broken(cache_config_relation),
        scenario.State(relations={cache_config_relation}),
    )
    assert out.unit_status == scenario.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)


def test_invalid_integration_data(ctx: scenario.Context):
    """
    arrange: A working charm.
    act: Fire relation-changed with invalid backends.
    assert: Charm in block state with Config error message.
    """
    bad_data = dict(SAMPLE_INTEGRATION_DATA)
    bad_data[BACKENDS_FIELD_NAME] = '["not-a-url"]'
    rel = scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config",
        remote_app_data=bad_data,
    )
    out = ctx.run(ctx.on.relation_changed(rel), scenario.State(relations={rel}))
    assert isinstance(out.unit_status, scenario.BlockedStatus)
    assert "Config error" in out.unit_status.message


def test_nginx_file_error(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
    monkeypatch,
):
    """
    arrange: update_and_load_config raises NginxFileError.
    act: Fire relation-changed.
    assert: The error is re-raised (wrapped in UncaughtCharmError by scenario).
    """
    monkeypatch.setattr(
        "charm.nginx_manager.update_and_load_config",
        MagicMock(side_effect=NginxFileError("Mock error")),
    )
    with pytest.raises(UncaughtCharmError) as exc_info:
        ctx.run(
            ctx.on.relation_changed(cache_config_relation),
            scenario.State(relations={cache_config_relation}),
        )
    assert isinstance(exc_info.value.__cause__, NginxFileError)


def test_nginx_config_error(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
    monkeypatch,
):
    """
    arrange: update_and_load_config raises NginxConfigurationAggregateError.
    act: Fire relation-changed.
    assert: The charm status reflects the error.
    """
    monkeypatch.setattr(
        "charm.nginx_manager.update_and_load_config",
        MagicMock(
            side_effect=NginxConfigurationAggregateError(
                ("mock host",), (NginxConfigurationError("Mock errors"),)
            )
        ),
    )
    out = ctx.run(
        ctx.on.relation_changed(cache_config_relation),
        scenario.State(relations={cache_config_relation}),
    )
    assert out.unit_status == scenario.ActiveStatus("Error for host: ('mock host',)")


def test_unique_port_allocated_per_relation(ctx: scenario.Context, monkeypatch):
    """
    arrange: Charm with two different cache-config integrations.
    act: Fire relation-changed for each relation in a shared state.
    assert: Each relation gets a unique port in cache-backends URL.
    """
    # Override the mock to return a port-aware URL so we can distinguish allocations.
    monkeypatch.setattr(
        "charm.get_cache_backend_url",
        lambda charm, relation, port, has_cache_cert=False: f"http://10.0.0.1:{port}",
    )
    rel1 = scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config1",
        remote_app_data=SAMPLE_INTEGRATION_DATA,
    )
    rel2 = scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config2",
        remote_app_data=SAMPLE_INTEGRATION_DATA,
    )
    state_with_two = scenario.State(relations={rel1, rel2})

    out1 = ctx.run(ctx.on.relation_changed(rel1), state_with_two)
    # Pass stored state from out1 so the port_map for rel1 is visible to rel2 allocation.
    state_after_rel1 = scenario.State(
        relations={rel1, rel2},
        stored_states=out1.stored_states,
    )
    out2 = ctx.run(ctx.on.relation_changed(rel2), state_after_rel1)

    def extract_port(out: scenario.State, relation_id: int) -> int:
        """Extract the allocated port number from the cache-backend URL in relation data.

        Args:
            out: The output state from scenario run.
            relation_id: The relation ID to look up.

        Returns:
            The port number, or -1 if no cache-backend is set.
        """
        rel = out.get_relation(relation_id)
        url = rel.local_unit_data.get("cache-backend", "")
        return int(url.rsplit(":", 1)[-1]) if url else -1

    port1 = extract_port(out1, rel1.id)
    port2 = extract_port(out2, rel2.id)

    assert port1 >= 8080
    assert port2 >= 8080
    assert port1 != port2


def test_port_stable_for_same_relation(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
):
    """
    arrange: Charm with a cache-config integration.
    act: Fire relation-changed twice for the same relation.
    assert: Same port (URL) is in cache-backends both times.
    """
    state_in = scenario.State(relations={cache_config_relation})
    out1 = ctx.run(ctx.on.relation_changed(cache_config_relation), state_in)
    out2 = ctx.run(ctx.on.relation_changed(cache_config_relation), state_in)

    rel1 = out1.get_relation(cache_config_relation.id)
    rel2 = out2.get_relation(cache_config_relation.id)

    assert rel1.local_unit_data.get("cache-backend") == rel2.local_unit_data.get("cache-backend")


def test_load_nginx_config_writes_cache_backend(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
):
    """
    arrange: A working charm with get_cache_backend_url mocked in the fixture.
    act: Fire relation-changed with valid data.
    assert: cache-backend is written to unit relation data with the expected URL.
    """
    out = ctx.run(
        ctx.on.relation_changed(cache_config_relation),
        scenario.State(relations={cache_config_relation}),
    )
    assert out.unit_status == scenario.ActiveStatus()
    out_rel = out.get_relation(cache_config_relation.id)
    cache_backend = out_rel.local_unit_data.get("cache-backend", "")
    assert cache_backend == "http://10.0.0.1:8080"


def test_relation_broken_clears_cache_backends(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
):
    """
    arrange: A charm with a cache-config relation that has cache-backends written.
    act: Fire relation-broken.
    assert: Charm returns to blocked status.
    """
    out = ctx.run(
        ctx.on.relation_broken(cache_config_relation),
        scenario.State(relations={cache_config_relation}),
    )
    assert out.unit_status == scenario.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)


def test_cache_backends_cleared_when_config_fails(ctx: scenario.Context):
    """
    arrange: A charm with an invalid cache-config relation.
    act: Fire relation-changed with invalid backends.
    assert: Charm enters blocked status.
    """
    bad_data = dict(SAMPLE_INTEGRATION_DATA)
    bad_data[BACKENDS_FIELD_NAME] = ""
    rel = scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config",
        remote_app_data=bad_data,
    )
    out = ctx.run(ctx.on.relation_changed(rel), scenario.State(relations={rel}))
    assert isinstance(out.unit_status, scenario.BlockedStatus)


def test_certificate_available_writes_cert_and_reloads(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A charm with an active cache-config relation and CA cert.
    act: Fire relation-changed on receive-ca-cert with cert data.
    assert: Charm remains Active (CA bundle is written and nginx reloads).
    """
    cert_rel = scenario.Relation(
        endpoint=CERT_TRANSFER_INTEGRATION_NAME,
        remote_app_name="cert-provider",
        remote_app_data={"certificates": json.dumps([SAMPLE_CA_CERT])},
    )
    out = ctx.run(
        ctx.on.relation_changed(cert_rel),
        scenario.State(relations={cache_config_relation, cert_rel}),
    )
    assert out.unit_status == scenario.ActiveStatus()


def test_certificate_removed_deletes_cert_and_stays_active(
    ctx: scenario.Context,
    mock_nginx_manager: MagicMock,
    monkeypatch,
):
    """
    arrange: A charm with HTTPS backends and a CA cert via certificate-transfer.
    act: Fire relation-broken on certificate-transfer.
    assert: Charm stays Active — no CA bundle gate since proxy_ssl_verify is off.
    """
    import ca_certs as _ca_certs

    monkeypatch.setattr(_ca_certs, "find_cert_by_fingerprint", lambda fp, certs: SAMPLE_CA_CERT)
    monkeypatch.setattr(_ca_certs, "load_system_ca_certs", lambda: [])
    monkeypatch.setattr(
        _ca_certs, "write_backend_ca_cert", lambda ident, pem: Path(f"/tmp/backend-{ident}-ca.pem")
    )
    https_data = dict(SAMPLE_INTEGRATION_DATA)
    https_data[BACKENDS_FIELD_NAME] = '["https://10.10.1.1:443"]'
    https_data.update(SAMPLE_HTTPS_EXTRA)
    config_rel = scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config",
        remote_app_data=https_data,
    )
    cert_rel = scenario.Relation(
        endpoint=CERT_TRANSFER_INTEGRATION_NAME,
        remote_app_name="cert-provider",
        remote_app_data={"certificates": json.dumps([SAMPLE_CA_CERT])},
    )
    out = ctx.run(
        ctx.on.relation_broken(cert_rel),
        scenario.State(relations={config_rel, cert_rel}),
    )
    assert out.unit_status == scenario.ActiveStatus()


def test_https_backends_without_ca_fields_sets_blocked(ctx: scenario.Context):
    """
    arrange: A charm with HTTPS backends but no backend_hostname or backend_ca_fingerprint.
    act: Fire relation-changed.
    assert: Charm enters BlockedStatus — both fields are required for HTTPS backends.
    """
    https_data = dict(SAMPLE_INTEGRATION_DATA)
    https_data[BACKENDS_FIELD_NAME] = '["https://10.10.1.1:443"]'
    rel = scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config",
        remote_app_data=https_data,
    )
    out = ctx.run(ctx.on.relation_changed(rel), scenario.State(relations={rel}))
    assert isinstance(out.unit_status, scenario.BlockedStatus)


def test_http_backends_without_ca_bundle_stays_active(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
):
    """
    arrange: A charm with no certificate_transfer relation.
    act: Fire relation-changed with HTTP backends.
    assert: Charm remains Active (no CA cert required for HTTP).
    """
    out = ctx.run(
        ctx.on.relation_changed(cache_config_relation),
        scenario.State(relations={cache_config_relation}),
    )
    assert out.unit_status == scenario.ActiveStatus()


def test_certificate_available_file_error_sets_blocked(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
    mock_nginx_manager: MagicMock,
    monkeypatch,
):
    """
    arrange: A charm with an active cache-config relation.
    act: Fire certificate_set_updated event when writing raises CACertificateFileError.
    assert: Charm enters BlockedStatus and nginx is not reloaded.
    """
    mock_nginx_manager.update_and_load_config.reset_mock()
    monkeypatch.setattr(
        "charm.ca_certs.write_ca_bundle",
        MagicMock(side_effect=CACertificateFileError("disk error")),
    )
    cert_rel = scenario.Relation(
        endpoint=CERT_TRANSFER_INTEGRATION_NAME,
        remote_app_name="cert-provider",
        remote_app_data={"certificates": json.dumps(["cert-A"])},
    )
    out = ctx.run(
        ctx.on.relation_changed(cert_rel),
        scenario.State(relations={cache_config_relation, cert_rel}),
    )
    assert isinstance(out.unit_status, scenario.BlockedStatus)
    assert "CA certificate" in out.unit_status.message
    mock_nginx_manager.update_and_load_config.assert_not_called()


def test_certificate_removed_file_error_sets_blocked(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
    mock_nginx_manager: MagicMock,
    monkeypatch,
):
    """
    arrange: A charm with a CA cert added via certificate-transfer.
    act: Remove the relation when deleting the cert raises CACertificateFileError.
    assert: Charm enters BlockedStatus and nginx is not reloaded.
    """
    cert_rel = scenario.Relation(
        endpoint=CERT_TRANSFER_INTEGRATION_NAME,
        remote_app_name="cert-provider",
        remote_app_data={"certificates": json.dumps(["cert-A"])},
    )
    mock_nginx_manager.update_and_load_config.reset_mock()
    monkeypatch.setattr(
        "charm.ca_certs.write_ca_bundle",
        MagicMock(side_effect=CACertificateFileError("disk error")),
    )
    out = ctx.run(
        ctx.on.relation_broken(cert_rel),
        scenario.State(relations={cache_config_relation, cert_rel}),
    )
    assert isinstance(out.unit_status, scenario.BlockedStatus)
    assert "CA certificate" in out.unit_status.message
    mock_nginx_manager.update_and_load_config.assert_not_called()


def test_tls_certificates_relation_added_sets_waiting(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A charm with an active cache-config relation.
    act: Fire relation-created on certificates (cert not yet available).
    assert: Charm enters WaitingStatus waiting for TLS certificate.
    """
    cert_rel = scenario.Relation(
        endpoint=CERTIFICATE_INTEGRATION_NAME,
        remote_app_name="cache-lego",
    )
    out = ctx.run(
        ctx.on.relation_created(cert_rel),
        scenario.State(relations={cache_config_relation, cert_rel}),
    )
    assert isinstance(out.unit_status, scenario.WaitingStatus)
    assert "TLS certificate" in out.unit_status.message


# The following two tests call _on_tls_certificate_available directly because the
# TLS certificates library's 'certificate_available' custom event cannot be easily
# triggered via scenario's standard event API.
def test_tls_certificate_available_writes_cert_and_reloads(
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A charm with cache-config and certificates relations.
    act: Call _on_tls_certificate_available directly (bypasses x509 snapshot/restore).
    assert: write_certificates is called and nginx is reloaded.
    """
    from ops.testing import Harness

    harness = Harness(ContentCacheCharm)
    harness.add_network("10.0.0.1", endpoint="certificates")
    harness.begin_with_initial_hooks()

    try:
        harness.add_relation(
            CACHE_CONFIG_INTEGRATION_NAME,
            remote_app="config",
            app_data=SAMPLE_INTEGRATION_DATA,
        )
        harness.add_relation(CERTIFICATE_INTEGRATION_NAME, remote_app="cache-lego")
        mock_nginx_manager.update_and_load_config.reset_mock()

        with (
            patch(
                "charm.certificates.write_certificate",
                return_value={"10.0.0.1": Path("/etc/nginx/certs/10.0.0.1.pem")},
            ) as mock_write,
            patch.object(
                harness.charm, "_get_cache_cert_path", return_value=Path("/fake/cert.pem")
            ),
        ):
            harness.charm._on_tls_certificate_available(MagicMock())

        mock_write.assert_called_once()
        mock_nginx_manager.update_and_load_config.assert_called()
    finally:
        harness.cleanup()


def test_tls_certificate_available_write_error_sets_blocked(
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A charm with certificates relation, cert write raises TLSCertificateFileError.
    act: Call _on_tls_certificate_available with write_certificates patched to raise.
    assert: Charm enters BlockedStatus; nginx is not reloaded.
    """
    from ops.testing import Harness

    harness = Harness(ContentCacheCharm)
    harness.add_network("10.0.0.1", endpoint="certificates")
    harness.begin_with_initial_hooks()

    try:
        harness.add_relation(
            CACHE_CONFIG_INTEGRATION_NAME,
            remote_app="config",
            app_data=SAMPLE_INTEGRATION_DATA,
        )
        harness.add_relation(CERTIFICATE_INTEGRATION_NAME, remote_app="cache-lego")
        mock_nginx_manager.update_and_load_config.reset_mock()

        with patch(
            "charm.certificates.write_certificate",
            side_effect=TLSCertificateFileError("disk error"),
        ):
            harness.charm._on_tls_certificate_available(MagicMock())

        assert isinstance(harness.charm.unit.status, ops.BlockedStatus)
        assert "TLS certificate" in harness.charm.unit.status.message
        mock_nginx_manager.update_and_load_config.assert_not_called()
    finally:
        harness.cleanup()


def test_tls_certificates_relation_broken_reverts_to_http(
    ctx: scenario.Context,
    cache_config_relation: scenario.Relation,
    mock_nginx_manager: MagicMock,
):
    """
    arrange: A charm with a TLS cert active (cert written, CN stored).
    act: Remove the certificates relation.
    assert: Nginx reloads serving HTTP (no cache_cert_path) and charm is Active.
    """
    cert_rel = scenario.Relation(
        endpoint=CERTIFICATE_INTEGRATION_NAME,
        remote_app_name="cache-lego",
    )
    stored = scenario.StoredState(
        name="_stored",
        owner_path="ContentCacheCharm",
        content={"cache_cert_cn": "10.0.0.1", "port_map": {}},
    )
    mock_nginx_manager.update_and_load_config.reset_mock()
    out = ctx.run(
        ctx.on.relation_broken(cert_rel),
        scenario.State(
            relations={cache_config_relation, cert_rel},
            stored_states={stored},
        ),
    )
    mock_nginx_manager.update_and_load_config.assert_called()
    call_kwargs = mock_nginx_manager.update_and_load_config.call_args.kwargs
    assert call_kwargs.get("cache_cert_path") is None
    assert out.unit_status == scenario.ActiveStatus()


def test_https_backend_fingerprint_miss_sets_blocked(
    ctx: scenario.Context,
    mock_nginx_manager: MagicMock,
    monkeypatch,
):
    """
    arrange: HTTPS backend with fingerprint; no matching cert available.
    act: Fire config-changed.
    assert: Charm enters BlockedStatus with fingerprint in message.
    """
    import ca_certs as _ca_certs

    monkeypatch.setattr(_ca_certs, "find_cert_by_fingerprint", lambda fp, certs: None)
    monkeypatch.setattr(_ca_certs, "load_system_ca_certs", lambda: [])

    https_data = dict(SAMPLE_INTEGRATION_DATA)
    https_data[BACKENDS_FIELD_NAME] = '["https://10.10.1.1:443"]'
    https_data.update(SAMPLE_HTTPS_EXTRA)
    rel = scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config",
        remote_app_data=https_data,
    )
    out = ctx.run(ctx.on.relation_changed(rel), scenario.State(relations={rel}))
    assert isinstance(out.unit_status, scenario.BlockedStatus)
    assert SAMPLE_FINGERPRINT in out.unit_status.message


def test_https_backend_fingerprint_hit_stays_active(
    ctx: scenario.Context,
    mock_nginx_manager: MagicMock,
    monkeypatch,
):
    """
    arrange: HTTPS backend with fingerprint; a matching cert is returned.
    act: Fire config-changed.
    assert: Charm enters ActiveStatus.
    """
    import ca_certs as _ca_certs

    fake_cert = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
    monkeypatch.setattr(_ca_certs, "find_cert_by_fingerprint", lambda fp, certs: fake_cert)
    monkeypatch.setattr(_ca_certs, "load_system_ca_certs", lambda: [])
    monkeypatch.setattr(
        _ca_certs,
        "write_backend_ca_cert",
        lambda ident, pem: Path(f"/tmp/backend-{ident}-ca.pem"),
    )

    https_data = dict(SAMPLE_INTEGRATION_DATA)
    https_data[BACKENDS_FIELD_NAME] = '["https://10.10.1.1:443"]'
    https_data.update(SAMPLE_HTTPS_EXTRA)
    rel = scenario.Relation(
        endpoint=CACHE_CONFIG_INTEGRATION_NAME,
        remote_app_name="config",
        remote_app_data=https_data,
    )
    out = ctx.run(ctx.on.relation_changed(rel), scenario.State(relations={rel}))
    assert out.unit_status == scenario.ActiveStatus()
