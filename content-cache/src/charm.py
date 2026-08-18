#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The content-cache charm."""

import json
import logging
from pathlib import Path

import ops
from charmlibs.interfaces.certificate_transfer import (
    CertificateTransferRequires,
)
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    CertificateRequestAttributes,
    Mode,
    TLSCertificatesRequiresV4,
)

import ca_certs
import certificates
import nginx_manager
from certificates import FRONTEND_CERT_COMMON_NAME
from errors import (
    CACertificateFileError,
    IntegrationDataError,
    NginxConfigurationAggregateError,
    NginxFileError,
    NginxSetupError,
    NginxStopError,
    TLSCertificateFileError,
    TLSCertificateNotAvailableError,
)
from state import (
    CACHE_CONFIG_INTEGRATION_NAME,
    NginxConfig,
    get_cache_backend_url,
    get_nginx_config,
)

logger = logging.getLogger(__name__)

WAIT_FOR_CONFIG_MESSAGE = "Waiting for integration with config charm"
NGINX_NOT_READY_MESSAGE = "Nginx is not ready"
RECEIVED_NGINX_CONFIG_MESSAGE = "Received nginx configuration"
CERTIFICATE_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"
WAIT_FOR_CA_CERT_MESSAGE = "Waiting for CA certificate via certificate-transfer"
CERTIFICATE_INTEGRATION_NAME = "certificates"
WAIT_FOR_TLS_CERT_MESSAGE = "Waiting for TLS certificate"

NGINX_PORT_RANGE_START = 30000
NGINX_PORT_RANGE_SIZE = 200


class ContentCacheCharm(ops.CharmBase):
    """Charm the application."""

    _stored = ops.StoredState()

    def __init__(self, framework: ops.Framework) -> None:
        """Initialize the object.

        Args:
            framework: The ops framework.
        """
        super().__init__(framework)

        self._stored.set_default(port_map={})
        self._stored.set_default(next_port_offset=0)

        self._cos_agent = COSAgentProvider(charm=self)
        self._certificate_transfer = CertificateTransferRequires(
            self, CERTIFICATE_TRANSFER_INTEGRATION_NAME
        )
        self._tls_certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=CERTIFICATE_INTEGRATION_NAME,
            certificate_requests=[
                CertificateRequestAttributes(common_name=FRONTEND_CERT_COMMON_NAME)
            ],
            mode=Mode.UNIT,
        )

        framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.stop, self._on_stop)
        framework.observe(self.on.update_status, self._on_update_status)
        framework.observe(
            self.on[CACHE_CONFIG_INTEGRATION_NAME].relation_changed,
            self._on_cache_config_relation_changed,
        )
        framework.observe(
            self.on[CACHE_CONFIG_INTEGRATION_NAME].relation_broken,
            self._on_cache_config_relation_broken,
        )
        framework.observe(
            self._certificate_transfer.on.certificate_set_updated,
            self._on_certificate_transfer_changed,
        )
        framework.observe(
            self._certificate_transfer.on.certificates_removed,
            self._on_certificate_transfer_changed,
        )
        # Also observe raw relation events to handle V0-format providers
        # (e.g. self-signed-certificates) that the library doesn't parse and
        # therefore never fires certificate_set_updated / certificates_removed for.
        framework.observe(
            self.on[CERTIFICATE_TRANSFER_INTEGRATION_NAME].relation_changed,
            self._on_certificate_transfer_changed,
        )
        framework.observe(
            self.on[CERTIFICATE_TRANSFER_INTEGRATION_NAME].relation_broken,
            self._on_certificate_transfer_changed,
        )
        framework.observe(
            self.on[CERTIFICATE_INTEGRATION_NAME].relation_created,
            self._on_tls_certificates_relation_created,
        )
        framework.observe(
            self._tls_certificates.on.certificate_available,
            self._on_tls_certificate_available,
        )
        framework.observe(
            self.on[CERTIFICATE_INTEGRATION_NAME].relation_broken,
            self._on_tls_certificates_relation_broken,
        )

    def _on_start(self, _: ops.StartEvent) -> None:
        """Handle start event."""
        self._nginx_initialize()
        self._load_nginx_config()

    def _on_stop(self, _: ops.StopEvent) -> None:
        """Handle the stop event."""
        self._nginx_stop()

    def _on_update_status(self, _: ops.UpdateStatusEvent) -> None:
        """Handle update status event."""
        self._load_nginx_config()

    def _on_cache_config_relation_changed(self, _: ops.RelationChangedEvent) -> None:
        """Handle config relation changed event."""
        self._load_nginx_config()

    def _on_cache_config_relation_broken(self, event: ops.RelationBrokenEvent) -> None:
        """Handle config relation broken event."""
        port_map: dict[str, int] = self._stored.port_map  # type: ignore[assignment]
        port_map.pop(str(event.relation.id), None)
        if not port_map:
            self._stored.next_port_offset = 0
        self.unit.set_ports(*port_map.values())
        event.relation.data[self.unit]["cache-backend"] = ""
        self._load_nginx_config()

    def _rebuild_ca_bundle(self) -> None:
        """Rebuild the CA bundle from all active cert-transfer relations.

        Reads all active ``receive-ca-cert`` relations and writes every CA cert
        found to a single bundle file, replacing any previously written bundle.
        Handles V1 (app databag, JSON-encoded list) and V0 (unit databag,
        ``ca``/``chain`` fields) provider formats.

        Raises:
            CACertificateFileError: If writing the bundle file fails.
        """
        all_certs: list[str] = []
        for rel in self.model.relations[CERTIFICATE_TRANSFER_INTEGRATION_NAME]:
            if not rel.active:
                continue
            certs = _certs_from_relation(rel)
            if certs:
                all_certs.extend(certs)
            else:
                logger.debug("No cert data found in relation %s databags", rel.id)
        try:
            ca_certs.write_ca_bundle(all_certs)
        except CACertificateFileError:
            logger.exception("Failed to write CA bundle")
            self.unit.status = ops.BlockedStatus("Failed to write CA certificate to disk")
            raise

    def _on_certificate_transfer_changed(self, _: ops.EventBase) -> None:
        """Handle any certificate-transfer change — rebuild bundle and reconfigure."""
        try:
            self._rebuild_ca_bundle()
        except CACertificateFileError:
            return
        self._load_nginx_config()

    def _on_tls_certificates_relation_created(self, _: ops.RelationCreatedEvent) -> None:
        """Handle certificates relation created — enter WaitingStatus until cert arrives."""
        self._load_nginx_config()

    def _on_tls_certificate_available(self, _: CertificateAvailableEvent) -> None:
        """Handle TLS certificate available event — write cert and serve HTTPS."""
        try:
            certificates.write_certificate(
                "root",
                nginx_manager.NGINX_CERTIFICATES_PATH,
                self._tls_certificates,
            )
        except TLSCertificateFileError:
            logger.exception("Failed to write TLS certificate to disk")
            self.unit.status = ops.BlockedStatus("Failed to write TLS certificate to disk")
            return
        except TLSCertificateNotAvailableError:
            # The library fired certificate_available but get_assigned_certificate
            # returned nothing (e.g. transient timing).  Stay in WaitingStatus;
            # the next certificates-relation-changed event will retry.
            logger.warning("TLS certificate not yet available; waiting for next event")
            self.unit.status = ops.WaitingStatus(WAIT_FOR_TLS_CERT_MESSAGE)
            return
        self._load_nginx_config()

    def _on_tls_certificates_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle certificates relation broken — delete cert and revert to HTTP."""
        cert_path = nginx_manager.NGINX_CERTIFICATES_PATH / f"{FRONTEND_CERT_COMMON_NAME}.pem"
        try:
            cert_path.unlink(missing_ok=True)
        except OSError:
            logger.exception("Failed to remove certificate file %s", cert_path)
            self.unit.status = ops.BlockedStatus("Failed to remove TLS certificate file")
            return
        self._load_nginx_config(tls_cert_removed=True)

    def _get_cache_cert_path(self) -> Path | None:
        """Return the frontend cert path if TLS termination is active, else None.

        Returns None if no certificates relation is present or the certificate
        file has not yet been written; does not set unit status.
        """
        if self.model.get_relation(CERTIFICATE_INTEGRATION_NAME) is None:
            return None
        cert_path = nginx_manager.NGINX_CERTIFICATES_PATH / f"{FRONTEND_CERT_COMMON_NAME}.pem"
        return cert_path if cert_path.exists() else None

    def _update_status_with_nginx(self) -> None:
        """Set the charm status according to nginx status."""
        if not nginx_manager.health_check():
            self.unit.status = ops.MaintenanceStatus(NGINX_NOT_READY_MESSAGE)
            return

        self.unit.status = ops.ActiveStatus()

    def _load_nginx_config(self, tls_cert_removed: bool = False) -> None:
        """Validate the configuration and load to integration.

        Args:
            tls_cert_removed: Set to True when called from the certificates relation-broken
                handler. Bypasses the "waiting for TLS cert" guard so nginx is reconfigured
                back to HTTP even though the departing relation is still visible to ops.

        Raises:
            NginxFileError: File operation errors while updating nginx configuration files.
        """
        nginx_config = self._get_config_and_update_status()
        if nginx_config is None:
            self._clear_cache_backend()
            return

        ported_config = {
            rel_id: (self._get_port_for_relation(rel_id), config)
            for rel_id, config in nginx_config.items()
        }

        ca_bundle_path = ca_certs.get_ca_bundle_path()
        if ca_bundle_path is None and any(
            str(config.backends[0].scheme) == "https" for _, config in nginx_config.items()
        ):
            self.unit.status = ops.WaitingStatus(WAIT_FOR_CA_CERT_MESSAGE)
            self._clear_cache_backend()
            return

        cache_cert_path = self._get_cache_cert_path()
        if (
            cache_cert_path is None
            and not tls_cert_removed
            and self.model.get_relation(CERTIFICATE_INTEGRATION_NAME) is not None
        ):
            self.unit.status = ops.WaitingStatus(WAIT_FOR_TLS_CERT_MESSAGE)
            self._clear_cache_backend()
            return

        status_message = ""
        try:
            nginx_manager.update_and_load_config(
                ported_config,
                self._get_instance_name(),
                frontend_cert_path=cache_cert_path,
            )
        except NginxFileError:
            logger.exception(
                "Failed to update nginx config file, going to error state for retries"
            )
            raise
        except NginxConfigurationAggregateError as err:
            logger.exception("Found error with configuration for hosts: %s", err.hosts)
            logger.warning(
                "Any hosts configuration without errors will be served on content cache"
            )
            status_message = f"Error for host: {err.hosts}"

        self._update_status_with_nginx()
        if isinstance(self.unit.status, ops.ActiveStatus):
            self.unit.status = ops.ActiveStatus(status_message)
            port_map: dict[str, int] = self._stored.port_map  # type: ignore[assignment]
            self.unit.set_ports(*port_map.values())
            self._write_cache_backends(ported_config, cache_cert_path)
        else:
            self._clear_cache_backend()

    def _write_cache_backends(self, ported_config: dict, cache_cert_path: Path | None) -> None:
        """Write cache-backend URLs to all cache-config relation databags."""
        for rel_id, (port, _) in ported_config.items():
            rel = self.model.get_relation(CACHE_CONFIG_INTEGRATION_NAME, rel_id)
            if rel is None:
                continue
            url = get_cache_backend_url(
                self, rel, port, has_cache_cert=cache_cert_path is not None
            )
            if rel.data[self.unit].get("cache-backend") != url:
                rel.data[self.unit]["cache-backend"] = url

    def _clear_cache_backend(self) -> None:
        """Clear cache-backend from all cache-config relation databags."""
        for rel in self.model.relations[CACHE_CONFIG_INTEGRATION_NAME]:
            if rel.data[self.unit].get("cache-backend"):
                rel.data[self.unit]["cache-backend"] = ""

    def _get_config_and_update_status(self) -> NginxConfig | None:
        """Attempt to get nginx config, updates charm status on failure.

        Returns:
            The nginx configuration if found and valid.
        """
        try:
            nginx_config = get_nginx_config(self)
        except IntegrationDataError as err:
            self.unit.status = ops.BlockedStatus(str(err))
            return None
        if not nginx_config:
            self.unit.status = ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)
            return None
        self.unit.status = ops.MaintenanceStatus(RECEIVED_NGINX_CONFIG_MESSAGE)
        return nginx_config

    def _get_port_for_relation(self, relation_id: int) -> int:
        """Get the nginx listening port assigned to a relation, allocating one if needed.

        Port assignments are persisted in StoredState so the same port is returned
        across charm restarts for the same relation.

        New ports are allocated monotonically (like Linux PIDs) to maximise the time
        interval before a port number is reused after a relation is removed.

        Args:
            relation_id: The Juju relation ID.

        Returns:
            The allocated port number.
        """
        key = str(relation_id)
        port_map: dict[str, int] = self._stored.port_map  # type: ignore[assignment]
        if key not in port_map:
            used_ports = set(port_map.values())
            next_offset: int = self._stored.next_port_offset  # type: ignore[assignment]
            for i in range(NGINX_PORT_RANGE_SIZE):
                offset = (next_offset + i) % NGINX_PORT_RANGE_SIZE
                candidate = NGINX_PORT_RANGE_START + offset
                if candidate not in used_ports:
                    port_map[key] = candidate
                    self._stored.next_port_offset = (offset + 1) % NGINX_PORT_RANGE_SIZE
                    break
            else:
                raise RuntimeError(
                    f"Port range exhausted: all {NGINX_PORT_RANGE_SIZE} ports "
                    f"starting at {NGINX_PORT_RANGE_START} are in use"
                )
        return port_map[key]

    def _nginx_initialize(self) -> None:
        """Initialize the nginx instance.

        Raises:
            NginxSetupError: Failure to setup nginx.
        """
        try:
            nginx_manager.initialize(self._get_instance_name())
        except NginxSetupError:
            logger.exception("Failed to initialize nginx, going to error state for retries")
            raise

    def _nginx_stop(self) -> None:
        """Stop the nginx instance.

        Raises:
            NginxStopError: Failure to stop nginx.
        """
        try:
            nginx_manager.stop()
        except NginxStopError:
            logger.exception("Failed to stop nginx, going to error state for retries")
            raise

    def _get_instance_name(self) -> str:
        """Get a name to identify this unit.

        The nginx_manager module needs a name that can be used in file path.

        Returns:
            The name.
        """
        return unit_name_to_instance_name(self.unit.name)


def unit_name_to_instance_name(unit_name: str) -> str:
    """Transform the unit name to be filepath friendly instance name.

    This logic is in a separate function, to make testing not duplicate logic/code.

    Args:
        unit_name: The unit name.

    Returns:
        The instance name.
    """
    # Replace "/" as it has meaning in a file path.
    return unit_name.replace("/", "_")


def _certs_from_relation(rel: ops.Relation) -> list[str]:
    """Extract CA certificate strings from a cert-transfer relation's databags.

    Handles V1 format (provider app databag, JSON-encoded "certificates" list)
    and V0 format (provider unit databag, "ca"/"chain" fields).  Older provider
    implementations may omit "chain" and only populate "ca".

    Args:
        rel: The Juju relation to read cert data from.

    Returns:
        A list of non-empty PEM certificate strings, or an empty list if none found.
    """
    certs = _certs_from_v1_app_databag(rel)
    if not certs:
        certs = _certs_from_v0_unit_databags(rel)
    return certs


def _certs_from_v1_app_databag(rel: ops.Relation) -> list[str]:
    """Read V1-format certs from the provider's app databag.

    Args:
        rel: The cert-transfer relation.

    Returns:
        Parsed cert list, or empty list if not present / not parseable.
    """
    provider_data = rel.data.get(rel.app)
    if not provider_data:
        return []
    raw = provider_data.get("certificates")
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [c for c in parsed if c]
    except (json.JSONDecodeError, TypeError, ValueError):
        logger.debug("Could not JSON-decode certificates from provider app databag for %s", rel.id)
    return []


def _certs_from_v0_unit_databags(rel: ops.Relation) -> list[str]:
    """Read V0-format certs from provider unit databags.

    Tries "chain" first, then falls back to "ca".  "chain" may be stored
    as a JSON-encoded list or as a raw PEM string.

    Args:
        rel: The cert-transfer relation.

    Returns:
        Cert list extracted from the first unit that has data, or empty list.
    """
    for unit in rel.units:
        unit_data = rel.data.get(unit)
        if not unit_data:
            continue
        certs = _parse_chain_field(unit_data.get("chain", ""))
        if not certs:
            ca_raw = unit_data.get("ca", "")
            if isinstance(ca_raw, str) and ca_raw.strip():
                certs = [ca_raw]
        if certs:
            return certs
    return []


def _parse_chain_field(chain_raw: str) -> list[str]:
    """Parse the "chain" field from a V0 unit databag.

    The field may be a JSON-encoded list or a plain PEM string.

    Args:
        chain_raw: The raw string value of the "chain" databag key.

    Returns:
        A list of non-empty cert strings, or empty list.
    """
    if not chain_raw or not isinstance(chain_raw, str):
        return []
    try:
        parsed = json.loads(chain_raw)
        if isinstance(parsed, list):
            return [c for c in parsed if c]
    except (json.JSONDecodeError, ValueError):
        if chain_raw.strip():
            return [chain_raw]
    return []


if __name__ == "__main__":  # pragma: nocover
    ops.main(ContentCacheCharm)
