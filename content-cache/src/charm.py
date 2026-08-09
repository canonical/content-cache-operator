#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The content-cache charm."""

import json
import logging

import ops
from charmlibs.interfaces.certificate_transfer import (
    CertificatesAvailableEvent,
    CertificatesRemovedEvent,
    CertificateTransferRequires,
)
from charms.grafana_agent.v0.cos_agent import COSAgentProvider

import ca_certs
import nginx_manager
from errors import (
    CACertificateFileError,
    IntegrationDataError,
    NginxConfigurationAggregateError,
    NginxFileError,
    NginxSetupError,
    NginxStopError,
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
            self._on_certificates_available,
        )
        framework.observe(
            self._certificate_transfer.on.certificates_removed,
            self._on_certificates_removed,
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

    def _sync_ca_certs_from_relations(self) -> None:
        """Write CA certs from all active cert-transfer relations to disk.

        This is a best-effort sync called when the CA bundle is missing but HTTPS
        backends are configured.  It handles the race where cache_config_relation_changed
        fires before certificate_set_updated has had a chance to write the bundle.

        Reads relation databags directly (bypassing the library parser) to handle
        both V1 (app databag, JSON-encoded "certificates" list) and V0 (unit databag,
        "ca"/"chain" fields) provider formats, including older providers that only
        write "ca" without "chain".
        """
        for rel in self.model.relations[CERTIFICATE_TRANSFER_INTEGRATION_NAME]:
            if not rel.active:
                continue
            certs = _certs_from_relation(rel)
            if not certs:
                logger.debug("No cert data found in relation %s databags", rel.id)
                continue
            try:
                ca_certs.write_ca_cert(rel.id, certs)
                logger.debug("Synced CA cert from relation %s", rel.id)
            except CACertificateFileError:
                logger.exception(
                    "Failed to sync CA certificate for relation %s during nginx config load",
                    rel.id,
                )

    def _on_certificates_available(self, event: CertificatesAvailableEvent) -> None:
        """Handle certificate-transfer certificates available event."""
        if event.certificates:
            try:
                ca_certs.write_ca_cert(event.relation_id, list(event.certificates))
            except CACertificateFileError:
                logger.exception(
                    "Failed to write CA certificate for relation %s", event.relation_id
                )
                self.unit.status = ops.BlockedStatus("Failed to write CA certificate to disk")
                return
        else:
            # Library returned empty certificates — the provider may not have written its
            # data yet, or the library failed to parse the databag.  Fall through to
            # _load_nginx_config() which calls _sync_ca_certs_from_relations() and reads
            # the provider's databag directly, bypassing the library parser.
            logger.debug(
                "Empty certificate set from library for relation %s; "
                "will attempt direct databag read in _load_nginx_config",
                event.relation_id,
            )
        self._load_nginx_config()

    def _on_certificates_removed(self, event: CertificatesRemovedEvent) -> None:
        """Handle certificate-transfer certificates removed event."""
        try:
            ca_certs.remove_ca_cert(event.relation_id)
        except CACertificateFileError:
            logger.exception("Failed to remove CA certificate for relation %s", event.relation_id)
            self.unit.status = ops.BlockedStatus("Failed to remove CA certificate from disk")
            return
        self._load_nginx_config()

    def _update_status_with_nginx(self) -> None:
        """Set the charm status according to nginx status."""
        if not nginx_manager.health_check():
            self.unit.status = ops.MaintenanceStatus(NGINX_NOT_READY_MESSAGE)
            return

        self.unit.status = ops.ActiveStatus()

    def _load_nginx_config(self) -> None:
        """Validate the configuration and load to integration.

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
        any_https = any(
            str(config.backends[0].scheme) == "https" for _, config in nginx_config.items()
        )
        if any_https and ca_bundle_path is None:
            # The CA bundle may not have been written yet if this hook fires before
            # the certificate_set_updated event.  Proactively read all cert-transfer
            # relations so we don't stay in WaitingStatus unnecessarily.
            self._sync_ca_certs_from_relations()
            ca_bundle_path = ca_certs.get_ca_bundle_path()
        if any_https and ca_bundle_path is None:
            self.unit.status = ops.WaitingStatus(WAIT_FOR_CA_CERT_MESSAGE)
            self._clear_cache_backends()
            return

        status_message = ""
        try:
            nginx_manager.update_and_load_config(
                ported_config, self._get_instance_name(), ca_bundle_path=ca_bundle_path
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
            for rel_id, (port, _) in ported_config.items():
                rel = self.model.get_relation(CACHE_CONFIG_INTEGRATION_NAME, rel_id)
                if rel is None:
                    continue
                url = get_cache_backend_url(self, rel, port)
                if rel.data[self.unit].get("cache-backend") != url:
                    rel.data[self.unit]["cache-backend"] = url
        else:
            self._clear_cache_backend()

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
