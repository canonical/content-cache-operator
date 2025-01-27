#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The content-cache charm."""

import logging

import ops
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    Mode,
    TLSCertificatesRequiresV4,
)

import nginx_manager
from certificates import write_certificates
from errors import (
    IntegrationDataError,
    NginxConfigurationAggregateError,
    NginxFileError,
    NginxSetupError,
    NginxStopError,
    TLSCertificateFileError,
    TLSCertificateIntegrationNotExistError,
    TLSCertificateNotAvailableError,
)
from state import (
    CACHE_CONFIG_INTEGRATION_NAME,
    CERTIFICATE_INTEGRATION_NAME,
    NginxConfig,
    extract_hostname_from_nginx_config,
    get_hostnames,
    get_nginx_config,
)

logger = logging.getLogger(__name__)

WAIT_FOR_CONFIG_MESSAGE = "Waiting for integration with config charm"
NGINX_NOT_READY_MESSAGE = "Nginx is not ready"
RECEIVED_NGINX_CONFIG_MESSAGE = "Received nginx configuration"
WAIT_FOR_TLS_CERT_MESSAGE = "Waiting for TLS certificates requested"


class ContentCacheCharm(ops.CharmBase):
    """Charm the application."""

    def __init__(self, framework: ops.Framework) -> None:
        """Initialize the object.

        Args:
            framework: The ops framework.
        """
        super().__init__(framework)

        self._cos_agent = COSAgentProvider(charm=self)

        # Get the hostname from the integration data.
        hostnames = []
        try:
            hostnames = get_hostnames(self)
        except IntegrationDataError as err:
            logger.warning("Issues with integration data: %s", err)
            # Unable to do anything about the error, therefore continue with setup.

        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=CERTIFICATE_INTEGRATION_NAME,
            certificate_requests=[
                CertificateRequestAttributes(common_name=name) for name in hostnames
            ],
            mode=Mode.UNIT,
            refresh_events=[
                self.on[CACHE_CONFIG_INTEGRATION_NAME].relation_changed,
                self.on[CACHE_CONFIG_INTEGRATION_NAME].relation_broken,
            ],
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
            self.certificates.on.certificate_available,
            self._on_certificate_available,
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

    def _on_cache_config_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle config relation broken event."""
        self._load_nginx_config()

    def _on_certificate_available(self, _: ops.EventBase) -> None:
        """Handle certificate available event."""
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
            return

        hostnames = extract_hostname_from_nginx_config(nginx_config)
        hostname_to_cert = {}
        try:
            hostname_to_cert = write_certificates(
                hostnames,
                nginx_manager.NGINX_USER,
                nginx_manager.NGINX_CERTIFICATES_PATH,
                self.certificates,
            )
            logger.info("Found all certificate requested")
            self.unit.open_port("tcp", 443)
        except TLSCertificateIntegrationNotExistError:
            logger.info("Skipping TLS certificates as tls-certificate integration not found")
        except TLSCertificateFileError:
            logger.exception(
                "Failed to write TLS certificate file, going to error state for retries"
            )
            raise
        except TLSCertificateNotAvailableError:
            logger.warning(
                "Unable to load nginx config due to not all certificate needed are available yet"
            )
            self.unit.status = ops.MaintenanceStatus(WAIT_FOR_TLS_CERT_MESSAGE)
            return

        status_message = ""
        try:
            nginx_manager.update_and_load_config(
                nginx_config, hostname_to_cert, self._get_instance_name()
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

    def _nginx_initialize(self) -> None:
        """Initialize the nginx instance.

        Raises:
            NginxSetupError: Failure to setup nginx.
        """
        try:
            nginx_manager.initialize(self._get_instance_name())
            self.unit.open_port("tcp", 80)
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


if __name__ == "__main__":  # pragma: nocover
    ops.main(ContentCacheCharm)
