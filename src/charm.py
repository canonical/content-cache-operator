#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The content-cache charm."""

import logging

import ops
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.tls_certificates_interface.v4.tls_certificates import Mode, TLSCertificatesRequiresV4

import nginx_manager
from certificates import TLSCertificatesManager, _generate_certificate_requests
from errors import (
    IntegrationDataError,
    NginxConfigurationAggregateError,
    NginxFileError,
    NginxSetupError,
    NginxStopError,
    TLSCertificateFileError,
)
from state import (
    CACHE_CONFIG_INTEGRATION_NAME,
    CERTIFICATE_INTEGRATION_NAME,
    NginxConfig,
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

        COSAgentProvider(charm=self)

        # Get the hostname from the integration data.
        certificate_requests = []
        try:
            nginx_config = get_nginx_config(self)
            certificate_requests = _generate_certificate_requests(list(nginx_config.keys()))
        except IntegrationDataError as err:
            logger.warning("Issues with integration data: %s", err)
            # Unable to do anything about the error, therefore continue with setup.

        certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=CERTIFICATE_INTEGRATION_NAME,
            certificate_requests=certificate_requests,
            mode=Mode.UNIT,
            refresh_events=[
                self.on[CACHE_CONFIG_INTEGRATION_NAME].relation_changed,
                self.on[CACHE_CONFIG_INTEGRATION_NAME].relation_broken,
            ],
        )
        self.certificates_manager = TLSCertificatesManager(
            user=nginx_manager.NGINX_USER,
            certificates_path=nginx_manager.NGINX_CERTIFICATES_PATH,
            certificates=certificates,
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
            self.certificates_manager.certificates.on.certificate_available,
            self._on_certificate_available,
        )

    def _on_start(self, _: ops.StartEvent) -> None:
        """Handle start event."""
        _nginx_initialize()
        self._load_nginx_config()

    def _on_stop(self, _: ops.StopEvent) -> None:
        """Handle the stop event."""
        _nginx_stop()

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

        hostnames = list(nginx_config.keys())

        hostname_to_cert = {}
        if self.certificates_manager.integration_exists():
            logger.info("Loading the certificates")
            try:
                hostname_to_cert = self.certificates_manager.load_certificates(hostnames)
            except TLSCertificateFileError:
                logger.exception(
                    "Failed to write TLS certificate file, going to error state for retries"
                )
                raise

            if len(hostname_to_cert) != len(hostnames):
                logger.warning(
                    "Unable to load nginx config due to not all certificates are available yet"
                )
                self.unit.status = ops.MaintenanceStatus(WAIT_FOR_TLS_CERT_MESSAGE)
                return
            logger.info("Found all certificate requested")

        status_message = ""
        try:
            nginx_manager.update_and_load_config(nginx_config, hostname_to_cert)
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


def _nginx_initialize() -> None:
    """Initialize the nginx instance.

    Raises:
        NginxSetupError: Failure to setup nginx.
    """
    try:
        nginx_manager.initialize()
    except NginxSetupError:
        logger.exception("Failed to initialize nginx, going to error state for retries")
        raise


def _nginx_stop() -> None:
    """Stop the nginx instance.

    Raises:
        NginxStopError: Failure to stop nginx.
    """
    try:
        nginx_manager.stop()
    except NginxStopError:
        logger.exception("Failed to stop nginx, going to error state for retries")
        raise


if __name__ == "__main__":  # pragma: nocover
    ops.main(ContentCacheCharm)
