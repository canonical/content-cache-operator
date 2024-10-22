#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The content-cache charm."""

import logging
from time import sleep

import ops

import nginx_manager
from errors import (
    IntegrationDataError,
    NginxConfigurationAggregateError,
    NginxFileError,
    NginxSetupError,
    NginxStopError,
)
from state import CACHE_CONFIG_INTEGRATION_NAME, NginxConfig, get_nginx_config

logger = logging.getLogger(__name__)

WAIT_FOR_CONFIG_MESSAGE = "Waiting for integration with config charm"
NGINX_NOT_READY_MESSAGE = "Nginx is not ready"
RECEIVED_NGINX_CONFIG_MESSAGE = "Received nginx configuration"


class ContentCacheCharm(ops.CharmBase):
    """Charm the application."""

    def __init__(self, framework: ops.Framework) -> None:
        """Initialize the object.

        Args:
            framework: The ops framework.
        """
        super().__init__(framework)
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

    def _on_start(self, _: ops.StartEvent) -> None:
        """Handle start event."""
        _nginx_initialize()
        self._update_status()

    def _on_stop(self, _: ops.StopEvent) -> None:
        """Handle the stop event."""
        _nginx_stop()

    def _on_update_status(self, _: ops.UpdateStatusEvent) -> None:
        """Handle update status event."""
        self._update_status()

    def _on_cache_config_relation_changed(self, _: ops.RelationChangedEvent) -> None:
        """Handle config relation changed event."""
        self._load_nginx_config()

    def _on_cache_config_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle config relation broken event."""
        self._load_nginx_config()

    def _update_status(self) -> None:
        """Set the charm status."""
        if self.get_config_and_update_status() is None:
            return
        self._update_status_with_nginx()

    def _update_status_with_nginx(self) -> None:
        """Set the charm status according to nginx status."""
        if not nginx_manager.ready_check():
            self.unit.status = ops.MaintenanceStatus(NGINX_NOT_READY_MESSAGE)
            return

        self.unit.status = ops.ActiveStatus()

    def _load_nginx_config(self) -> None:
        """Validate the configuration and load to integration.

        Raises:
            NginxFileError: File operation errors while updating nginx configuration files.
        """
        nginx_config = self.get_config_and_update_status()
        if nginx_config is None:
            return

        status_message = ""
        try:
            nginx_manager.update_and_load_config(nginx_config)
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

        for _ in range(6):
            self._update_status_with_nginx()
            if isinstance(self.unit.status, ops.ActiveStatus):
                self.unit.status = ops.ActiveStatus(status_message)
                break
            sleep(5)

    def get_config_and_update_status(self) -> NginxConfig | None:
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
            _nginx_stop()
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
