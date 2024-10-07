#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The content-cache charm."""

import logging

import ops

from errors import IntegrationDataError
from nginx_manager import NginxManager
from state import CACHE_CONFIG_INTEGRATION_NAME, get_nginx_config

logger = logging.getLogger(__name__)

WAIT_FOR_CONFIG_MESSAGE = "Waiting for integration with config charm"
NGINX_NOT_READY_MESSAGE = "Nginx is not ready"


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
        self._nginx = NginxManager()

    def _on_start(self, _: ops.StartEvent) -> None:
        """Handle start event."""
        self._nginx.init()
        self._set_status()

    def _on_stop(self, _: ops.StopEvent) -> None:
        """Handle the stop event."""
        self._nginx.stop()

    def _on_update_status(self, _: ops.UpdateStatusEvent) -> None:
        """Handle update status event."""
        self._set_status()

    def _on_cache_config_relation_changed(self, _: ops.RelationChangedEvent) -> None:
        """Handle config relation changed event."""
        self._load_nginx_config()

    def _on_cache_config_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle config relation broken event."""
        self._load_nginx_config()

    def _set_status(self) -> None:
        """Set the charm status."""
        if not self.model.relations[CACHE_CONFIG_INTEGRATION_NAME]:
            self.unit.status = ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)
            return

        if not self._nginx.ready_check():
            self.unit.status = ops.MaintenanceStatus(NGINX_NOT_READY_MESSAGE)
        else:
            self.unit.status = ops.ActiveStatus()

    def _load_nginx_config(self) -> None:
        """Validate the configuration and load to integration."""
        try:
            nginx_config = get_nginx_config(self)
        except IntegrationDataError as err:
            self.unit.status = ops.BlockedStatus(str(err))
            return
        if not nginx_config:
            self._nginx.stop()
            self.unit.status = ops.BlockedStatus(WAIT_FOR_CONFIG_MESSAGE)
            return

        self._nginx.update_config(nginx_config)
        self._nginx.load()
        self.unit.status = ops.ActiveStatus()


if __name__ == "__main__":  # pragma: nocover
    ops.main(ContentCacheCharm)  # type: ignore
