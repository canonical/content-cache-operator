#!/usr/bin/env python3

# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The content-cache-backends-config charm."""

import logging

import ops

from errors import ConfigurationError
from state import Configuration

logger = logging.getLogger(__name__)

CACHE_CONFIG_INTEGRATION_NAME = "cache-config"


class ContentCacheBackendsConfigCharm(ops.CharmBase):
    """Charm the application."""

    def __init__(self, framework: ops.Framework) -> None:
        """Initialize the object.

        Args:
            framework: The ops framework.
        """
        super().__init__(framework)
        framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.config_changed, self._on_config_changed)
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
        self._leader_set_status()

    def _on_config_changed(self, _: ops.ConfigChangedEvent) -> None:
        """Handle config changed event."""
        self._load_integration_data()

    def _on_cache_config_relation_changed(self, _: ops.RelationChangedEvent) -> None:
        """Handle cache config relation changed event."""
        self._load_integration_data()

    def _on_cache_config_relation_broken(self, _: ops.RelationBrokenEvent) -> None:
        """Handle cache config relation broken event."""
        self._leader_set_status()

    def _load_integration_data(self) -> None:
        """Validate the configuration and load to integration."""
        if not self._leader_set_status():
            return

        logger.info("Loading configuration")
        try:
            config = Configuration.from_charm(self)
            data = config.to_integration_data()
        except ConfigurationError as err:
            logger.error("Configuration error: %s", err)
            self.unit.status = ops.BlockedStatus(str(err))
            return

        logger.info("Setting integration data")
        rel = self.model.relations[CACHE_CONFIG_INTEGRATION_NAME][0]
        rel.data[self.app].update(data)
        logger.info("Integration data set")

    def _leader_set_status(self) -> bool:
        """Set the charm status.

        Returns:
            Whether the unit is leader and ready.
        """
        if not self.unit.is_leader():
            logger.debug("Not leader: not setting the application status")
            self.unit.status = ops.ActiveStatus()
            return False

        if not self.model.relations[CACHE_CONFIG_INTEGRATION_NAME]:
            logger.info("No integration found")
            self.unit.status = ops.BlockedStatus("Waiting for integration")
            return False

        self.unit.status = ops.ActiveStatus()
        return True


if __name__ == "__main__":  # pragma: nocover
    ops.main(ContentCacheBackendsConfigCharm)
