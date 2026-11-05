# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""cache-config interface library, provider side.

Implements the provider side of the cache-config interface: reading and validating the
backend configuration published by requirers, and publishing the resulting cache-backend
URL back to each relation.
"""

import logging

import ops
from ops.framework import Object
from pydantic import ValidationError

from cache_config.errors import CacheConfigIntegrationDataError
from cache_config.requirer import (
    CACHE_BACKEND_FIELD_NAME,
    CACHE_CONFIG_RELATION_NAME,
    CacheConfigRequirerAppData,
    _decode,
)

logger = logging.getLogger(__name__)

RelationId = int


class CacheConfigProvider(Object):
    """cache-config interface provider implementation."""

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str = CACHE_CONFIG_RELATION_NAME,
    ) -> None:
        """Initialize the CacheConfigProvider.

        Args:
            charm: The charm instance using this library.
            relation_name: The name of the relation endpoint.
        """
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

    def get_requirers_data(self) -> dict[RelationId, CacheConfigRequirerAppData]:
        """Read and validate every related requirer's app databag.

        Relations with no data published yet are omitted rather than errored, since that
        is the normal state before the remote charm has finished its own configuration.

        Raises:
            CacheConfigIntegrationDataError: When a requirer's app databag fails
                validation. This fails the whole call on the first bad relation, rather
                than silently skipping it, since a misconfigured backend must block
                reconciliation rather than be dropped.

        Returns:
            A mapping of relation id to the requirer's validated app data.
        """
        configurations: dict[RelationId, CacheConfigRequirerAppData] = {}
        for relation in self.charm.model.relations[self.relation_name]:
            relation_data = relation.data[relation.app]
            if not relation_data:
                continue
            try:
                configurations[relation.id] = relation.load(
                    CacheConfigRequirerAppData, relation.app, decoder=_decode
                )
            except ValidationError as exc:
                raise CacheConfigIntegrationDataError(
                    f"Faulty cache-config data from relation {relation.id}: {exc}"
                ) from exc
        return configurations

    def publish_cache_backend(self, relation_id: int, cache_backend_url: str) -> None:
        """Publish the resolved cache-backend URL to a relation's unit databag.

        Args:
            relation_id: The id of the relation to publish to.
            cache_backend_url: The URL this unit serves the relation's backend on.
        """
        relation = self.charm.model.get_relation(self.relation_name, relation_id)
        if relation is None:
            return
        if relation.data[self.charm.unit].get(CACHE_BACKEND_FIELD_NAME) != cache_backend_url:
            relation.data[self.charm.unit][CACHE_BACKEND_FIELD_NAME] = cache_backend_url

    def clear_cache_backend(self, relation: ops.Relation) -> None:
        """Clear the cache-backend value from a relation's unit databag.

        Args:
            relation: The relation to clear cache-backend from.
        """
        if relation.data[self.charm.unit].get(CACHE_BACKEND_FIELD_NAME):
            relation.data[self.charm.unit][CACHE_BACKEND_FIELD_NAME] = ""
