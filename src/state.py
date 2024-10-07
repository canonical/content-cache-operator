# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The charm state and configurations."""

import enum
import json
import logging
import typing

import ops
import pydantic

from errors import ConfigurationError, IntegrationDataError

logger = logging.getLogger(__name__)

CACHE_CONFIG_INTEGRATION_NAME = "cache-config"

LOCATION_CONFIG_NAME = "location"
BACKENDS_CONFIG_NAME = "backends"
PROTOCOL_CONFIG_NAME = "protocol"


class Protocol(str, enum.Enum):
    """Protocol to request backends.

    Attributes:
        HTTP: Use HTTP for requests.
        HTTPS: Use HTTPS for requests.
    """

    HTTP = "http"
    HTTPS = "https"


class LocationConfig(pydantic.BaseModel):
    """Represents the configuration for a location.

    Attributes:
        location: Defines what URL to match for this set of configuration.
        backends: The backends for this set of configuration.
        protocol: The protocol to request the backends with. Can be http or
            https.
    """

    location: typing.Annotated[str, pydantic.StringConstraints(min_length=1)]
    backends: tuple[pydantic.IPvAnyAddress, ...]
    protocol: Protocol

    @classmethod
    def from_integration_data(cls, data: ops.RelationDataContent) -> "LocationConfig":
        """Initialize object from the charm.

        Args:
            data: One set of integration data.

        Raises:
            ConfigurationError: Invalid cache configurations in integration data.

        Returns:
            The object.
        """
        location = data.get(LOCATION_CONFIG_NAME, "").strip()
        protocol = data.get(PROTOCOL_CONFIG_NAME, "").lower().strip()
        backends_str = data.get(BACKENDS_CONFIG_NAME, "").strip()

        try:
            backends = json.loads(backends_str)
        except json.decoder.JSONDecodeError as err:
            raise ConfigurationError("Unable to parse backends as json") from err

        if not isinstance(backends, list):
            raise ConfigurationError("Unable to convert backends to list")
        if not backends:
            raise ConfigurationError("Empty backends found")

        try:
            # Ignore type check and let pydantic handle the type with validation errors.
            return cls(
                location=location,
                backends=backends,  # type: ignore
                protocol=protocol,  # type: ignore
            )
        except pydantic.ValidationError as err:
            err_msg = [
                f'{error["loc"][0]} = {error["input"]}: {error["msg"]}' for error in err.errors()
            ]
            logger.error("Found integration data error: %s", err_msg)
            raise ConfigurationError(f"Config error: {err_msg}") from err


NginxConfig = dict[str, LocationConfig]


def get_nginx_config(charm: ops.CharmBase) -> NginxConfig:
    """Get the nginx locations configuration from integration data.

    Args:
        charm: The charm to extract integration data from.

    Raises:
        IntegrationDataError: Invalid cache configurations in integration data.

    Returns:
        The collection of locations and their configurations.
    """
    relations = charm.model.relations[CACHE_CONFIG_INTEGRATION_NAME]
    if not relations:
        logger.info("Found no integrations")
        return {}

    configurations = {}

    for rel in relations:
        logger.info("Parsing integration data for %s", rel.app)
        try:
            relation_data = rel.data[rel.app]
            if not relation_data:
                logger.info("Found integration %s with no data", rel.id)
                continue
            config = LocationConfig.from_integration_data(relation_data)
        except ConfigurationError as err:
            raise IntegrationDataError(
                f"Faulty data from integration {rel.id}: {str(err)}"
            ) from err
        configurations[config.location] = config
    return configurations
