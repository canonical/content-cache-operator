# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The charm state and configurations."""

import enum
import json
import logging
import re
import typing
from collections import defaultdict

import ops
import pydantic

from errors import ConfigurationError, IntegrationDataError

logger = logging.getLogger(__name__)

CACHE_CONFIG_INTEGRATION_NAME = "cache-config"

HOSTNAME_CONFIG_NAME = "hostname"
PATH_CONFIG_NAME = "path"
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
        hostname: The hostname for the virtual host for this set of configuration.
        path: The path for this set of configuration.
        backends: The backends for this set of configuration.
        protocol: The protocol to request the backends with. Can be http or
            https.
    """

    hostname: typing.Annotated[str, pydantic.StringConstraints(min_length=1)]
    path: typing.Annotated[str, pydantic.StringConstraints(min_length=1)]
    backends: tuple[pydantic.IPvAnyAddress, ...]
    protocol: Protocol

    @pydantic.field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        """Validate the hostname.

        Args:
            value: The value to validate.

        Raises:
            ValueError: Error in validation.

        Returns:
            The value after validation.
        """
        if len(value) > 255:
            raise ValueError("Hostname cannot be longer than 255")

        valid_segment = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        for segment in value.split("."):
            if valid_segment.fullmatch(segment) is None:
                raise ValueError(
                    "Each Hostname segment must be less than 64 in length, and consist of alphanumeric and hyphen"
                )

        return value

    @pydantic.field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        """Validate the path.

        Args:
            value: The value to validate.

        Raises:
            ValueError: Error in validation.

        Returns:
            The value after validation.
        """
        # This are the valid characters for path in addition to `/`:
        # a-z A-Z 0-9 . - _ ~ ! $ & ' ( ) * + , ; = : @
        # https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
        valid_path = re.compile("[/A-Z\d.\-_~!$&'()*+,;=:@]+", re.IGNORECASE)
        if valid_path.fullmatch(value) is None:
            raise ValueError("Path contains non-allowed character")
        return value

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
        hostname = data.get(HOSTNAME_CONFIG_NAME, "").strip()
        path = data.get(PATH_CONFIG_NAME, "").strip()
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
                hostname=hostname,
                path=path,
                backends=backends,  # type: ignore
                protocol=protocol,  # type: ignore
            )
        except pydantic.ValidationError as err:
            err_msg = [
                f'{error["loc"][0]} = {error["input"]}: {error["msg"]}' for error in err.errors()
            ]
            logger.error("Found integration data error: %s", err_msg)
            raise ConfigurationError(f"Config error: {err_msg}") from err


Hostname = str
Location = str
NginxConfig = dict[Hostname, dict[Location, LocationConfig]]
ServerConfig = dict[Location, LocationConfig]


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

    configurations = defaultdict(dict)

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

        configurations[config.hostname][config.path] = config
    return configurations
