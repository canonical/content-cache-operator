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
CERTIFICATE_INTEGRATION_NAME = "certificates"

HOSTNAME_FIELD_NAME = "hostname"
PATH_FIELD_NAME = "path"
BACKENDS_FIELD_NAME = "backends"
PROTOCOL_FIELD_NAME = "protocol"
FAIL_TIMEOUT_FIELD_NAME = "fail_timeout"
BACKENDS_PATH_FIELD_NAME = "backends_path"
PROXY_CACHE_VALID_FIELD_NAME = "proxy_cache_valid"


class Protocol(str, enum.Enum):
    """Protocol to request backends.

    Attributes:
        HTTP: Use HTTP for requests.
        HTTPS: Use HTTPS for requests.
    """

    HTTP = "http"
    HTTPS = "https"


def _validate_hostname_value(value: str) -> str:
    """Validate the value as a hostname.

    Validation performed:
    - The hostname must be of length 255 or below.
    - The hostname must be consist of a certain characters.

    Args:
        value: The value to validate.

    Raises:
        ValueError: The validation failed.

    Returns:
        The value after validation.
    """
    if len(value) > 255:
        raise ValueError("Hostname cannot be longer than 255")

    valid_segment = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    for segment in value.split("."):
        if valid_segment.fullmatch(segment) is None:
            raise ValueError(
                (
                    "Each Hostname segment must be less than 64 in length, and consist of "
                    "alphanumeric and hyphen"
                )
            )

    return value


def _validate_path_value(value: str) -> str:
    """Validate the value as a path.

    Validation performed:
    - The path is only consist of allowed characters.

    These are the valid characters for path in addition to `/`:
    a-z A-Z 0-9 . - _ ~ ! $ & ' ( ) * + , ; = : @
    https://datatracker.ietf.org/doc/html/rfc3986#section-3.3

    Args:
        value: The value to validate.

    Raises:
        ValueError: The validation failed.

    Returns:
        The value after validation.
    """
    valid_path = re.compile(r"[/\w.\-~!$&'()*+,;=:@]+", re.IGNORECASE)
    if valid_path.fullmatch(value) is None:
        raise ValueError("Path contains non-allowed character")
    return value


class LocationConfig(pydantic.BaseModel):
    """Represents the configuration for a location.

    Attributes:
        hostname: The hostname for the virtual host for this set of configuration.
        path: The path for this set of configuration.
        backends: The backends for this set of configuration.
        protocol: The protocol to request the backends with. Can be http or https.
        fail_timeout: The time to wait before using a backend after failure.
        backends_path: The path to request the backends.
        proxy_cache_valid: The cache valid duration.
    """

    hostname: typing.Annotated[
        str,
        pydantic.StringConstraints(min_length=1),
        pydantic.AfterValidator(_validate_hostname_value),
    ]
    path: typing.Annotated[
        str,
        pydantic.StringConstraints(min_length=1),
        pydantic.AfterValidator(_validate_path_value),
    ]
    backends: tuple[pydantic.IPvAnyAddress, ...]
    protocol: Protocol
    fail_timeout: typing.Annotated[str, pydantic.StringConstraints(min_length=1)]
    backends_path: typing.Annotated[
        str,
        pydantic.StringConstraints(min_length=1),
        pydantic.AfterValidator(_validate_path_value),
    ]
    proxy_cache_valid: tuple[str, ...]

    @pydantic.field_validator("proxy_cache_valid")
    @classmethod
    def validate_proxy_cache_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Validate the proxy_cache_valid.

        Validation performed:
        - Each token is consist of at least one status code and a time.
        - The status code is a int within allowed range.
        - The time string is of correct format.

        Args:
            value: The value to validate.

        Raises:
            ValueError: The proxy_cache_valid is invalid.

        Returns:
            The value after validation.
        """
        for item in value:
            tokens = item.split(" ")
            if len(tokens) < 2:
                raise ValueError(
                    f"The proxy_cache_valid requires at least one status code and a time: {item}"
                )
            status_codes, time_str = tokens[:-1], tokens[-1]
            for code_str in status_codes:
                _check_status_code(code_str)
            _check_nginx_time_str(time_str)
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
        hostname = data.get(HOSTNAME_FIELD_NAME, "").strip()
        path = data.get(PATH_FIELD_NAME, "").strip()
        protocol = data.get(PROTOCOL_FIELD_NAME, "").lower().strip()
        backends_str = data.get(BACKENDS_FIELD_NAME, "").strip()
        fail_timeout = data.get(FAIL_TIMEOUT_FIELD_NAME, "").strip()
        backends_path = data.get(BACKENDS_PATH_FIELD_NAME, "").strip()
        proxy_cache_valid_str = data.get(PROXY_CACHE_VALID_FIELD_NAME, "").strip()

        try:
            proxy_cache_valid = json.loads(proxy_cache_valid_str)
        except json.JSONDecodeError as err:
            raise ConfigurationError(
                f"Unable to parse proxy_cache_valid: {proxy_cache_valid_str}"
            ) from err

        if not isinstance(proxy_cache_valid, list):
            raise ConfigurationError(
                f"The proxy_cache_valid is not a list: {proxy_cache_valid_str}"
            )

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
                fail_timeout=fail_timeout,
                backends_path=backends_path,
                proxy_cache_valid=proxy_cache_valid,  # type: ignore
            )
        except pydantic.ValidationError as err:
            err_msg = [
                f'{error["loc"][0]} = {error["input"]}: {error["msg"]}' for error in err.errors()
            ]
            logger.error("Found integration data error: %s", err_msg)
            raise ConfigurationError(f"Config error: {err_msg}") from err


def _check_nginx_time_str(time_str: str) -> None:
    """Check if nginx time str is valid.

    Validation performed:
    - The character at the end must be "d", "h", "m", "s".
    - The time must be positive int.

    Args:
        time_str: The time str for nginx configuration.

    Raises:
        ValueError: The input is not valid time str for nginx.
    """
    time_char = {"d", "h", "m", "s"}
    if time_str[-1] not in time_char:
        raise ValueError(f"Invalid time unit for proxy_cache_valid: {time_str}")
    try:
        time = int(time_str[:-1])
    except ValueError as err:
        raise ValueError(f"Non-int time in proxy_cache_valid: {time_str}") from err

    if time < 1:
        raise ValueError(f"Time must be positive int for proxy_cache_valid: {time_str}")


def _check_status_code(code_str: str) -> None:
    """Check if status code is valid.

    Validation performed:
    - The status code must be int.
    - The status code must be within 100 to 900.

    The standard status code is found here:
    https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml

    It is possible for software to have custom status code, so any three digit int is
    supported here.

    Args:
        code_str: The status code.

    Raises:
        ValueError: The input is not valid status code.
    """
    try:
        code = int(code_str)
    except ValueError as err:
        raise ValueError(f"Non-int status code in proxy_cache_valid: {code_str}") from err

    if code < 100 or code > 999:
        raise ValueError(f"Invalid status code in proxy_cache_valid: {code}")


Hostname = str
Location = str
NginxConfig = dict[Hostname, dict[Location, LocationConfig]]
HostConfig = dict[Location, LocationConfig]


def extract_hostname_from_nginx_config(config: NginxConfig) -> tuple[Hostname, ...]:
    """Extract the list of hostnames from nginx configuration.

    Args:
        config: The configuration.

    Returns:
        The list of hostnames.
    """
    return tuple(config.keys())


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
        logger.info("Found no configuration integrations")
        return {}

    configurations: defaultdict[Hostname, dict[Location, LocationConfig]] = defaultdict(dict)

    for rel in relations:
        logger.info("Parsing integration data for %s", rel.app)
        relation_data = rel.data[rel.app]
        if not relation_data:
            logger.info("Found integration %s with no data", rel.id)
            continue
        try:
            config = LocationConfig.from_integration_data(relation_data)
        except ConfigurationError as err:
            logger.exception("Found integration %s with faulty data", rel.id)
            raise IntegrationDataError(
                f"Faulty data from integration {rel.id}: {str(err)}"
            ) from err

        configurations[config.hostname][config.path] = config
    return configurations


def get_hostnames(charm: ops.CharmBase) -> tuple[Hostname, ...]:
    """Get the hostnames from integration data.

    Args:
        charm: The charm to extract integration data from.

    Raises:
        IntegrationDataError: Invalid hostname in integration data.

    Returns:
        A list of hostnames.
    """
    hostnames: list[Hostname] = []
    relations = charm.model.relations.get(CACHE_CONFIG_INTEGRATION_NAME)
    if not relations:
        logger.info("Found no configuration integrations")
        return tuple(hostnames)

    for rel in relations:
        logger.info("Getting hostname from integration data for %s", rel.app)
        hostname = rel.data[rel.app].get(HOSTNAME_FIELD_NAME, "").strip()
        try:
            _validate_hostname_value(hostname)
        except ValueError as err:
            logger.exception("Found integration %s with faulty hostname %s", rel.id, hostname)
            raise IntegrationDataError(
                f"Faulty hostname from integration {rel.id}: {str(err)}"
            ) from err
        hostnames.append(hostname)
    return tuple(hostnames)
