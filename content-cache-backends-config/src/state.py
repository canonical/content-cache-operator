# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The charm state and configurations."""

import enum
import json
import logging
import re
import typing

import ops
import pydantic
import pydantic_core

from errors import ConfigurationError

logger = logging.getLogger(__name__)

HOSTNAME_CONFIG_NAME = "hostname"
PATH_CONFIG_NAME = "path"
BACKENDS_CONFIG_NAME = "backends"
PROTOCOL_CONFIG_NAME = "protocol"
FAIL_TIMEOUT_CONFIG_NAME = "fail-timeout"
BACKENDS_PATH_CONFIG_NAME = "backends-path"
HEALTHCHECK_PATH_CONFIG_NAME = "healthcheck-path"
HEALTHCHECK_INTERVAL_CONFIG_NAME = "healthcheck-interval"
PROXY_CACHE_VALID_CONFIG_NAME = "proxy-cache-valid"


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


class Configuration(pydantic.BaseModel):
    """Represents the configuration.

    Attributes:
        hostname: The hostname for the virtual host for this set of configuration.
        path: The path for this set of configuration.
        backends: The backends for this set of configuration.
        protocol: The protocol to request the backends with. Can be http or https.
        fail_timeout: The time to wait before using a backend after failure.
        backends_path: The path to request the backends.
        healthcheck_path: The path to request the healthcheck endpoint.
        healthcheck_interval: The time between two helthchecks, in milliseconds.
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
    healthcheck_path: typing.Annotated[
        str,
        pydantic.StringConstraints(min_length=1),
        pydantic.AfterValidator(_validate_path_value),
    ]
    healthcheck_interval: pydantic.PositiveInt
    proxy_cache_valid: tuple[str, ...]

    @pydantic.field_validator("proxy_cache_valid")
    @classmethod
    def validate_proxy_cache_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Validate the proxy_cache_valid.

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
                raise ValueError(f"Invalid item in proxy_cache_valid: {item}")
            status_codes, time_str = tokens[:-1], tokens[-1]
            for code_str in status_codes:
                _check_status_code(code_str)
            _check_nginx_time_str(time_str)
        return value

    @classmethod
    def from_charm(cls, charm: ops.CharmBase) -> "Configuration":
        """Initialize object from the charm.

        Args:
            charm: The charm containing the configuration.

        Raises:
            ConfigurationError: Error with the charm configuration.

        Returns:
            The object.
        """
        hostname = typing.cast(str, charm.config.get(HOSTNAME_CONFIG_NAME, "")).strip()
        path = typing.cast(str, charm.config.get(PATH_CONFIG_NAME, "")).strip()
        protocol = typing.cast(str, charm.config.get(PROTOCOL_CONFIG_NAME, "")).lower().strip()
        backends_str = typing.cast(str, charm.config.get(BACKENDS_CONFIG_NAME, "")).strip()
        if not backends_str:
            raise ConfigurationError("Empty backends configuration found")
        fail_timeout = typing.cast(str, charm.config.get(FAIL_TIMEOUT_CONFIG_NAME, "")).strip()
        backends_path = typing.cast(str, charm.config.get(BACKENDS_PATH_CONFIG_NAME, "")).strip()
        healthcheck_path = typing.cast(
            str, charm.config.get(HEALTHCHECK_PATH_CONFIG_NAME, "")
        ).strip()
        healthcheck_interval = typing.cast(
            int, charm.config.get(HEALTHCHECK_INTERVAL_CONFIG_NAME, -1)
        )
        proxy_cache_valid_str = typing.cast(
            str, charm.config.get(PROXY_CACHE_VALID_CONFIG_NAME, "")
        ).strip()

        backends = tuple(ip.strip() for ip in backends_str.split(","))
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
            # Ignore type check and let pydantic handle the type with validation errors.
            return cls(
                hostname=hostname,
                path=path,
                backends=backends,  # type: ignore
                protocol=protocol,  # type: ignore
                fail_timeout=fail_timeout,
                backends_path=backends_path,
                healthcheck_path=healthcheck_path,
                healthcheck_interval=healthcheck_interval,
                proxy_cache_valid=proxy_cache_valid,  # type: ignore
            )
        except pydantic.ValidationError as err:
            err_msg = [
                f'{error["loc"][0]} = {error["input"]}: {error["msg"]}' for error in err.errors()
            ]
            logger.error("Found config error: %s", err_msg)
            raise ConfigurationError(f"Config error: {err_msg}") from err

    def to_integration_data(self) -> dict[str, str]:
        """Convert to format supported by integration.

        Juju integration only supports data of dict[str, str] type.
        This method ensures the the values in the dict are all str type.

        Raises:
            ConfigurationError: Unable to convert to integration data format.

        Returns:
            The data in the format accepted by integrations.
        """
        try:
            data = json.loads(self.model_dump_json())
        except pydantic_core.PydanticSerializationError as err:  #
            logger.exception("Failed to convert configuration to json")
            raise ConfigurationError(
                "Unable to convert configuration to integration data format"
            ) from err

        for key, value in data.items():
            if isinstance(value, str):
                continue
            try:
                data[key] = json.dumps(value)
            except (ValueError, TypeError) as err:
                logger.exception("Failed to convert configuration to integration data format")
                raise ConfigurationError(
                    "Unable to convert configuration to integration data format"
                ) from err
        return data


def _check_nginx_time_str(time_str: str) -> None:
    """Check if nginx time str is valid.

    Args:
        time_str: The time str for nginx configuration.

    Raises:
        ValueError: The input is not valid time str for nginx.
    """
    time_char = {"h", "m", "s"}
    if time_str[-1] not in time_char:
        raise ValueError(f"Invalid time for proxy_cache_valid: {time_str}")
    try:
        time = int(time_str[:-1])
    except ValueError as err:
        raise ValueError(f"Non-int time in proxy_cache_valid: {time_str}") from err

    if time < 1:
        raise ValueError(f"Time must be positive int for proxy_cache_valid: {time_str}")


def _check_status_code(code_str: str) -> None:
    """Check if status code is valid.

    Args:
        code_str: The status code.

    Raises:
        ValueError: The input is not valid status code.
    """
    try:
        code = int(code_str)
    except ValueError as err:
        raise ValueError(f"Non-int status code in proxy_cache_valid: {code_str}") from err

    # The standard status code is found here:
    # https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
    # It is possible for software to have custom status code, so any three digit int is
    # supported here.
    if code < 100 or code > 999:
        raise ValueError(f"Invalid status code in proxy_cache_valid: {code}")
