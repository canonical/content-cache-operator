# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The charm state and configurations."""

import json
import logging
import re
import typing

import ops
import pydantic
import pydantic_core

from errors import ConfigurationError

logger = logging.getLogger(__name__)

BACKENDS_CONFIG_NAME = "backends"
FAIL_TIMEOUT_CONFIG_NAME = "fail-timeout"
BACKENDS_PATH_CONFIG_NAME = "backends-path"
HEALTHCHECK_INTERVAL_CONFIG_NAME = "healthcheck-interval"
HEALTHCHECK_PATH_CONFIG_NAME = "healthcheck-path"
HEALTHCHECK_SSL_VERIFY_CONFIG_NAME = "healthcheck-ssl-verify"
HEALTHCHECK_VALID_STATUS_CONFIG_NAME = "healthcheck-valid-status"
PROXY_CACHE_VALID_CONFIG_NAME = "proxy-cache-valid"
CACHE_INACTIVE_CONFIG_NAME = "cache-inactive"
CACHE_MAX_SIZE_CONFIG_NAME = "cache-max-size"
CACHE_INACTIVE_FIELD_NAME = "cache_inactive"
CACHE_MAX_SIZE_FIELD_NAME = "cache_max_size"
BACKEND_HOSTNAME_CONFIG_NAME = "backend-hostname"
BACKEND_CA_FINGERPRINT_CONFIG_NAME = "backend-ca-fingerprint"


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


def _validate_fingerprint_value(value: str) -> str:
    """Validate the value as a colon-separated SHA-256 hex fingerprint.

    Args:
        value: The value to validate. Empty string is allowed (means not configured).

    Raises:
        ValueError: The validation failed.

    Returns:
        The value after validation, uppercased.
    """
    if not value:
        return value
    pattern = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){31}$")
    if not pattern.match(value):
        raise ValueError(
            "backend-ca-fingerprint must be a colon-separated SHA-256 hex fingerprint "
            "consisting of 32 two-digit hex groups separated by colons "
            "(e.g. 96:BC:EC:06:...)"
        )
    return value.upper()


class HealthcheckConfig(pydantic.BaseModel):
    """Represents the configuration for healthchecks.

    Attributes:
        interval: The time between two healthchecks, in milliseconds.
        path: The path to check on the backends for health.
        valid_status: HTTP status codes considered as valid during health checks.
        ssl_verify: Should we check SSL certificates during health checks.
    """

    interval: pydantic.PositiveInt
    path: typing.Annotated[
        str,
        pydantic.StringConstraints(min_length=1),
        pydantic.AfterValidator(_validate_path_value),
    ]
    ssl_verify: bool
    valid_status: tuple[int, ...]

    @classmethod
    def from_charm(cls, charm: ops.CharmBase) -> "HealthcheckConfig":
        """Initialize object from the charm.

        Args:
            charm: The charm containing the configuration.

        Raises:
            ConfigurationError: Error with the charm configuration.

        Returns:
            The object.
        """
        interval = typing.cast(int, charm.config.get(HEALTHCHECK_INTERVAL_CONFIG_NAME, -1))
        path = typing.cast(str, charm.config.get(HEALTHCHECK_PATH_CONFIG_NAME, "")).strip()
        valid_status_str = typing.cast(
            str, charm.config.get(HEALTHCHECK_VALID_STATUS_CONFIG_NAME, "")
        ).strip()
        ssl_verify = typing.cast(bool, charm.config.get(HEALTHCHECK_SSL_VERIFY_CONFIG_NAME, False))

        valid_status = tuple(int(status) for status in valid_status_str.split(","))

        try:
            # Ignore type check and let pydantic handle the type with validation errors.
            return cls(
                interval=interval,
                path=path,
                ssl_verify=ssl_verify,  # type: ignore
                valid_status=valid_status,
            )
        except pydantic.ValidationError as err:
            err_msg = [
                f'{error["loc"][0]} = {error["input"]}: {error["msg"]}' for error in err.errors()
            ]
            logger.error("Found config error: %s", err_msg)
            raise ConfigurationError(f"Config error: {err_msg}") from err


class Configuration(pydantic.BaseModel):
    """Represents the configuration.

    Attributes:
        backends: The backends for this configuration as full URLs.
        fail_timeout: The time to wait before using a backend after failure.
        proxy_cache_valid: The cache valid duration.
        healthcheck: The healthcheck configuration.
        cache_inactive: Time after which an unaccessed item is evicted from the disk cache.
        cache_max_size: Maximum total disk size for the cache; empty string means no limit.
        backend_hostname: Hostname for SNI and Host header when proxying to HTTPS backends.
        backend_ca_fingerprint: SHA-256 fingerprint of the CA cert for backend TLS verification.
    """

    backends: tuple[pydantic.AnyHttpUrl, ...]
    fail_timeout: typing.Annotated[str, pydantic.StringConstraints(min_length=1)]
    proxy_cache_valid: tuple[str, ...]
    healthcheck: HealthcheckConfig
    cache_inactive: str
    cache_max_size: str
    backend_hostname: str = ""
    backend_ca_fingerprint: typing.Annotated[
        str,
        pydantic.AfterValidator(_validate_fingerprint_value),
    ] = ""

    @pydantic.field_validator("backends")
    @classmethod
    def validate_backends_scheme(
        cls, value: tuple[pydantic.AnyHttpUrl, ...]
    ) -> tuple[pydantic.AnyHttpUrl, ...]:
        """Validate that all backends share the same URL scheme.

        Args:
            value: The backends tuple to validate.

        Raises:
            ValueError: Backends have mixed schemes.

        Returns:
            The value after validation.
        """
        if len(value) > 1:
            schemes = {url.scheme for url in value}
            if len(schemes) > 1:
                raise ValueError(
                    f"All backends must share the same scheme; found mixed schemes: {schemes}"
                )
        return value

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

    @pydantic.field_validator("cache_inactive")
    @classmethod
    def validate_cache_inactive(cls, value: str) -> str:
        """Validate the cache_inactive time string.

        Args:
            value: The nginx time string to validate.

        Raises:
            ValueError: The value is not a valid nginx time string.

        Returns:
            The validated value.
        """
        try:
            _check_nginx_time_str(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @pydantic.field_validator("cache_max_size")
    @classmethod
    def validate_cache_max_size(cls, value: str) -> str:
        """Validate the cache_max_size size string.

        Args:
            value: The nginx size string to validate (may be empty to mean no limit).

        Raises:
            ValueError: The value is not empty and not a valid nginx size string.

        Returns:
            The validated value, lowercased.
        """
        if not value:
            return value
        try:
            _check_nginx_size_str(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return value.lower()

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
        backends_str = typing.cast(str, charm.config.get(BACKENDS_CONFIG_NAME, "")).strip()
        if not backends_str:
            raise ConfigurationError("Empty backends configuration found")
        fail_timeout = typing.cast(str, charm.config.get(FAIL_TIMEOUT_CONFIG_NAME, "")).strip()
        proxy_cache_valid_str = typing.cast(
            str, charm.config.get(PROXY_CACHE_VALID_CONFIG_NAME, "")
        ).strip()

        backends = tuple(url.strip() for url in backends_str.split(","))
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

        healthcheck_config = HealthcheckConfig.from_charm(charm)

        cache_inactive = typing.cast(
            str, charm.config.get(CACHE_INACTIVE_CONFIG_NAME, "10m")
        ).strip()
        cache_max_size = typing.cast(str, charm.config.get(CACHE_MAX_SIZE_CONFIG_NAME, "")).strip()
        backend_hostname = typing.cast(
            str, charm.config.get(BACKEND_HOSTNAME_CONFIG_NAME, "")
        ).strip()
        backend_ca_fingerprint = typing.cast(
            str, charm.config.get(BACKEND_CA_FINGERPRINT_CONFIG_NAME, "")
        ).strip()

        try:
            # Ignore type check and let pydantic handle the type with validation errors.
            return cls(
                backends=backends,  # type: ignore
                fail_timeout=fail_timeout,
                proxy_cache_valid=proxy_cache_valid,  # type: ignore
                healthcheck=healthcheck_config,
                cache_inactive=cache_inactive,
                cache_max_size=cache_max_size,
                backend_hostname=backend_hostname,
                backend_ca_fingerprint=backend_ca_fingerprint,  # type: ignore
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

        to_expand = {key for key, value in data.items() if isinstance(value, dict)}
        for key in to_expand:
            data.update({f"{key}_{_key}": str(_value) for _key, _value in data[key].items()})
            data.pop(key)

        for key, value in data.items():
            if isinstance(value, str):
                if value in ["True", "False"]:
                    data[key] = value.lower()
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
    time_char = {"h", "m", "s", "d"}
    if not time_str or time_str[-1] not in time_char:
        raise ValueError(f"Invalid time for proxy_cache_valid: {time_str}")
    try:
        time = int(time_str[:-1])
    except ValueError as err:
        raise ValueError(f"Non-int time in proxy_cache_valid: {time_str}") from err

    if time < 1:
        raise ValueError(f"Time must be positive int for proxy_cache_valid: {time_str}")


def _check_nginx_size_str(size_str: str) -> None:
    """Check if nginx size string is valid.

    Valid format: positive integer followed by k, m, g, or t (case-insensitive).

    Args:
        size_str: The size string to validate.

    Raises:
        ValueError: The input is not a valid nginx size string.
    """
    if not size_str:
        raise ValueError("Size string must not be empty")
    unit = size_str[-1].lower()
    if unit not in {"k", "m", "g", "t"}:
        raise ValueError(f"Invalid size unit in {size_str!r}: must be k, m, g, or t")
    try:
        value = int(size_str[:-1])
    except ValueError as err:
        raise ValueError(f"Non-integer size value in {size_str!r}") from err
    if value < 1:
        raise ValueError(f"Size must be a positive integer in {size_str!r}")


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
