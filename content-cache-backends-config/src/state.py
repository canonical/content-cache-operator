# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The charm state and configurations."""

import json
import logging
import typing
from dataclasses import dataclass

import ops
import pydantic

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
BACKEND_HOSTNAME_CONFIG_NAME = "backend-hostname"
CACHE_INACTIVE_CONFIG_NAME = "cache-inactive"
CACHE_MAX_SIZE_CONFIG_NAME = "cache-max-size"


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
                f"{error['loc'][0]} = {error['input']}: {error['msg']}" for error in err.errors()
            ]
            logger.error("Found config error: %s", err_msg)
            raise ConfigurationError(f"Config error: {err_msg}") from err


@dataclass(frozen=True)
class Configuration:
    """Represents the configuration.

    Attributes:
        backends: The backends for this configuration as full URLs.
        fail_timeout: The time to wait before using a backend after failure.
        proxy_cache_valid: The cache valid duration.
        healthcheck: The healthcheck configuration.
        backend_hostname: Hostname used for backend SNI and Host header.
        cache_inactive: Time after which an unaccessed item is evicted from the disk cache.
        cache_max_size: Maximum total disk size for the cache; empty string means no limit.
    """

    backends: tuple[str, ...]
    fail_timeout: str
    proxy_cache_valid: tuple[str, ...]
    healthcheck: HealthcheckConfig
    backend_hostname: str | None
    cache_inactive: str
    cache_max_size: str

    @classmethod
    def from_charm(cls, charm: ops.CharmBase) -> "Configuration":
        """Parse configuration values from the charm.

        Args:
            charm: The charm containing the configuration.

        Raises:
            ConfigurationError: When a charm-specific representation cannot be parsed.

        Returns:
            The parsed configuration. Shared contract validation is deferred to the library.
        """
        backends_str = typing.cast(str, charm.config.get(BACKENDS_CONFIG_NAME, "")).strip()
        if not backends_str:
            raise ConfigurationError("Empty backends configuration found")

        proxy_cache_valid_str = typing.cast(
            str, charm.config.get(PROXY_CACHE_VALID_CONFIG_NAME, "")
        ).strip()
        try:
            proxy_cache_valid = json.loads(proxy_cache_valid_str) if proxy_cache_valid_str else []
        except json.JSONDecodeError as err:
            raise ConfigurationError(
                f"Unable to parse proxy_cache_valid: {proxy_cache_valid_str}"
            ) from err
        if not isinstance(proxy_cache_valid, list):
            raise ConfigurationError(
                f"The proxy_cache_valid is not a list: {proxy_cache_valid_str}"
            )

        return cls(
            backends=tuple(url.strip() for url in backends_str.split(",")),
            fail_timeout=typing.cast(str, charm.config.get(FAIL_TIMEOUT_CONFIG_NAME, "")).strip(),
            proxy_cache_valid=tuple(proxy_cache_valid),
            healthcheck=HealthcheckConfig.from_charm(charm),
            backend_hostname=typing.cast(
                str, charm.config.get(BACKEND_HOSTNAME_CONFIG_NAME, "")
            ).strip()
            or None,
            cache_inactive=typing.cast(
                str, charm.config.get(CACHE_INACTIVE_CONFIG_NAME, "10m")
            ).strip()
            or "10m",
            cache_max_size=typing.cast(
                str, charm.config.get(CACHE_MAX_SIZE_CONFIG_NAME, "")
            ).strip(),
        )

    def to_cache_config_kwargs(self) -> dict[str, typing.Any]:
        """Flatten this local configuration for ``publish_cache_config``.

        Returns:
            Keyword arguments accepted by ``CacheConfigRequirer.publish_cache_config``.
        """
        return {
            "backends": list(self.backends),
            "fail_timeout": self.fail_timeout,
            "healthcheck_interval": self.healthcheck.interval,
            "healthcheck_path": self.healthcheck.path,
            "healthcheck_valid_status": list(self.healthcheck.valid_status),
            "healthcheck_ssl_verify": self.healthcheck.ssl_verify,
            "proxy_cache_valid": list(self.proxy_cache_valid),
            "backend_hostname": self.backend_hostname,
            "cache_inactive": self.cache_inactive,
            "cache_max_size": self.cache_max_size,
        }
