# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The charm state and configurations."""

import json
import logging
import typing

import ops

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
CACHE_INACTIVE_FIELD_NAME = "cache_inactive"
CACHE_MAX_SIZE_FIELD_NAME = "cache_max_size"


def configuration_from_charm(charm: ops.CharmBase) -> dict[str, typing.Any]:
    """Read this charm's config into cache_config.CacheConfigRequirer.publish_cache_config kwargs.

    Only parses the charm config's own shape (comma-separated lists, JSON-encoded lists,
    int/bool coercion). Field-level validation of the resulting values (nginx time/size
    formats, backend-hostname-required-for-https, status code ranges, etc.) is left to the
    cache_config library, which is shared with content-cache (the provider reading this same
    data) and so is the single source of truth for what is a valid value.

    Args:
        charm: The charm containing the configuration.

    Raises:
        ConfigurationError: The charm config cannot be parsed into the shape
            publish_cache_config() expects (e.g. backends is empty, or proxy-cache-valid
            is not valid JSON or not a list).

    Returns:
        Kwargs ready to pass to CacheConfigRequirer.publish_cache_config(**kwargs).
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
        raise ConfigurationError(f"The proxy_cache_valid is not a list: {proxy_cache_valid_str}")

    valid_status_str = typing.cast(
        str, charm.config.get(HEALTHCHECK_VALID_STATUS_CONFIG_NAME, "")
    ).strip()
    try:
        healthcheck_valid_status = [int(status) for status in valid_status_str.split(",")]
    except ValueError as err:
        raise ConfigurationError(
            f"Unable to parse healthcheck_valid_status: {valid_status_str}"
        ) from err

    try:
        healthcheck_interval = int(charm.config.get(HEALTHCHECK_INTERVAL_CONFIG_NAME, -1))
    except (TypeError, ValueError) as err:
        raise ConfigurationError(
            f"Unable to parse healthcheck_interval: "
            f"{charm.config.get(HEALTHCHECK_INTERVAL_CONFIG_NAME)}"
        ) from err

    return {
        "backends": [url.strip() for url in backends_str.split(",")],
        "fail_timeout": typing.cast(str, charm.config.get(FAIL_TIMEOUT_CONFIG_NAME, "")).strip(),
        "healthcheck_interval": healthcheck_interval,
        "healthcheck_path": typing.cast(
            str, charm.config.get(HEALTHCHECK_PATH_CONFIG_NAME, "")
        ).strip(),
        "healthcheck_valid_status": healthcheck_valid_status,
        "healthcheck_ssl_verify": bool(
            charm.config.get(HEALTHCHECK_SSL_VERIFY_CONFIG_NAME, False)
        ),
        "proxy_cache_valid": proxy_cache_valid,
        "backend_hostname": typing.cast(
            str, charm.config.get(BACKEND_HOSTNAME_CONFIG_NAME, "")
        ).strip()
        or None,
        "cache_inactive": typing.cast(
            str, charm.config.get(CACHE_INACTIVE_CONFIG_NAME, "10m")
        ).strip()
        or "10m",
        "cache_max_size": typing.cast(
            str, charm.config.get(CACHE_MAX_SIZE_CONFIG_NAME, "")
        ).strip(),
    }
