# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The charm state and configurations."""

import ipaddress
import logging
import typing

import ops
import pydantic

from cache_config.v0 import (
    CacheConfigProvider,
    CacheConfigRelationDataError,
    CacheConfigRequirerAppData,
    parse_requirer_app_data,
)
from errors import ConfigurationError, IntegrationDataError

logger = logging.getLogger(__name__)

CACHE_CONFIG_INTEGRATION_NAME = "cache-config"
CLIENT_IP_HASH_SALT_CONFIG_NAME = "client-ip-hash-salt"

_URL_ADAPTER: pydantic.TypeAdapter[pydantic.AnyHttpUrl] = pydantic.TypeAdapter(pydantic.AnyHttpUrl)

_SALT_DISALLOWED_CHARACTERS = frozenset({'"', "\\", "$"})

PORT_MAP_FIELD = "port-map"
NEXT_OFFSET_FIELD = "next-offset"


class PeerData(pydantic.BaseModel):
    """Content-cache peer application databag write schema."""

    model_config = pydantic.ConfigDict(populate_by_name=True)

    port_map: dict[str, int] = pydantic.Field(alias=PORT_MAP_FIELD)  # type: ignore[literal-required]
    next_offset: int = pydantic.Field(alias=NEXT_OFFSET_FIELD)  # type: ignore[literal-required]


def get_client_ip_hash_salt(charm: ops.CharmBase) -> str | None:
    """Return and validate the configured client IP hash salt.

    Args:
        charm: The charm to read configuration from.

    Raises:
        ConfigurationError: The salt secret is missing, inaccessible, or contains an
            invalid value.

    Returns:
        The salt string, or None if client IP hashing is not enabled.
    """
    secret_uri = typing.cast("str | None", charm.config.get(CLIENT_IP_HASH_SALT_CONFIG_NAME))
    if secret_uri is None:
        return None
    if not secret_uri.strip():
        raise ConfigurationError(
            f"The {CLIENT_IP_HASH_SALT_CONFIG_NAME} config must reference a valid secret URI, "
            "not a blank value."
        )

    try:
        secret_content = charm.model.get_secret(id=secret_uri).get_content(refresh=True)
    except (ops.SecretNotFoundError, ops.ModelError) as exc:
        raise ConfigurationError(
            f"The {CLIENT_IP_HASH_SALT_CONFIG_NAME} secret does not exist or cannot be accessed."
        ) from exc

    salt = secret_content.get("salt")
    if not isinstance(salt, str) or not salt.strip():
        raise ConfigurationError(
            f"The {CLIENT_IP_HASH_SALT_CONFIG_NAME} secret must contain a non-empty 'salt' value."
        )
    if any(
        character in _SALT_DISALLOWED_CHARACTERS or ord(character) < 32 or ord(character) == 127
        for character in salt
    ):
        raise ConfigurationError(
            f"The {CLIENT_IP_HASH_SALT_CONFIG_NAME} secret must not contain control "
            "characters, double quotes, backslashes, or dollar signs."
        )
    return salt


def is_client_ip_hash_salt_secret(charm: ops.CharmBase, secret_id: str) -> bool:
    """Check whether a secret ID is the configured client-ip-hash-salt secret.

    Args:
        charm: The charm to read configuration from.
        secret_id: The ID of the secret to check (e.g. from a SecretChangedEvent).

    Returns:
        True if secret_id refers to the secret configured as client-ip-hash-salt,
        False otherwise (including when the configured secret cannot be resolved).
    """
    secret_uri = typing.cast("str | None", charm.config.get(CLIENT_IP_HASH_SALT_CONFIG_NAME))
    if not secret_uri:
        return False
    try:
        return charm.model.get_secret(id=secret_uri).id == secret_id
    except (ops.SecretNotFoundError, ops.ModelError):
        return False


class HealthcheckConfig(pydantic.BaseModel):
    """Represents the configuration for healthchecks.

    Attributes:
        interval: The time between two healthchecks, in milliseconds.
        path: The path to check on the backends for health.
        valid_status: HTTP status codes considered as valid during health checks.
        ssl_verify: Should we check SSL certificates during health checks.
    """

    model_config = pydantic.ConfigDict(frozen=True)

    interval: int
    path: str
    valid_status: tuple[int, ...]
    ssl_verify: bool


class LocationConfig(pydantic.BaseModel):
    """Represents the configuration for a location.

    Attributes:
        backends: The backend URLs for this configuration.
        fail_timeout: The time to wait before using a backend after failure.
        proxy_cache_valid: The cache valid duration.
        healthcheck_config: The healthcheck configuration.
        backend_hostname: Hostname used for backend SNI, Host header, and (combined with the
            port) as the nginx log filename stem.
        cache_inactive: Time after which an unaccessed item is evicted from the disk cache.
        cache_max_size: Maximum total disk size for the cache; empty string means no limit.
    """

    model_config = pydantic.ConfigDict(frozen=True)

    backends: tuple[pydantic.AnyHttpUrl, ...]
    fail_timeout: str
    proxy_cache_valid: tuple[str, ...]
    healthcheck_config: HealthcheckConfig
    backend_hostname: str = ""
    cache_inactive: str = "10m"
    cache_max_size: str = ""

    @classmethod
    def from_integration_data(cls, data: typing.Mapping[str, str]) -> "LocationConfig":
        """Build a LocationConfig from raw cache-config relation data.

        Decodes and validates using the cache_config library, so the wire format is
        understood in one place rather than duplicated here.

        Args:
            data: Raw relation data (e.g. ``ops.RelationDataContent`` or a plain dict),
                keyed by the same field names ``CacheConfigRequirerAppData`` uses.

        Raises:
            IntegrationDataError: The data fails the library's validation.

        Returns:
            The equivalent LocationConfig.
        """
        try:
            app_data = parse_requirer_app_data(data)
        except pydantic.ValidationError as exc:
            raise IntegrationDataError(str(exc)) from exc
        return _to_location_config(app_data)


def _to_location_config(data: CacheConfigRequirerAppData) -> LocationConfig:
    """Convert validated cache-config requirer data into nginx_manager's rendering shape.

    Args:
        data: The validated requirer app data for one relation.

    Returns:
        The equivalent LocationConfig.

    Raises:
        IntegrationDataError: The data cannot be converted into a LocationConfig.
    """
    try:
        return LocationConfig(
            backends=tuple(_URL_ADAPTER.validate_python(backend) for backend in data.backends),
            fail_timeout=data.fail_timeout,
            proxy_cache_valid=tuple(data.proxy_cache_valid),
            healthcheck_config=HealthcheckConfig(
                interval=data.healthcheck_interval,
                path=data.healthcheck_path,
                valid_status=tuple(data.healthcheck_valid_status),
                ssl_verify=data.healthcheck_ssl_verify,
            ),
            backend_hostname=data.backend_hostname or "",
            cache_inactive=data.cache_inactive,
            cache_max_size=data.cache_max_size,
        )
    except pydantic.ValidationError as exc:
        raise IntegrationDataError(str(exc)) from exc


RelationId = int
NginxConfig = dict[RelationId, LocationConfig]


def get_nginx_config(cache_config: CacheConfigProvider) -> NginxConfig:
    """Get the nginx locations configuration from cache-config integration data.

    Args:
        cache_config: The charm's CacheConfigProvider instance.

    Raises:
        IntegrationDataError: Invalid cache configurations in integration data.

    Returns:
        A mapping of relation ID to location configuration.
    """
    try:
        requirers_data = cache_config.get_requirers_data()
    except CacheConfigRelationDataError as err:
        raise IntegrationDataError(str(err)) from err

    if not requirers_data:
        logger.info("Found no configuration integrations")

    return {rel_id: _to_location_config(data) for rel_id, data in requirers_data.items()}


def get_cache_backend_url(
    charm: ops.CharmBase,
    relation: ops.Relation,
    port: int,
    has_cache_cert: bool = False,
) -> str:
    """Return the cache-backend URL for a given relation and port.

    Args:
        charm: The charm instance used to look up the binding address.
        relation: The relation to get the binding address for.
        port: The nginx listening port allocated for this relation.
        has_cache_cert: Whether a TLS termination cert is present, determines
            whether to use https or http in the returned URL.

    Returns:
        A URL in the form protocol://ip:port. IPv6 addresses are bracketed.
    """
    bind_address = charm.model.get_binding(relation).network.bind_address
    if isinstance(bind_address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = bind_address
    else:
        ip = ipaddress.ip_address(str(bind_address).strip())
    host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    protocol = "https" if has_cache_cert else "http"
    return f"{protocol}://{host}:{port}"
