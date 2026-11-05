# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""cache-config interface library, requirer side.

Implements the requirer side of the ``cache-config`` interface, used to configure a
[content-cache](https://charmhub.io/content-cache) deployment with backend origins,
healthcheck parameters and caching rules, and to read back the URL content-cache serves
on.
"""

import dataclasses
import ipaddress
import json
import logging
import typing

import ops
from ops.framework import Object
from ops.model import RelationDataTypeError
from pydantic import (
    AfterValidator,
    AnyHttpUrl,
    Field,
    TypeAdapter,
    ValidationError,
    model_validator,
)
from pydantic.dataclasses import dataclass

from cache_config._validators import (
    _URL_ADAPTER,
    _MAX_STATUS_CODE,
    _MIN_STATUS_CODE,
    validate_hostname,
    validate_http_url,
    validate_nginx_size,
    validate_nginx_time,
    validate_path,
    validate_proxy_cache_valid,
)
from cache_config.errors import CacheConfigInvalidRelationDataError, InvalidCacheBackendsDataError

logger = logging.getLogger(__name__)

CACHE_CONFIG_RELATION_NAME = "cache-config"
CACHE_BACKEND_FIELD_NAME = "cache-backend"


def _encode(value: typing.Any) -> str:
    """Encode a field value for the cache-config databag.

    Strings are written as-is because content-cache reads them raw; None is encoded as the
    empty string, which erases the key from the databag, whereas the JSON literal ``null``
    would be written through and accepted by content-cache as a legitimate value;
    everything else is JSON encoded.

    Args:
        value: The value to encode.

    Returns:
        The databag representation of the value.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _decode(value: str) -> typing.Any:
    """Decode a field value from the cache-config databag.

    Args:
        value: The raw databag value.

    Returns:
        The JSON-decoded value, or the raw string when it is not valid JSON.
    """
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


_Backend = typing.Annotated[str, AfterValidator(validate_http_url)]
_StatusCode = typing.Annotated[int, Field(ge=_MIN_STATUS_CODE, le=_MAX_STATUS_CODE)]
_ProxyCacheValid = typing.Annotated[str, AfterValidator(validate_proxy_cache_valid)]


@dataclass(frozen=True)
class CacheConfigRequirerAppData:
    """Requirer application databag schema.

    Attributes:
        backends: Backend URLs content-cache proxies to. All must share one scheme.
        fail_timeout: Time before a backend is considered unavailable after a failure.
        healthcheck_interval: Time between two healthchecks, in milliseconds.
        healthcheck_path: The path checked on the backends.
        healthcheck_valid_status: HTTP status codes considered healthy.
        healthcheck_ssl_verify: Whether to verify backend TLS certificates when checking.
        proxy_cache_valid: nginx cache validity rules. Empty means no rules are emitted.
        backend_hostname: SNI hostname for backend TLS. Required for https backends.
        cache_inactive: Time after which an unaccessed cached item is evicted from disk.
        cache_max_size: Maximum total disk space used by the cache. Empty means no limit.
    """

    backends: typing.Annotated[list[_Backend], Field(min_length=1)]
    fail_timeout: typing.Annotated[str, AfterValidator(validate_nginx_time)]
    healthcheck_interval: typing.Annotated[int, Field(gt=0)]
    healthcheck_path: typing.Annotated[str, AfterValidator(validate_path)]
    healthcheck_valid_status: typing.Annotated[list[_StatusCode], Field(min_length=1)]
    healthcheck_ssl_verify: bool
    proxy_cache_valid: list[_ProxyCacheValid]
    backend_hostname: typing.Annotated[str, AfterValidator(validate_hostname)] | None = None
    cache_inactive: typing.Annotated[str, AfterValidator(validate_nginx_time)] = "10m"
    cache_max_size: typing.Annotated[str, AfterValidator(validate_nginx_size)] = ""

    @model_validator(mode="after")
    def _validate_backends_and_hostname(self) -> "CacheConfigRequirerAppData":
        """Validate that backends share one scheme and https backends have a hostname.

        Raises:
            ValueError: When schemes are mixed, or https backends have no hostname.

        Returns:
            The validated model.
        """
        schemes = {_URL_ADAPTER.validate_python(backend).scheme for backend in self.backends}
        if len(schemes) > 1:
            raise ValueError(f"All backends must share the same scheme, found: {sorted(schemes)}")
        if schemes == {"https"} and not self.backend_hostname:
            raise ValueError("backend_hostname is required for https backends")
        return self


@dataclass(frozen=True)
class CacheConfigProviderUnitData:
    """Provider unit databag schema.

    Attributes:
        cache_backend: The URL content-cache serves this relation on.
    """

    cache_backend: typing.Annotated[AnyHttpUrl, Field(alias=CACHE_BACKEND_FIELD_NAME)] = (
        dataclasses.field(metadata={"alias": CACHE_BACKEND_FIELD_NAME})
    )

    @model_validator(mode="after")
    def _validate_cache_backend(self) -> "CacheConfigProviderUnitData":
        """Validate the cache backend URL."""
        if self.cache_backend.port is None or not (0 < self.cache_backend.port <= 65535):
            raise ValueError(f"Invalid cache backend port: {self.cache_backend.port}")
        ipaddress.ip_address(str(self.cache_backend.host).removeprefix("[").removesuffix("]"))
        return self

    @property
    def cache_backend_host(self) -> str:
        """Return the cache backend host, with IPv6 brackets removed."""
        # IP address validation should already be handled by the model validator.
        host = str(self.cache_backend.host).removeprefix("[").removesuffix("]")
        return str(ipaddress.ip_address(host))


@dataclass(frozen=True)
class CacheConfigProviderUnitsData:
    """Provider units databag.

    Attributes:
        cache_backends: The URL content-cache serves this relation on.
    """

    cache_backends: list[CacheConfigProviderUnitData]

    @property
    def cache_backend_hosts(self) -> list[str]:
        """Return cache backend hosts without IPv6 brackets."""
        return [backend.cache_backend_host for backend in self.cache_backends]

    @property
    def cache_backend_ports(self) -> list[int]:
        """Return cache backend ports."""
        return list({backend.cache_backend.port for backend in self.cache_backends})

    @model_validator(mode="after")
    def validate_cache_protocol(self) -> "CacheConfigProviderUnitsData":
        """Validate the cache backend protocols."""
        if not self.cache_backends:
            return self

        if len({backend.cache_backend.scheme for backend in self.cache_backends}) > 1:
            raise ValueError("Inconsistent cache backend protocols")
        return self


class CacheConfigRequirer(Object):
    """cache-config interface requirer implementation."""

    def __init__(
        self,
        charm: ops.CharmBase,
        relation_name: str = CACHE_CONFIG_RELATION_NAME,
    ) -> None:
        """Initialize the CacheConfigRequirer.

        Args:
            charm: The charm instance using this library.
            relation_name: The name of the relation endpoint.
        """
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name

    @property
    def relation(self) -> ops.Relation | None:
        """The relation instance for this endpoint.

        The endpoint is expected to be declared with ``limit: 1``. Without it,
        :meth:`ops.Model.get_relation` raises :class:`ops.TooManyRelatedAppsError` when
        more than one application is related, which this library does not handle.
        """
        return self.charm.model.get_relation(self.relation_name)

    def publish_cache_config(
        self,
        *,
        backends: list[str],
        fail_timeout: str,
        healthcheck_interval: int,
        healthcheck_path: str,
        healthcheck_valid_status: list[int],
        healthcheck_ssl_verify: bool,
        proxy_cache_valid: list[str],
        backend_hostname: str | None = None,
        cache_inactive: str = "10m",
        cache_max_size: str = "",
    ) -> None:
        """Publish the cache configuration to the provider.

        Does nothing when the relation is absent or the unit is not the leader, since
        only the leader may write to the application databag.

        Args:
            backends: Backend URLs content-cache proxies to.
            fail_timeout: Time before a backend is considered unavailable after failure.
            healthcheck_interval: Time between two healthchecks, in milliseconds.
            healthcheck_path: The path checked on the backends.
            healthcheck_valid_status: HTTP status codes considered healthy.
            healthcheck_ssl_verify: Whether to verify backend TLS certificates.
            proxy_cache_valid: nginx cache validity rules.
            backend_hostname: SNI hostname for backend TLS verification.
            cache_inactive: Time after which an unaccessed cached item is evicted.
            cache_max_size: Maximum total disk space used by the cache.

        Raises:
            CacheConfigInvalidRelationDataError: When the data fails validation or
                cannot be written to the databag.
        """
        if not (relation := self.relation) or not self.charm.unit.is_leader():
            return

        try:
            app_data = CacheConfigRequirerAppData(
                backends=backends,
                fail_timeout=fail_timeout,
                healthcheck_interval=healthcheck_interval,
                healthcheck_path=healthcheck_path,
                healthcheck_valid_status=healthcheck_valid_status,
                healthcheck_ssl_verify=healthcheck_ssl_verify,
                proxy_cache_valid=proxy_cache_valid,
                backend_hostname=backend_hostname,
                cache_inactive=cache_inactive,
                cache_max_size=cache_max_size,
            )
            relation.save(app_data, self.charm.app, encoder=_encode)
        except (ValidationError, RelationDataTypeError) as exc:
            raise CacheConfigInvalidRelationDataError(
                "Failed to publish cache-config requirer data."
            ) from exc

    def get_provider_units_data(self) -> CacheConfigProviderUnitsData:
        """Fetch the cache backend URLs published by the provider units.

        Invalid or unpublished units data are skipped.

        The URLs are returned parsed and normalized by pydantic, so the string form may
        differ from what the provider wrote: a trailing slash is added and default ports
        are dropped. Callers should use ``.scheme``, ``.host`` and ``.port`` rather than
        the string form.

        Returns:
            The cache backend URLs.
        """
        if not (relation := self.relation):
            return CacheConfigProviderUnitsData([])

        cache_backends: list[CacheConfigProviderUnitData] = []
        for unit in relation.units:
            try:
                unit_data = relation.load(CacheConfigProviderUnitData, unit, decoder=_decode)
            except ValidationError:
                logger.exception(
                    f"Invalid {CACHE_BACKEND_FIELD_NAME} published by {unit.name}. skipping."
                )
                continue
            cache_backends.append(unit_data)
        try:
            return CacheConfigProviderUnitsData(cache_backends)
        except ValidationError:
            raise InvalidCacheBackendsDataError("Invalid cache backends data.")
