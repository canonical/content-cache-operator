# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Cache-config interface library.

This library implements both sides of the `content-cache-config` interface. Requirer charms
publish backend origins, healthcheck parameters, and caching rules. The content-cache provider
reads this configuration and publishes the URL that serves each relation.

## Getting Started

This library is distributed as a Python package from the content-cache operator repository.
Add a commit-pinned git dependency to the requirer charm with UV:

```shell
repository="git+https://github.com/canonical/content-cache-operator.git@<commit>"
uv add "${repository}#subdirectory=libs/cache-config"
```

The charm's `uv.lock` records the resolved commit. External consumers must include `git` in
the charm part's build packages so Charmcraft can install the dependency during packing. See
[Manage git dependencies](https://canonical.com/juju/docs/charmlibs/how-to/manage-libraries/#manage-git-dependencies)
for the complete workflow.

In the `metadata.yaml` of the requirer charm, add the following:

```yaml
requires:
    cache-config:
        interface: content-cache-config
        limit: 1
```

Then, initialise the requirer and publish the cache configuration whenever the backend
configuration changes. The library does not register event observers itself, so publish on
config changes, leader election, and relation creation as well:

```python
import ops

from cache_config.v0 import (
    CACHE_CONFIG_RELATION_NAME,
    CacheConfigRequirer,
    InvalidCacheBackendsDataError,
)


class SomeCharm(ops.CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.cache_config = CacheConfigRequirer(self)
        self.framework.observe(self.on.config_changed, self._publish_cache_config)
        self.framework.observe(self.on.leader_elected, self._publish_cache_config)
        self.framework.observe(
            self.on[CACHE_CONFIG_RELATION_NAME].relation_created,
            self._publish_cache_config,
        )
        self.framework.observe(
            self.on[CACHE_CONFIG_RELATION_NAME].relation_changed,
            self._on_cache_config_relation_changed,
        )

    def _publish_cache_config(self, _: ops.EventBase) -> None:
        self.cache_config.publish_cache_config(
            backends=["http://10.0.0.1:80"],
            fail_timeout="30s",
            healthcheck_interval=2000,
            healthcheck_path="/",
            healthcheck_valid_status=[200],
            healthcheck_ssl_verify=True,
            proxy_cache_valid=["200 1h"],
        )

    def _on_cache_config_relation_changed(self, _: ops.RelationChangedEvent) -> None:
        try:
            provider_data = self.cache_config.get_provider_units_data()
        except InvalidCacheBackendsDataError:
            # At least one provider unit has not published its URL yet. Wait for the
            # next relation-changed event instead of failing the hook.
            pass
        else:
            cache_backend_hosts = provider_data.cache_backend_hosts
            cache_backend_ports = provider_data.cache_backend_ports
```

`publish_cache_config` validates the data before writing it to the application databag. It
does nothing when the relation is absent or the unit is not the leader.

## Using the library as the provider

The provider charm should expose the interface as shown below:

```yaml
provides:
    cache-config:
        interface: content-cache-config
```

The provider supports multiple requirer applications. Initialise `CacheConfigProvider`, read
the validated configuration for each relation, and publish the cache backend URL for that
relation:

```python
from ops import CharmBase

from cache_config.v0 import CacheConfigProvider


class ContentCacheCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.cache_config = CacheConfigProvider(self)

    def _reconcile(self) -> None:
        for relation_id, configuration in self.cache_config.get_requirers_data().items():
            cache_backend_url = self._configure_backend(configuration)
            self.cache_config.publish_cache_backend(relation_id, cache_backend_url)
```

## Maintaining this library

This file is the single source of truth; do not add vendored copies. The charms in this
monorepo install the package from `libs/cache-config` through a local UV source, while external
charms use a commit-pinned git dependency. Increment `LIBPATCH` for a backwards-compatible
change and the package's major version together with `LIBAPI` for a breaking change.
"""

import dataclasses
import ipaddress
import json
import logging
import re
import typing

import ops
from ops.framework import Object
from ops.model import RelationDataTypeError
from pydantic import (
    AfterValidator,
    AnyHttpUrl,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    model_validator,
)
from pydantic.dataclasses import dataclass

# Interface API/patch version. The distribution version lives in pyproject.toml.
LIBAPI = 0
LIBPATCH = 0

logger = logging.getLogger(__name__)

CACHE_CONFIG_RELATION_NAME = "cache-config"
_CACHE_BACKEND_FIELD_NAME = "cache-backend"

_DEFAULT_CACHE_INACTIVE = "10m"
_DEFAULT_CACHE_MAX_SIZE = ""

_MIN_STATUS_CODE = 100
_MAX_STATUS_CODE = 999

# nginx's ngx_parse_time/ngx_parse_size accept only ASCII digits. \d also matches
# Unicode decimal digits, which int() accepts but nginx rejects, so use [0-9] to match
# the removed backend-config _DIGITS_PATTERN.
_NGINX_TIME_PATTERN = re.compile(r"[0-9]+[dhms]")
_NGINX_SIZE_PATTERN = re.compile(r"[0-9]+[kmgKMG]")
# Flags included, so that this library rejects exactly what the provider rejects. It is
# deliberately not an RFC 3986 path grammar: percent-encoding is not accepted, and
# Python's \w is Unicode-aware.
_PATH_PATTERN = re.compile(r"[/\w.\-~!$&'()*+,;=:@]+", re.IGNORECASE)
# The trailing $ is redundant under fullmatch, but is kept so the pattern stays
# byte-identical to the provider's historical one.
_HOSTNAME_SEGMENT_PATTERN = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
_URL_ADAPTER: TypeAdapter[AnyHttpUrl] = TypeAdapter(AnyHttpUrl)


class CacheConfigError(Exception):
    """Base error for the cache-config interface library."""


class CacheConfigInvalidRelationDataError(CacheConfigError):
    """Raised when cache-config relation data fails validation on write (requirer side)."""


class InvalidCacheBackendDataError(CacheConfigError):
    """Raised when a cache-backend URL is invalid on publication."""


class InvalidCacheBackendsDataError(CacheConfigError):
    """Raised when the provider units' cache_backend data is invalid as a whole."""


class CacheConfigIntegrationDataError(CacheConfigError):
    """Raised when a requirer's app databag fails validation (provider side)."""


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

    Only list fields are JSON encoded on the wire. Scalars stay raw so that a string such
    as a numeric hostname is not silently converted to a different type; Pydantic coerces
    raw booleans and integers for their declared fields.

    Args:
        value: The raw databag value.

    Returns:
        The decoded list, or the raw string for every other value.
    """
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return value
    return decoded if isinstance(decoded, list) else value


def _validate_nginx_time(value: str) -> str:
    """Validate an nginx time string, for example "30s".

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the value is not a positive integer followed by d, h, m or s.

    Returns:
        The validated value.
    """
    if not _NGINX_TIME_PATTERN.fullmatch(value) or int(value[:-1]) < 1:
        raise ValueError(
            f"Time must be a positive integer followed by d, h, m or s, got: {value!r}"
        )
    return value


def _validate_nginx_size(value: str) -> str:
    """Validate an nginx size string, for example "512m".

    The empty string means "no limit" and is accepted unchanged, mirroring content-cache's
    handling of an unset ``cache_max_size``.

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the value is non-empty and not a positive integer followed by
            k, m or g (case-insensitive).

    Returns:
        The validated value.
    """
    if not value:
        return value
    if not _NGINX_SIZE_PATTERN.fullmatch(value) or int(value[:-1]) < 1:
        raise ValueError(f"Size must be a positive integer followed by k, m or g, got: {value!r}")
    return value


def _validate_http_url(value: str) -> str:
    """Validate that the value is an HTTP or HTTPS URL.

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the value is not a valid HTTP(S) URL.

    Returns:
        The validated value.
    """
    try:
        _URL_ADAPTER.validate_python(value)
    except ValidationError as exc:
        raise ValueError(f"Invalid backend URL: {value!r}") from exc
    return value


def _validate_path(value: str) -> str:
    """Validate a URL path against the characters content-cache accepts.

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the value is empty or contains disallowed characters.

    Returns:
        The validated value.
    """
    if not value or _PATH_PATTERN.fullmatch(value) is None:
        raise ValueError(f"Path contains non-allowed character: {value!r}")
    return value


def _validate_hostname(value: str) -> str:
    """Validate a hostname against the rules content-cache applies.

    The empty string is accepted and returned unchanged, mirroring content-cache's
    ``_validate_optional_hostname_value``: a caller passing ``""`` means "unset", not a
    malformed hostname. Like None, it erases the key from the databag once encoded.

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the hostname is too long or has an invalid segment.

    Returns:
        The validated value.
    """
    if not value:
        return value
    if len(value) > 255:
        raise ValueError(f"Hostname cannot be longer than 255 characters: {value!r}")
    for segment in value.split("."):
        if _HOSTNAME_SEGMENT_PATTERN.fullmatch(segment) is None:
            raise ValueError(
                "Each hostname segment must be at most 63 characters and consist of "
                f"alphanumeric characters and hyphens: {value!r}"
            )
    return value


def _validate_proxy_cache_valid(value: str) -> str:
    """Validate a proxy_cache_valid entry, for example "200 301 1h".

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the entry has no status code, or an invalid code or time.

    Returns:
        The validated value.
    """
    # split(" ") rather than split(): content-cache splits on a single space, so an entry
    # like "200  1h" is rejected there. Splitting on arbitrary whitespace here would accept
    # it and move the failure to the remote charm.
    tokens = value.split(" ")
    if len(tokens) < 2:
        raise ValueError(
            f"proxy_cache_valid requires at least one status code and a time: {value!r}"
        )
    status_codes, time_str = tokens[:-1], tokens[-1]
    # int() mirrors content-cache's _check_status_code, which means nginx's "any" keyword
    # ("proxy_cache_valid any 1h") is unsupported by the provider and so rejected here too.
    for code_str in status_codes:
        try:
            code = int(code_str)
        except ValueError as exc:
            raise ValueError(
                f"Non-integer status code in proxy_cache_valid: {code_str!r}"
            ) from exc
        if code < _MIN_STATUS_CODE or code > _MAX_STATUS_CODE:
            raise ValueError(f"Invalid status code in proxy_cache_valid: {code}")
    _validate_nginx_time(time_str)
    return value


_Backend = typing.Annotated[str, AfterValidator(_validate_http_url)]
_StatusCode = typing.Annotated[int, Field(ge=_MIN_STATUS_CODE, le=_MAX_STATUS_CODE)]
_ProxyCacheValid = typing.Annotated[str, AfterValidator(_validate_proxy_cache_valid)]


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
    fail_timeout: typing.Annotated[str, AfterValidator(_validate_nginx_time)]
    healthcheck_interval: typing.Annotated[int, Field(gt=0)]
    healthcheck_path: typing.Annotated[str, AfterValidator(_validate_path)]
    healthcheck_valid_status: typing.Annotated[list[_StatusCode], Field(min_length=1)]
    healthcheck_ssl_verify: bool
    proxy_cache_valid: list[_ProxyCacheValid]
    backend_hostname: typing.Annotated[str, AfterValidator(_validate_hostname)] | None = None
    cache_inactive: typing.Annotated[str, AfterValidator(_validate_nginx_time)] = (
        _DEFAULT_CACHE_INACTIVE
    )
    cache_max_size: typing.Annotated[str, AfterValidator(_validate_nginx_size)] = (
        _DEFAULT_CACHE_MAX_SIZE
    )

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
        cache_backend_host: The cache backend host without IPv6 brackets.
    """

    # ops reads the Juju key from the dataclass field metadata, while pydantic reads it
    # from the annotation, so the alias has to be declared in both places.
    cache_backend: typing.Annotated[AnyHttpUrl, Field(alias=_CACHE_BACKEND_FIELD_NAME)] = (
        dataclasses.field(metadata={"alias": _CACHE_BACKEND_FIELD_NAME})
    )

    # Allow construction by field name as well as by the Juju databag alias.
    __pydantic_config__ = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def _validate_cache_backend(self) -> "CacheConfigProviderUnitData":
        """Validate the cache backend URL."""
        if self.cache_backend.port is None or not (0 < self.cache_backend.port <= 65535):
            raise ValueError(f"Invalid cache backend port: {self.cache_backend.port}")
        host = str(self.cache_backend.host).removeprefix("[").removesuffix("]")
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError(
                f"Invalid cache backend host, expected an IP address: {host!r}"
            ) from exc
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
        cache_backend_hosts: The cache backend hosts without IPv6 brackets.
        cache_backend_ports: The unique cache backend ports.
    """

    cache_backends: list[CacheConfigProviderUnitData]

    @property
    def cache_backend_hosts(self) -> list[str]:
        """Return cache backend hosts without IPv6 brackets."""
        return [backend.cache_backend_host for backend in self.cache_backends]

    @property
    def cache_backend_ports(self) -> list[int]:
        """Return cache backend ports."""
        return sorted(
            {typing.cast(int, backend.cache_backend.port) for backend in self.cache_backends}
        )

    @model_validator(mode="after")
    def validate_cache_protocol(self) -> "CacheConfigProviderUnitsData":
        """Validate the cache backend protocols.

        Raises:
            ValueError: When cache backends use different protocols.

        Returns:
            The validated provider units data.
        """
        if not self.cache_backends:
            return self

        if len({backend.cache_backend.scheme for backend in self.cache_backends}) > 1:
            raise ValueError("Inconsistent cache backend protocols")
        return self


def parse_requirer_app_data(data: typing.Mapping[str, str]) -> CacheConfigRequirerAppData:
    """Decode and validate a requirer application databag.

    Args:
        data: Raw relation data keyed by ``CacheConfigRequirerAppData`` field names.

    Returns:
        The validated requirer application data.
    """
    return CacheConfigRequirerAppData(**{key: _decode(value) for key, value in data.items()})


class CacheConfigRequirer(Object):
    """cache-config interface requirer implementation.

    Attributes:
        charm: The charm instance using this library.
        relation_name: The relation endpoint name.
        relation: The relation instance for this endpoint, if present.
    """

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
        cache_inactive: str = _DEFAULT_CACHE_INACTIVE,
        cache_max_size: str = _DEFAULT_CACHE_MAX_SIZE,
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
                f"Failed to publish cache-config requirer data: {exc}"
            ) from exc

    def get_provider_units_data(self) -> CacheConfigProviderUnitsData:
        """Fetch the cache backend URLs published by the provider units.

        Every published unit must be valid. A partially valid set is rejected rather than
        silently used, since dropping one provider unit would remove it from the routing
        target set and black-hole its share of traffic.

        The URLs are returned parsed and normalized by pydantic, so the string form may
        differ from what the provider wrote: a trailing slash is added and default ports
        are dropped. Callers should use ``.scheme``, ``.host`` and ``.port`` rather than
        the string form.

        Returns:
            The cache backend URLs.

        Raises:
            InvalidCacheBackendsDataError: When any provider unit's data is invalid, or
                when the units publish inconsistent cache backend protocols.
        """
        if not (relation := self.relation):
            return CacheConfigProviderUnitsData([])

        cache_backends: list[CacheConfigProviderUnitData] = []
        for unit in relation.units:
            try:
                unit_data = relation.load(CacheConfigProviderUnitData, unit, decoder=_decode)
            except ValidationError as exc:
                raise InvalidCacheBackendsDataError(
                    f"Invalid {_CACHE_BACKEND_FIELD_NAME} published by {unit.name}: {exc}"
                ) from exc
            cache_backends.append(unit_data)
        try:
            return CacheConfigProviderUnitsData(cache_backends)
        except ValidationError as exc:
            raise InvalidCacheBackendsDataError(f"Invalid cache backends data: {exc}") from exc


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

    def get_requirers_data(self) -> dict[int, CacheConfigRequirerAppData]:
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
        configurations: dict[int, CacheConfigRequirerAppData] = {}
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

        The URL is validated against the same schema used when reading it back, so the
        provider cannot publish data it would later reject.

        Args:
            relation_id: The id of the relation to publish to.
            cache_backend_url: The URL this unit serves the relation's backend on.

        Raises:
            InvalidCacheBackendDataError: When the URL is not a valid cache backend.
        """
        relation = self.charm.model.get_relation(self.relation_name, relation_id)
        if relation is None:
            return
        try:
            CacheConfigProviderUnitData(cache_backend=cache_backend_url)  # type: ignore[arg-type]
        except ValidationError as exc:
            raise InvalidCacheBackendDataError(
                f"Invalid cache-backend URL: {cache_backend_url!r}: {exc}"
            ) from exc
        if relation.data[self.charm.unit].get(_CACHE_BACKEND_FIELD_NAME) != cache_backend_url:
            relation.data[self.charm.unit][_CACHE_BACKEND_FIELD_NAME] = cache_backend_url

    def clear_cache_backend(self, relation_id: int) -> None:
        """Clear the cache-backend value from a relation's unit databag.

        Args:
            relation_id: The id of the relation to clear cache-backend from.
        """
        relation = self.charm.model.get_relation(self.relation_name, relation_id)
        if relation is None:
            return
        if relation.data[self.charm.unit].get(_CACHE_BACKEND_FIELD_NAME):
            relation.data[self.charm.unit][_CACHE_BACKEND_FIELD_NAME] = ""
