# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the cache-config interface library."""

import json
from typing import TypedDict

import pytest
from ops import CharmBase
from ops.testing import Harness
from pydantic import TypeAdapter, ValidationError

from cache_config.v0 import (
    CacheConfigIntegrationDataError,
    CacheConfigInvalidRelationDataError,
    CacheConfigProvider,
    CacheConfigProviderUnitData,
    CacheConfigProviderUnitsData,
    CacheConfigRequirer,
    CacheConfigRequirerAppData,
    InvalidCacheBackendDataError,
    InvalidCacheBackendsDataError,
    parse_requirer_app_data,
)


class RequirerData(TypedDict):
    """Keyword arguments required to publish cache-config requirer data.

    Attributes:
        backends: Backend URLs.
        fail_timeout: Backend failure timeout.
        healthcheck_interval: Healthcheck interval in milliseconds.
        healthcheck_path: Backend healthcheck path.
        healthcheck_valid_status: HTTP statuses considered healthy.
        healthcheck_ssl_verify: Whether to verify healthcheck TLS certificates.
        proxy_cache_valid: nginx cache validity rules.
    """

    backends: list[str]
    fail_timeout: str
    healthcheck_interval: int
    healthcheck_path: str
    healthcheck_valid_status: list[int]
    healthcheck_ssl_verify: bool
    proxy_cache_valid: list[str]


VALID_REQUIRER_DATA: RequirerData = {
    "backends": ["http://10.0.0.1:80"],
    "fail_timeout": "30s",
    "healthcheck_interval": 1000,
    "healthcheck_path": "/healthz",
    "healthcheck_valid_status": [200],
    "healthcheck_ssl_verify": True,
    "proxy_cache_valid": ["200 1h"],
}

VALID_REQUIRER_DATABAG = {
    "backends": '["http://10.0.0.1:80"]',
    "fail_timeout": "30s",
    "healthcheck_interval": "1000",
    "healthcheck_path": "/healthz",
    "healthcheck_valid_status": "[200]",
    "healthcheck_ssl_verify": "true",
    "proxy_cache_valid": '["200 1h"]',
    "cache_inactive": "10m",
}


class _RequirerCharm(CharmBase):
    """Minimal charm using the cache-config requirer."""

    def __init__(self, *args):
        """Initialize the minimal requirer charm.

        Args:
            args: Arguments forwarded to ``CharmBase``.
        """
        super().__init__(*args)
        self.cache_config = CacheConfigRequirer(self)


class _ProviderCharm(CharmBase):
    """Minimal charm using the cache-config provider."""

    def __init__(self, *args):
        """Initialize the minimal provider charm.

        Args:
            args: Arguments forwarded to ``CharmBase``.
        """
        super().__init__(*args)
        self.cache_config = CacheConfigProvider(self)


REQUIRER_METADATA = """
name: backend
requires:
  cache-config:
    interface: cache-config
    limit: 1
"""

PROVIDER_METADATA = """
name: content-cache
provides:
  cache-config:
    interface: cache-config
"""


def _requirer_data(**overrides) -> CacheConfigRequirerAppData:
    """Construct requirer data with selected values overridden."""
    return CacheConfigRequirerAppData(**{**VALID_REQUIRER_DATA, **overrides})


def _provider_unit_data(url: str) -> CacheConfigProviderUnitData:
    """Validate provider unit data from its wire representation."""
    return TypeAdapter(CacheConfigProviderUnitData).validate_python({"cache-backend": url})


def test_requirer_data_defaults():
    """Requirer data applies cache defaults."""
    data = _requirer_data()

    assert data.backend_hostname is None
    assert data.cache_inactive == "10m"
    assert data.cache_max_size == ""


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("backends", [], id="empty-backends"),
        pytest.param("backends", ["10.0.0.1"], id="backend-without-scheme"),
        pytest.param("backends", ["ftp://10.0.0.1"], id="non-http-backend"),
        pytest.param("fail_timeout", "0s", id="zero-fail-timeout"),
        pytest.param("fail_timeout", "30", id="fail-timeout-without-unit"),
        pytest.param("fail_timeout", "١m", id="non-ascii-fail-timeout"),
        pytest.param("healthcheck_interval", 0, id="zero-healthcheck-interval"),
        pytest.param("healthcheck_path", "", id="empty-healthcheck-path"),
        pytest.param("healthcheck_path", "has spaces", id="invalid-healthcheck-path"),
        pytest.param("healthcheck_valid_status", [], id="empty-valid-statuses"),
        pytest.param("healthcheck_valid_status", [99], id="low-valid-status"),
        pytest.param("healthcheck_valid_status", [1000], id="high-valid-status"),
        pytest.param("proxy_cache_valid", ["200"], id="cache-valid-without-time"),
        pytest.param("proxy_cache_valid", ["ok 1h"], id="cache-valid-noninteger-status"),
        pytest.param("proxy_cache_valid", ["200 0h"], id="cache-valid-zero-time"),
        pytest.param("proxy_cache_valid", ["200 ١h"], id="cache-valid-non-ascii-time"),
        pytest.param("cache_inactive", "0m", id="zero-cache-inactive"),
        pytest.param("cache_inactive", "١m", id="non-ascii-cache-inactive"),
        pytest.param("cache_max_size", "1t", id="invalid-cache-size-unit"),
        pytest.param("cache_max_size", "١m", id="non-ascii-cache-size"),
        pytest.param("backend_hostname", "invalid hostname", id="invalid-hostname"),
    ],
)
def test_requirer_data_rejects_invalid_fields(field, value):
    """Requirer data rejects values outside the cache-config contract."""
    with pytest.raises(ValidationError):
        _requirer_data(**{field: value})


@pytest.mark.parametrize("value", ["1s", "30m", "2h", "7d"])
def test_requirer_data_accepts_nginx_times(value):
    """Requirer data accepts supported positive nginx time values."""
    assert _requirer_data(fail_timeout=value).fail_timeout == value


@pytest.mark.parametrize("value", ["", "100k", "512m", "2g", "1G"])
def test_requirer_data_accepts_cache_sizes(value):
    """Requirer data accepts supported nginx cache sizes and no limit."""
    assert _requirer_data(cache_max_size=value).cache_max_size == value


def test_numeric_hostname_stays_a_string():
    """A raw hostname that looks like JSON is not coerced to another type."""
    data = parse_requirer_app_data({**VALID_REQUIRER_DATABAG, "backend_hostname": "123"})

    assert data.backend_hostname == "123"


def test_https_backends_require_hostname():
    """HTTPS backends require a backend hostname."""
    with pytest.raises(ValidationError, match="backend_hostname is required"):
        _requirer_data(backends=["https://10.0.0.1:443"])

    data = _requirer_data(
        backends=["https://10.0.0.1:443"], backend_hostname="backend.example.com"
    )
    assert data.backend_hostname == "backend.example.com"


def test_mixed_backend_schemes_are_rejected():
    """All backends must use the same scheme."""
    with pytest.raises(ValidationError, match="All backends must share the same scheme"):
        _requirer_data(
            backends=["http://10.0.0.1:80", "https://10.0.0.2:443"],
            backend_hostname="backend.example.com",
        )


def test_parse_requirer_app_data_decodes_wire_values():
    """Raw databag strings decode into typed requirer data."""
    data = parse_requirer_app_data(VALID_REQUIRER_DATABAG)

    assert data.backends == ["http://10.0.0.1:80"]
    assert data.healthcheck_interval == 1000
    assert data.healthcheck_ssl_verify is True
    assert data.healthcheck_valid_status == [200]
    assert data.proxy_cache_valid == ["200 1h"]


def test_provider_unit_data_parses_ipv6_cache_backend():
    """Provider unit data parses an IPv6 cache backend and strips the brackets."""
    data = _provider_unit_data("https://[2001:db8::1]:8443")

    assert data.cache_backend_host == "2001:db8::1"
    assert data.cache_backend.port == 8443


def test_provider_unit_data_rejects_invalid_cache_backend():
    """Provider unit data rejects a malformed cache backend URL."""
    with pytest.raises((ValidationError, ValueError)):
        _provider_unit_data("not-a-url")


def test_provider_units_data_collects_hosts_and_ports():
    """Provider units data exposes cache backend hosts and sorted unique ports."""
    data = CacheConfigProviderUnitsData(
        [
            _provider_unit_data("http://10.0.0.1:8080"),
            _provider_unit_data("http://10.0.0.2:9090"),
            _provider_unit_data("http://10.0.0.3:8080"),
        ]
    )

    assert data.cache_backend_hosts == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert data.cache_backend_ports == [8080, 9090]


def test_provider_unit_data_uses_default_http_port():
    """Provider unit data exposes the normalized default port for HTTP URLs."""
    assert _provider_unit_data("http://10.0.0.1").cache_backend.port == 80


def test_requirer_publishes_validated_wire_data():
    """The requirer validates and serializes application relation data."""
    harness = Harness(_RequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    harness.set_leader(True)
    relation_id = harness.add_relation("cache-config", "content-cache")

    harness.charm.cache_config.publish_cache_config(**VALID_REQUIRER_DATA)

    databag = harness.get_relation_data(relation_id, harness.model.app.name)
    assert json.loads(databag["backends"]) == ["http://10.0.0.1:80"]
    assert databag["fail_timeout"] == "30s"
    assert databag["healthcheck_interval"] == "1000"
    assert databag["healthcheck_ssl_verify"] == "true"
    assert databag["cache_inactive"] == "10m"
    assert "cache_max_size" not in databag


def test_requirer_wraps_validation_errors():
    """The requirer raises its public error for invalid publication data."""
    harness = Harness(_RequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    harness.set_leader(True)
    harness.add_relation("cache-config", "content-cache")
    invalid_data: RequirerData = {**VALID_REQUIRER_DATA, "backends": []}

    with pytest.raises(CacheConfigInvalidRelationDataError, match="backends"):
        harness.charm.cache_config.publish_cache_config(**invalid_data)


def test_requirer_does_not_publish_from_follower():
    """The requirer leaves application data unchanged when the unit is not leader."""
    harness = Harness(_RequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    relation_id = harness.add_relation("cache-config", "content-cache")

    harness.charm.cache_config.publish_cache_config(**VALID_REQUIRER_DATA)

    assert harness.get_relation_data(relation_id, harness.model.app.name) == {}


def test_provider_loads_requirer_data():
    """The provider returns typed data keyed by relation ID."""
    harness = Harness(_ProviderCharm, meta=PROVIDER_METADATA)
    harness.begin()
    relation_id = harness.add_relation("cache-config", "backend")
    harness.update_relation_data(relation_id, "backend", VALID_REQUIRER_DATABAG)

    data = harness.charm.cache_config.get_requirers_data()

    assert set(data) == {relation_id}
    assert data[relation_id].healthcheck_interval == 1000


def test_provider_ignores_empty_requirer_data():
    """The provider omits a relation whose requirer has not published data yet."""
    harness = Harness(_ProviderCharm, meta=PROVIDER_METADATA)
    harness.begin()
    harness.add_relation("cache-config", "backend")

    assert harness.charm.cache_config.get_requirers_data() == {}


def test_provider_wraps_invalid_requirer_data():
    """The provider raises its public error for invalid requirer data."""
    harness = Harness(_ProviderCharm, meta=PROVIDER_METADATA)
    harness.begin()
    relation_id = harness.add_relation("cache-config", "backend")
    harness.update_relation_data(
        relation_id,
        "backend",
        {**VALID_REQUIRER_DATABAG, "backends": "[]"},
    )

    with pytest.raises(CacheConfigIntegrationDataError):
        harness.charm.cache_config.get_requirers_data()


def test_requirer_loads_provider_units_data():
    """The requirer returns valid provider unit cache backends."""
    harness = Harness(_RequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    relation_id = harness.add_relation("cache-config", "content-cache")
    harness.add_relation_unit(relation_id, "content-cache/0")
    harness.update_relation_data(
        relation_id, "content-cache/0", {"cache-backend": "http://10.0.0.1:8080"}
    )

    data = harness.charm.cache_config.get_provider_units_data()

    assert data.cache_backend_hosts == ["10.0.0.1"]
    assert data.cache_backend_ports == [8080]


def test_requirer_rejects_invalid_provider_unit_data():
    """The requirer rejects the whole provider set when one unit is invalid."""
    harness = Harness(_RequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    relation_id = harness.add_relation("cache-config", "content-cache")
    harness.add_relation_unit(relation_id, "content-cache/0")
    harness.add_relation_unit(relation_id, "content-cache/1")
    harness.update_relation_data(
        relation_id, "content-cache/0", {"cache-backend": "http://10.0.0.1:8080"}
    )
    harness.update_relation_data(
        relation_id, "content-cache/1", {"cache-backend": "http://cache.example.com:8080"}
    )

    with pytest.raises(InvalidCacheBackendsDataError, match="content-cache/1"):
        harness.charm.cache_config.get_provider_units_data()


def test_requirer_rejects_mixed_provider_protocols():
    """The requirer wraps inconsistent provider protocols in its public error."""
    harness = Harness(_RequirerCharm, meta=REQUIRER_METADATA)
    harness.begin()
    relation_id = harness.add_relation("cache-config", "content-cache")
    harness.add_relation_unit(relation_id, "content-cache/0")
    harness.add_relation_unit(relation_id, "content-cache/1")
    harness.update_relation_data(
        relation_id, "content-cache/0", {"cache-backend": "http://10.0.0.1:8080"}
    )
    harness.update_relation_data(
        relation_id, "content-cache/1", {"cache-backend": "https://10.0.0.2:8443"}
    )

    with pytest.raises(
        InvalidCacheBackendsDataError, match="Inconsistent cache backend protocols"
    ):
        harness.charm.cache_config.get_provider_units_data()


def test_provider_publishes_and_clears_cache_backend():
    """The provider manages its cache-backend unit databag field."""
    harness = Harness(_ProviderCharm, meta=PROVIDER_METADATA)
    harness.begin()
    relation_id = harness.add_relation("cache-config", "backend")

    harness.charm.cache_config.publish_cache_backend(relation_id, "http://10.0.0.1:8080")
    assert harness.get_relation_data(relation_id, harness.model.unit.name) == {
        "cache-backend": "http://10.0.0.1:8080"
    }

    harness.charm.cache_config.clear_cache_backend(relation_id)
    assert harness.get_relation_data(relation_id, harness.model.unit.name) == {}


def test_provider_rejects_invalid_cache_backend_on_publish():
    """The provider cannot publish a cache-backend URL that readers would reject."""
    harness = Harness(_ProviderCharm, meta=PROVIDER_METADATA)
    harness.begin()
    relation_id = harness.add_relation("cache-config", "backend")

    with pytest.raises(InvalidCacheBackendDataError, match="cache.example.com"):
        harness.charm.cache_config.publish_cache_backend(
            relation_id, "http://cache.example.com:8080"
        )

    assert harness.get_relation_data(relation_id, harness.model.unit.name) == {}
