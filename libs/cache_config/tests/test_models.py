# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the cache-config interface library's data models."""

import pytest
from pydantic import AnyHttpUrl, ValidationError

from cache_config import (
    CacheConfigProviderUnitData,
    CacheConfigProviderUnitsData,
    CacheConfigRequirerAppData,
)
from cache_config.provider import CacheConfigProvider  # noqa: F401  (import smoke test)
from cache_config.requirer import CacheConfigRequirer  # noqa: F401  (import smoke test)

VALID_KWARGS = {
    "backends": ["http://10.0.0.1:80"],
    "fail_timeout": "30s",
    "healthcheck_interval": 1000,
    "healthcheck_path": "/healthz",
    "healthcheck_valid_status": [200],
    "healthcheck_ssl_verify": True,
    "proxy_cache_valid": ["200 1h"],
}


def test_valid_app_data():
    """Baseline valid data constructs without error."""
    CacheConfigRequirerAppData(**VALID_KWARGS)


def test_https_backend_requires_hostname():
    """https:// backends without backend_hostname are rejected."""
    kwargs = {**VALID_KWARGS, "backends": ["https://10.0.0.1:443"]}
    with pytest.raises(ValidationError):
        CacheConfigRequirerAppData(**kwargs)

    CacheConfigRequirerAppData(**{**kwargs, "backend_hostname": "example.com"})


def test_mixed_backend_schemes_rejected():
    """Backends must share a single scheme."""
    kwargs = {
        **VALID_KWARGS,
        "backends": ["http://10.0.0.1:80", "https://10.0.0.2:443"],
        "backend_hostname": "example.com",
    }
    with pytest.raises(ValidationError):
        CacheConfigRequirerAppData(**kwargs)


@pytest.mark.parametrize(
    "field,value",
    [
        ("fail_timeout", "notatime"),
        ("healthcheck_path", "has spaces"),
        ("cache_max_size", "notasize"),
    ],
)
def test_invalid_field_values_rejected(field, value):
    """Each nginx-format field rejects an obviously invalid value."""
    with pytest.raises(ValidationError):
        CacheConfigRequirerAppData(**{**VALID_KWARGS, field: value})


def test_invalid_proxy_cache_valid_rejected():
    """proxy_cache_valid entries without both a status code and a time are rejected."""
    with pytest.raises(ValidationError):
        CacheConfigRequirerAppData(**{**VALID_KWARGS, "proxy_cache_valid": ["1h"]})


def test_provider_unit_data_parses_cache_backend_as_url():
    """Regression test: cache_backend must be coerced into a parsed AnyHttpUrl, not left as
    a plain string, so callers can use .host/.port/.scheme (see CacheConfigProviderUnitData's
    model_validator and CacheConfigProviderUnitsData.cache_backend_hosts/_ports)."""
    unit_data = CacheConfigProviderUnitData(**{"cache-backend": "http://10.0.0.1:8080"})

    assert isinstance(unit_data.cache_backend, AnyHttpUrl)
    assert unit_data.cache_backend.port == 8080
    assert unit_data.cache_backend_host == "10.0.0.1"


def test_provider_unit_data_rejects_non_ip_host():
    """A hostname (not an IP) in cache_backend is rejected."""
    with pytest.raises(ValidationError):
        CacheConfigProviderUnitData(**{"cache-backend": "http://example.com:8080"})


def test_provider_units_data_aggregates_hosts_and_ports():
    """CacheConfigProviderUnitsData exposes parsed hosts/ports across units."""
    units = CacheConfigProviderUnitsData(
        [
            CacheConfigProviderUnitData(**{"cache-backend": "http://10.0.0.1:8080"}),
            CacheConfigProviderUnitData(**{"cache-backend": "http://10.0.0.2:8080"}),
        ]
    )

    assert set(units.cache_backend_hosts) == {"10.0.0.1", "10.0.0.2"}
    assert units.cache_backend_ports == [8080]


def test_provider_units_data_rejects_mixed_protocols():
    """Backends using different schemes across units are rejected."""
    with pytest.raises(ValidationError):
        CacheConfigProviderUnitsData(
            [
                CacheConfigProviderUnitData(**{"cache-backend": "http://10.0.0.1:8080"}),
                CacheConfigProviderUnitData(**{"cache-backend": "https://10.0.0.2:8443"}),
            ]
        )
