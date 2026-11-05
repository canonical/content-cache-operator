# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the cache-config interface library's data models."""

import pytest
from pydantic import ValidationError

from cache_config import CacheConfigRequirerAppData
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
