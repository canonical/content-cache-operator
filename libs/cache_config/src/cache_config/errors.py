# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Errors for the cache-config interface library."""


class CacheConfigError(Exception):
    """Base error for the cache-config interface library."""


class CacheConfigInvalidRelationDataError(CacheConfigError):
    """Raised when cache-config relation data fails validation on write (requirer side)."""


class InvalidCacheBackendsDataError(CacheConfigError):
    """Raised when the provider units' cache_backend data is invalid as a whole."""


class CacheConfigIntegrationDataError(CacheConfigError):
    """Raised when a requirer's app databag fails validation (provider side)."""
