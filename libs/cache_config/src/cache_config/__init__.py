# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Public API for the cache-config interface library."""

from cache_config.errors import (
    CacheConfigError,
    CacheConfigIntegrationDataError,
    CacheConfigInvalidRelationDataError,
    InvalidCacheBackendsDataError,
)
from cache_config.provider import CacheConfigProvider
from cache_config.requirer import (
    CACHE_BACKEND_FIELD_NAME,
    CACHE_CONFIG_RELATION_NAME,
    CacheConfigProviderUnitData,
    CacheConfigProviderUnitsData,
    CacheConfigRequirer,
    CacheConfigRequirerAppData,
)

__all__ = [
    "CACHE_BACKEND_FIELD_NAME",
    "CACHE_CONFIG_RELATION_NAME",
    "CacheConfigError",
    "CacheConfigIntegrationDataError",
    "CacheConfigInvalidRelationDataError",
    "CacheConfigProvider",
    "CacheConfigProviderUnitData",
    "CacheConfigProviderUnitsData",
    "CacheConfigRequirer",
    "CacheConfigRequirerAppData",
    "InvalidCacheBackendsDataError",
]
