# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Errors of the content-cache-backend-config charm."""


class IntegrationDataError(Exception):
    """Represents failure in integration data validation."""


class ConfigurationError(Exception):
    """Represents failure in configuration validation."""


class NginxError(Exception):
    """Represents nginx service in bad state."""
