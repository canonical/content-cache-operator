# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Errors of the content-cache-backend-config charm."""


class IntegrationDataError(Exception):
    """Represents failure in integration data validation."""


class ConfigurationError(Exception):
    """Represents failure in configuration validation."""


class NginxError(Exception):
    """Represents nginx-related failure."""


class NginxSetupError(Exception):
    """Represents failure in nginx setup."""


class NginxStopError(Exception):
    """Represents failure to stop nginx."""


class NginxConfigurationError(NginxError):
    """Represents failure in creating configuration for nginx."""


class NginxConfigurationAggregateError(NginxError):
    """Represents a collection of NginxConfigurationError."""

    def __init__(self, hosts: tuple[str], errors: tuple[NginxConfigurationError]):
        """Initialize the object.

        Args:
            hosts: List of hosts with configuration issues.
            errors: Collection of the configuration errors.
        """
        super().__init__(f"Configuration error in hosts: {hosts}")

        self.hosts = hosts
        self.errors = errors


class NginxFileError(NginxError):
    """Represents failures in writing the nginx configuration file."""


class TLSCertificateError(Exception):
    """Represents failure related to TLS certificate."""


class TLSCertificateIntegrationNotExistError(TLSCertificateError):
    """Represents TLS certificates integration not exists."""


class TLSCertificateNotAvailableError(TLSCertificateError):
    """Represents TLS certificate not available yet."""


class TLSCertificateFileError(TLSCertificateError):
    """Represents failure in writing TLS certificates to file."""
