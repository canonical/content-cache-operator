# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the state.py"""

import pytest
from factories import MockCharmFactory  # pylint: disable=import-error

from errors import ConfigurationError
from src.state import (
    BACKENDS_CONFIG_NAME,
    CACHE_INACTIVE_CONFIG_NAME,
    CACHE_MAX_SIZE_CONFIG_NAME,
    HEALTHCHECK_INTERVAL_CONFIG_NAME,
    HEALTHCHECK_PATH_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    Configuration,
)

# Field-level validation is covered by content-cache's test_cache_config_lib.py. These tests
# cover Configuration's job: parsing charm config into a typed local representation.


def test_valid_config():
    """
    arrange: Mock charm with valid URL-format backends configuration.
    act: Build the typed configuration from the charm.
    assert: Correct values are parsed from the mock charm.
    """
    charm = MockCharmFactory()

    config = Configuration.from_charm(charm)

    assert config.backends == ("http://10.10.1.1:80", "http://10.10.2.2:80")
    assert config.fail_timeout == "30s"
    assert config.healthcheck.path == "/healthz"
    assert config.healthcheck.interval == 2123
    assert not config.proxy_cache_valid


def test_https_backends():
    """
    arrange: Mock charm with https URL-format backends configuration and backend-hostname set.
    act: Build the typed configuration from the charm.
    assert: Backends passed through unparsed, backend_hostname set.
    """
    charm = MockCharmFactory()
    charm.config[BACKENDS_CONFIG_NAME] = "https://10.10.1.1:443,https://10.10.2.2:443"
    charm.config["backend-hostname"] = "backend.example.com"

    config = Configuration.from_charm(charm)

    assert config.backends == ("https://10.10.1.1:443", "https://10.10.2.2:443")
    assert config.backend_hostname == "backend.example.com"


def test_empty_backends_raises():
    """
    arrange: Mock charm with empty backends config.
    act: Read the configuration kwargs from the charm.
    assert: ConfigurationError raised.
    """
    charm = MockCharmFactory()
    charm.config[BACKENDS_CONFIG_NAME] = ""

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert "Empty backends configuration found" in str(err.value)


def test_invalid_format_proxy_cache_valid():
    """
    arrange: Mock charm with invalid (non-JSON) cache valid config.
    act: Read the configuration kwargs from the charm.
    assert: ConfigurationError raised with a correct error message.
    """
    charm = MockCharmFactory()
    charm.config[PROXY_CACHE_VALID_CONFIG_NAME] = "invalid"

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert "Unable to parse proxy_cache_valid: invalid" in str(err.value)


def test_non_list_proxy_cache_valid_raises():
    """
    arrange: Mock charm with a JSON object (not a list) for proxy-cache-valid.
    act: Read the configuration kwargs from the charm.
    assert: ConfigurationError raised.
    """
    charm = MockCharmFactory()
    charm.config[PROXY_CACHE_VALID_CONFIG_NAME] = '{"hello": 10}'

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert 'The proxy_cache_valid is not a list: {"hello": 10}' in str(err.value)


def test_valid_proxy_cache_valid_passthrough():
    """
    arrange: Mock charm with valid proxy_cache_valid configuration.
    act: Read the configuration kwargs from the charm.
    assert: proxy_cache_valid parsed as a plain list, unvalidated at this layer.
    """
    charm = MockCharmFactory()
    charm.config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 302 2h", "400 1m"]'

    config = Configuration.from_charm(charm)

    assert config.proxy_cache_valid == ("200 302 2h", "400 1m")


def test_invalid_healthcheck_interval_raises():
    """
    arrange: Mock charm with a non-integer healthcheck-interval.
    act: Read the configuration kwargs from the charm.
    assert: ConfigurationError raised.
    """
    charm = MockCharmFactory()
    charm.config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "notanumber"

    with pytest.raises(ConfigurationError):
        Configuration.from_charm(charm)


def test_healthcheck_path_passthrough():
    """
    arrange: Mock charm with a healthcheck path containing disallowed characters.
    act: Build the typed configuration from the charm.
    assert: The value passes through for the shared library to validate.
    """
    charm = MockCharmFactory()
    charm.config[HEALTHCHECK_PATH_CONFIG_NAME] = "{"

    config = Configuration.from_charm(charm)

    assert config.healthcheck.path == "{"


@pytest.mark.parametrize("value", ["10m", "1h", "7d", "30s"])
def test_cache_inactive_passthrough(value: str):
    """
    arrange: Mock charm with a cache-inactive value.
    act: Read the configuration kwargs from the charm.
    assert: cache_inactive is passed through unchanged.
    """
    charm = MockCharmFactory()
    charm.config[CACHE_INACTIVE_CONFIG_NAME] = value

    config = Configuration.from_charm(charm)

    assert config.cache_inactive == value


def test_cache_max_size_empty_allowed():
    """
    arrange: Mock charm with empty cache-max-size.
    act: Read the configuration kwargs from the charm.
    assert: cache_max_size is empty string (no limit).
    """
    charm = MockCharmFactory()
    charm.config[CACHE_MAX_SIZE_CONFIG_NAME] = ""

    config = Configuration.from_charm(charm)

    assert config.cache_max_size == ""


def test_configuration_flattens_for_cache_config_library():
    """
    arrange: Typed local configuration built from charm config.
    act: Convert it to cache-config library keyword arguments.
    assert: Nested healthcheck values are flattened without wire serialization.
    """
    config = Configuration.from_charm(MockCharmFactory())

    kwargs = config.to_cache_config_kwargs()

    assert kwargs == {
        "backends": ["http://10.10.1.1:80", "http://10.10.2.2:80"],
        "fail_timeout": "30s",
        "healthcheck_interval": 2123,
        "healthcheck_path": "/healthz",
        "healthcheck_valid_status": [200],
        "healthcheck_ssl_verify": False,
        "proxy_cache_valid": [],
        "backend_hostname": None,
        "cache_inactive": "10m",
        "cache_max_size": "",
    }
