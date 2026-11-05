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
    configuration_from_charm,
)

# Field-level validation (nginx time/size formats, backend-hostname-required-for-https,
# status code ranges, proxy_cache_valid shape, etc.) is owned by the cache_config library
# and already covered by its own test suite (libs/cache_config/tests). The tests here only
# cover configuration_from_charm's job: turning this charm's config into the library's kwargs.


def test_valid_config():
    """
    arrange: Mock charm with valid URL-format backends configuration.
    act: Read the configuration kwargs from the charm.
    assert: Correct kwargs parsed from the mock charm.
    """
    charm = MockCharmFactory()

    kwargs = configuration_from_charm(charm)

    assert kwargs["backends"] == ["http://10.10.1.1:80", "http://10.10.2.2:80"]
    assert kwargs["fail_timeout"] == "30s"
    assert kwargs["healthcheck_path"] == "/healthz"
    assert kwargs["healthcheck_interval"] == 2123
    assert kwargs["proxy_cache_valid"] == []


def test_https_backends():
    """
    arrange: Mock charm with https URL-format backends configuration and backend-hostname set.
    act: Read the configuration kwargs from the charm.
    assert: Backends passed through unparsed, backend_hostname set.
    """
    charm = MockCharmFactory()
    charm.config[BACKENDS_CONFIG_NAME] = "https://10.10.1.1:443,https://10.10.2.2:443"
    charm.config["backend-hostname"] = "backend.example.com"

    kwargs = configuration_from_charm(charm)

    assert kwargs["backends"] == ["https://10.10.1.1:443", "https://10.10.2.2:443"]
    assert kwargs["backend_hostname"] == "backend.example.com"


def test_empty_backends_raises():
    """
    arrange: Mock charm with empty backends config.
    act: Read the configuration kwargs from the charm.
    assert: ConfigurationError raised.
    """
    charm = MockCharmFactory()
    charm.config[BACKENDS_CONFIG_NAME] = ""

    with pytest.raises(ConfigurationError) as err:
        configuration_from_charm(charm)

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
        configuration_from_charm(charm)

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
        configuration_from_charm(charm)

    assert 'The proxy_cache_valid is not a list: {"hello": 10}' in str(err.value)


def test_valid_proxy_cache_valid_passthrough():
    """
    arrange: Mock charm with valid proxy_cache_valid configuration.
    act: Read the configuration kwargs from the charm.
    assert: proxy_cache_valid parsed as a plain list, unvalidated at this layer.
    """
    charm = MockCharmFactory()
    charm.config[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 302 2h", "400 1m"]'

    kwargs = configuration_from_charm(charm)

    assert kwargs["proxy_cache_valid"] == ["200 302 2h", "400 1m"]


def test_invalid_healthcheck_interval_raises():
    """
    arrange: Mock charm with a non-integer healthcheck-interval.
    act: Read the configuration kwargs from the charm.
    assert: ConfigurationError raised.
    """
    charm = MockCharmFactory()
    charm.config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = "notanumber"

    with pytest.raises(ConfigurationError):
        configuration_from_charm(charm)


def test_healthcheck_path_passthrough():
    """
    arrange: Mock charm with a healthcheck path containing disallowed characters.
    act: Read the configuration kwargs from the charm.
    assert: The raw value is passed through; format validation is the library's job.
    """
    charm = MockCharmFactory()
    charm.config[HEALTHCHECK_PATH_CONFIG_NAME] = "{"

    kwargs = configuration_from_charm(charm)

    assert kwargs["healthcheck_path"] == "{"


@pytest.mark.parametrize("value", ["10m", "1h", "7d", "30s"])
def test_cache_inactive_passthrough(value: str):
    """
    arrange: Mock charm with a cache-inactive value.
    act: Read the configuration kwargs from the charm.
    assert: cache_inactive is passed through unchanged.
    """
    charm = MockCharmFactory()
    charm.config[CACHE_INACTIVE_CONFIG_NAME] = value

    kwargs = configuration_from_charm(charm)

    assert kwargs["cache_inactive"] == value


def test_cache_max_size_empty_allowed():
    """
    arrange: Mock charm with empty cache-max-size.
    act: Read the configuration kwargs from the charm.
    assert: cache_max_size is empty string (no limit).
    """
    charm = MockCharmFactory()
    charm.config[CACHE_MAX_SIZE_CONFIG_NAME] = ""

    kwargs = configuration_from_charm(charm)

    assert kwargs["cache_max_size"] == ""
